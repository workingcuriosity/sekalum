import { LifecycleState } from '../models/lifecycle-state.js';
import { isProviderProfileMigrationVerified } from '../models/credential.js';
import { DerivedRuntimeMaterial } from '../models/derived-runtime-material.js';
import { RuntimeDerivationContract } from '../models/runtime-derivation-contract.js';
import { ResolveDiagnosticCode, resolveDiagnostic } from './resolve-diagnostics.js';

export const BATCH_RESOLVE_MAX_REQUESTS = 20;

export class ConsumerCredentialService {
  constructor({ credentialStore, consumerGrantService, providerRegistry, credentialManager = null, runtimePublicProjectionService = null, auditLogService = null } = {}) {
    if (!credentialStore?.load) throw new Error('ConsumerCredentialService requires CredentialStore');
    if (!consumerGrantService?.findGrant) throw new Error('ConsumerCredentialService requires ConsumerGrantService');
    if (!providerRegistry?.get) throw new Error('ConsumerCredentialService requires ProviderRegistry');

    this.credentialStore = credentialStore;
    this.consumerGrantService = consumerGrantService;
    this.providerRegistry = providerRegistry;
    this.credentialManager = credentialManager;
    this.runtimePublicProjectionService = runtimePublicProjectionService;
    this.auditLogService = auditLogService;
  }

  async discover({ consumerId, filters = undefined }) {
    const normalizedFilters = this.#normalizeDiscoveryFilters(filters);
    const grants = await this.consumerGrantService.listGrants({ consumerId });
    const metadataList = typeof this.credentialStore.listMetadata === 'function'
      ? await this.credentialStore.listMetadata()
      : null;
    const metadataById = new Map((metadataList ?? []).map((credential) => [credential.credentialId, credential]));
    const seen = new Set();
    const credentials = [];

    for (const grant of grants) {
      if (!grant?.credentialId || !grant?.providerKey) continue;

      let credential;
      try {
        credential = metadataById.size > 0
          ? metadataById.get(grant.credentialId)
          : await this.credentialStore.load(grant.credentialId);
      } catch (error) {
        if (error?.code === 'NOT_FOUND') continue;
        throw error;
      }
      if (!credential || credential.lifecycleState !== LifecycleState.ACTIVE || credential.providerKey !== grant.providerKey) continue;
      if (!this.#profileCompatible(credential)) continue;
      if (this.#isExpired(credential)) continue;
      if (!await this.#hasValidGrant({ consumerId, grant, credential })) continue;
      if (seen.has(credential.credentialId)) continue;
      seen.add(credential.credentialId);
      credentials.push(credential);
    }

    this.#assertUniqueCredentialKeys(credentials);
    const filteredCredentials = credentials.filter((credential) => this.#matchesDiscoveryFilters(credential, normalizedFilters));

    return {
      credentials: (await Promise.all(filteredCredentials.map((credential) => this.#discoveryProjection(credential))))
        .filter(Boolean)
    };
  }

  async resolve({ consumerId, apiTokenId = null, credentialKey, secretNames }) {
    let credential = null;
    let providerKey = null;
    try {
      const requestedNames = this.#requestedNames(secretNames);
      credential = await this.#resolveCredential(credentialKey);
      providerKey = credential.providerKey;

      if (!this.#profileCompatible(credential)) {
        throw this.#error('CONSUMER_ACCESS_DENIED', 'Consumer is not permitted to resolve the requested credential fields', 403);
      }

      if (credential.lifecycleState !== LifecycleState.ACTIVE) {
        throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_NOT_CONSUMABLE);
      }

      const grant = await this.consumerGrantService.findGrant({ consumerId, credentialId: credential.credentialId, providerKey });
      if (!grant) {
        throw this.#diagnosticError(ResolveDiagnosticCode.GRANT_MISSING);
      }
      if (requestedNames.some((name) => !grant.secretNames.includes(name))) {
        throw this.#diagnosticError(ResolveDiagnosticCode.SECRET_NOT_GRANTED);
      }

      credential = await this.#refreshIfDue(credential);
      const finalAuthorization = await this.#revalidateResolveAuthorization({
        consumerId,
        credential,
        providerKey,
        requestedNames
      });
      const finalCredential = finalAuthorization.credential;
      const contract = this.#secretContract(providerKey, finalCredential.credentialMethodKey, requestedNames);
      const derivedNames = this.#derivedFieldNames(providerKey, credential.credentialMethodKey, requestedNames);

      const derivedValues = derivedNames.length > 0
        ? await this.#deriveRuntimeSecrets({ credential: finalCredential, providerKey, derivedNames, consumerId, apiTokenId })
        : {};
      const materializationAuthorization = await this.#revalidateResolveAuthorization({
        consumerId,
        credential: finalCredential,
        providerKey,
        requestedNames
      });
      const materializedCredential = materializationAuthorization.credential;
      const storedNames = requestedNames.filter((name) => !derivedNames.includes(name));
      const values = new Map(materializedCredential.secrets.map((secret) => [secret.name, secret.value]));
      if (storedNames.some((name) => !values.has(name))) {
        throw this.#diagnosticError(ResolveDiagnosticCode.SECRET_NOT_GRANTED);
      }
      const secrets = Object.fromEntries(requestedNames.map((name) => [
        name,
        Object.hasOwn(derivedValues, name) ? derivedValues[name] : values.get(name)
      ]));
      // Re-read authorization immediately before recording success and returning material.
      const finalConsistency = await this.#revalidateResolveAuthorization({
        consumerId,
        credential: materializedCredential,
        providerKey,
        requestedNames
      });
      if (finalConsistency.credential.version !== materializedCredential.version) {
        throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_NOT_CONSUMABLE);
      }
      try {
        await this.#audit({ consumerId, apiTokenId, credentialId: materializedCredential.credentialId, providerKey, result: 'success', reason: 'resolved', secretFieldCount: contract.length });
      } catch {
        throw this.#error('INTERNAL_ERROR', 'Credential resolution could not be completed', 500);
      }
      return {
        credentialKey,
        providerKey,
        lifecycleState: materializedCredential.lifecycleState,
        secrets
      };
    } catch (error) {
      try {
        await this.#audit({ consumerId, apiTokenId, credentialId: credential?.credentialId ?? this.#safeId(credentialKey), providerKey, result: 'failure', reason: error.code ?? 'INTERNAL_ERROR', secretFieldCount: 0 });
      } catch {
        // Preserve the safe original error; audit failure must not expose raw storage details.
      }
      throw error;
    }
  }

  async batchResolve({ consumerId, apiTokenId = null, requests }) {
    if (!Array.isArray(requests) || requests.length === 0 || requests.length > BATCH_RESOLVE_MAX_REQUESTS) {
      throw this.#error('INVALID_BATCH_REQUEST', `Batch Resolve accepts between 1 and ${BATCH_RESOLVE_MAX_REQUESTS} requests`, 400);
    }

    const results = await Promise.all(requests.map(async (request, index) => {
      const credentialKey = typeof request?.credentialKey === 'string' && request.credentialKey.trim() !== ''
        ? request.credentialKey.trim()
        : null;
      if (!credentialKey || !Array.isArray(request?.secretNames)) {
        return {
          index,
          credentialKey,
          success: false,
          error: { code: ResolveDiagnosticCode.INVALID_SECRET_REQUEST, message: 'Batch Resolve request item is invalid' }
        };
      }

      try {
        const data = await this.resolve({ consumerId, apiTokenId, credentialKey, secretNames: request.secretNames });
        return { index, credentialKey, success: true, data };
      } catch (error) {
        return { index, credentialKey, success: false, error: this.#publicBatchError(error) };
      }
    }));

    return {
      results,
      summary: {
        total: results.length,
        succeeded: results.filter(({ success }) => success).length,
        failed: results.filter(({ success }) => !success).length
      }
    };
  }

  async diagnose({ consumerId, credentialId, secretNames }) {
    try {
      const requestedNames = this.#requestedNames(secretNames);
      const credential = await this.#credential(credentialId);
      if (credential.lifecycleState !== LifecycleState.ACTIVE) throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_DISABLED);
      const grant = await this.consumerGrantService.findGrant({ consumerId, credentialId: credential.credentialId, providerKey: credential.providerKey });
      if (!grant) throw this.#diagnosticError(ResolveDiagnosticCode.GRANT_MISSING);
      if (requestedNames.some((name) => !grant.secretNames.includes(name))) throw this.#diagnosticError(ResolveDiagnosticCode.SECRET_NOT_GRANTED);
      this.#secretContract(credential.providerKey, credential.credentialMethodKey, requestedNames);
      const derivedNames = this.#derivedFieldNames(credential.providerKey, credential.credentialMethodKey, requestedNames);
      const values = new Map(credential.secrets.map((secret) => [secret.name, secret.value]));
      if (requestedNames.some((name) => !derivedNames.includes(name) && !values.has(name))) {
        throw this.#diagnosticError(ResolveDiagnosticCode.SECRET_NOT_GRANTED);
      }
      return { code: ResolveDiagnosticCode.SUCCESS, credentialId: credential.credentialId, providerKey: credential.providerKey, credentialMethodKey: credential.credentialMethodKey };
    } catch (error) {
      return { code: error.code ?? 'INTERNAL_ERROR' };
    }
  }

  #requestedNames(secretNames) {
    if (!Array.isArray(secretNames) || secretNames.length === 0 || secretNames.some((name) => typeof name !== 'string' || name.trim() === '')) {
      throw this.#diagnosticError(ResolveDiagnosticCode.INVALID_SECRET_REQUEST);
    }
    const names = secretNames.map((name) => name.trim());
    if (new Set(names).size !== names.length) {
      throw this.#diagnosticError(ResolveDiagnosticCode.INVALID_SECRET_REQUEST);
    }
    return names;
  }

  #isExpired(credential) {
    const value = credential?.metadata?.expiresAt ?? credential?.expiresAt ?? null;
    if (!value) return false;
    const expiresAt = new Date(value);
    return !Number.isNaN(expiresAt.getTime()) && expiresAt.getTime() <= Date.now();
  }

  #normalizeDiscoveryFilters(filters) {
    if (filters === undefined || filters === null) return { displayName: null, tag: null };
    if (typeof filters !== 'object' || Array.isArray(filters)) throw this.#discoveryFilterError();

    const supported = new Set(['displayName', 'tag']);
    for (const key of Object.keys(filters)) {
      if (!supported.has(key)) throw this.#discoveryFilterError();
    }

    const normalize = (value) => {
      if (value === undefined || value === '') return null;
      if (typeof value !== 'string' || value.trim() === '') throw this.#discoveryFilterError();
      return value.trim().toLowerCase();
    };

    return {
      displayName: normalize(filters.displayName),
      tag: normalize(filters.tag)
    };
  }

  #discoveryFilterError() {
    const error = new Error('Credential discovery filters are invalid');
    error.code = 'INVALID_DISCOVERY_FILTER';
    return error;
  }

  #matchesDiscoveryFilters(credential, filters) {
    const metadata = this.#publicDiscoveryMetadata(credential);
    if (filters.displayName && metadata.displayName.toLowerCase() !== filters.displayName) return false;
    if (filters.tag && !metadata.tags.some((tag) => tag.toLowerCase() === filters.tag)) return false;
    return true;
  }

  #publicDiscoveryMetadata(credential) {
    const metadata = credential.metadata?.toJSON?.() ?? credential.metadata ?? {};
    const tags = Array.isArray(metadata.tags)
      ? [...new Set(metadata.tags.filter((tag) => typeof tag === 'string').map((tag) => tag.trim()).filter(Boolean))]
      : [];
    return {
      displayName: metadata.displayName ?? credential.externalReference ?? credential.credentialKey,
      ...(metadata.description ? { description: metadata.description } : {}),
      ...(tags.length > 0 ? { tags } : {})
    };
  }

  async #discoveryProjection(credential) {
    let provider;
    try {
      provider = this.providerRegistry.get(credential.providerKey);
    } catch {
      return null;
    }

    const method = provider.getCredentialMethod?.(credential.credentialMethodKey);
    const binding = provider.getProviderMethodBinding?.(credential.credentialMethodKey);
    if (!method || !binding) return null;

    const projection = {
      credentialKey: credential.credentialKey,
      metadata: this.#publicDiscoveryMetadata(credential),
      fields: method.credentialFields.map((field) => ({
        name: field.key,
        label: field.label,
        inputType: field.type,
        required: field.required,
        secret: field.secret,
        visible: field.visible,
        userConfigurable: field.userConfigurable,
        systemManaged: field.systemManaged
      }))
    };

    const runtimePublic = await this.#runtimePublicProjection(credential);
    if (runtimePublic) projection.runtimePublic = runtimePublic;
    return projection;
  }

  async #runtimePublicProjection(credential) {
    if (!this.runtimePublicProjectionService?.project) return null;

    try {
      const result = await this.runtimePublicProjectionService.project({ credential });
      const values = result?.runtimePublic;
      return values && typeof values === 'object' && !Array.isArray(values)
        && Object.keys(values).length > 0
        ? values
        : null;
    } catch {
      return null;
    }
  }

  async #revalidateResolveAuthorization({ consumerId, credential, providerKey, requestedNames }) {
    let currentCredential;
    try {
      currentCredential = typeof this.credentialStore.loadByCredentialKey === 'function'
        ? await this.credentialStore.loadByCredentialKey(credential.credentialKey)
        : await this.credentialStore.load(credential.credentialId);
    } catch (error) {
      if (error?.code === 'NOT_FOUND') {
        throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_NOT_FOUND);
      }
      throw error;
    }

    if (currentCredential.providerKey !== providerKey || currentCredential.version !== credential.version) {
      throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_NOT_CONSUMABLE);
    }
    if (!this.#profileCompatible(currentCredential)) {
      throw this.#error('CONSUMER_ACCESS_DENIED', 'Consumer is not permitted to resolve the requested credential fields', 403);
    }
    if (currentCredential.lifecycleState !== LifecycleState.ACTIVE || this.#isExpired(currentCredential)) {
      throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_NOT_CONSUMABLE);
    }

    const grant = await this.consumerGrantService.findGrant({
      consumerId,
      credentialId: currentCredential.credentialId,
      providerKey
    });
    if (!grant) {
      throw this.#diagnosticError(ResolveDiagnosticCode.GRANT_MISSING);
    }
    const profile = currentCredential.providerProfile ?? currentCredential.metadata?.custom?.providerProfile ?? null;
    if (grant.providerProfile && profile && grant.providerProfile.digest !== profile.digest) {
      throw this.#error('CONSUMER_ACCESS_DENIED', 'Consumer is not permitted to resolve the requested credential fields', 403);
    }
    if (grant.credentialId !== currentCredential.credentialId
      || grant.providerKey !== currentCredential.providerKey
      || (grant.credentialGeneration ?? `legacy:${grant.credentialId}`)
        !== (currentCredential.credentialGeneration ?? `legacy:${currentCredential.credentialId}`)
      || (Object.hasOwn(grant, 'consumerId') && grant.consumerId !== consumerId)) {
      throw this.#diagnosticError(ResolveDiagnosticCode.GRANT_MISSING);
    }
    if (requestedNames.some((name) => !grant.secretNames.includes(name))) {
      throw this.#diagnosticError(ResolveDiagnosticCode.SECRET_NOT_GRANTED);
    }

    return { credential: currentCredential, grant };
  }

  async #hasValidGrant({ consumerId, grant, credential }) {
    if (grant.credentialId !== credential.credentialId
      || grant.providerKey !== credential.providerKey
      || (grant.credentialGeneration ?? `legacy:${grant.credentialId}`)
        !== (credential.credentialGeneration ?? `legacy:${credential.credentialId}`)) return false;
    const profile = credential.providerProfile ?? credential.metadata?.custom?.providerProfile ?? null;
    if (profile && grant.providerProfile && profile.digest !== grant.providerProfile.digest) return false;
    if (Object.hasOwn(grant, 'consumerId') && grant.consumerId !== consumerId) return false;

    let verifiedGrant;
    try {
      verifiedGrant = await this.consumerGrantService.findGrant({
        consumerId,
        credentialId: credential.credentialId,
        providerKey: credential.providerKey
      });
    } catch {
      return false;
    }

    return Boolean(verifiedGrant)
      && verifiedGrant.credentialId === credential.credentialId
      && verifiedGrant.providerKey === credential.providerKey
      && (verifiedGrant.credentialGeneration ?? `legacy:${verifiedGrant.credentialId}`)
        === (credential.credentialGeneration ?? `legacy:${credential.credentialId}`)
      && (!Object.hasOwn(verifiedGrant, 'consumerId') || verifiedGrant.consumerId === consumerId);
  }

  #assertUniqueCredentialKeys(credentials) {
    const byKey = new Map();
    for (const credential of credentials) {
      const existing = byKey.get(credential.credentialKey);
      if (existing && existing.credentialId !== credential.credentialId) {
        const error = new Error(`Credential key '${credential.credentialKey}' is assigned to multiple credentials`);
        error.code = 'CREDENTIAL_KEY_DUPLICATE';
        throw error;
      }
      byKey.set(credential.credentialKey, credential);
    }
  }

  async #credential(credentialId) {
    try {
      return await this.credentialStore.load(credentialId);
    } catch (error) {
      if (error?.code === 'NOT_FOUND') throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_NOT_FOUND);
      throw error;
    }
  }

  async #resolveCredential(credentialKey) {
    if (typeof credentialKey !== 'string' || credentialKey.trim() === '') {
      throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_NOT_FOUND);
    }

    if (typeof this.credentialStore.loadByCredentialKey === 'function') {
      try {
        return await this.credentialStore.loadByCredentialKey(credentialKey);
      } catch (error) {
        if (error?.code !== 'NOT_FOUND') throw error;
      }
    } else if (typeof this.credentialStore.listMetadata === 'function') {
      const metadata = (await this.credentialStore.listMetadata()).find((entry) => entry.credentialKey === credentialKey);
      if (metadata) return this.credentialStore.load(metadata.credentialId);
    } else if (this.credentialStore.list) {
      const credential = (await this.credentialStore.list()).find((entry) => entry.credentialKey === credentialKey);
      if (credential) return credential;
    }

    // ADR-020 permits existing credential-ID path values as a migration fallback.
    return this.#credential(credentialKey);
  }

  #secretContract(providerKey, credentialMethodKey, names) {
    let provider;
    try { provider = this.providerRegistry.get(providerKey); } catch {
      throw this.#error('CONSUMER_ACCESS_DENIED', 'Consumer is not permitted to resolve the requested credential fields', 403);
    }
    if (!credentialMethodKey) {
      throw this.#error('CONSUMER_ACCESS_DENIED', 'Consumer is not permitted to resolve the requested credential fields', 403);
    }
    const method = provider.getCredentialMethod?.(credentialMethodKey);
    const binding = provider.getProviderMethodBinding?.(credentialMethodKey);
    if (!method || !binding) {
      throw this.#error('CONSUMER_ACCESS_DENIED', 'Consumer is not permitted to resolve the requested credential fields', 403);
    }
    const fields = new Map((method.credentialFields ?? []).map((field) => [field.key, field]));
    if (names.some((name) => fields.get(name)?.secret !== true)) {
      throw this.#error('CONSUMER_ACCESS_DENIED', 'Consumer is not permitted to resolve the requested credential fields', 403);
    }
    return names;
  }

  #derivedFieldNames(providerKey, credentialMethodKey, names) {
    let provider;
    try { provider = this.providerRegistry.get(providerKey); } catch { return []; }
    const method = provider.getCredentialMethod?.(credentialMethodKey);
    const fields = new Map((method?.credentialFields ?? []).map((field) => [field.key, field]));
    return names.filter((name) => fields.get(name)?.materialization === 'derived');
  }

  async #deriveRuntimeSecrets({ credential, providerKey, derivedNames, consumerId, apiTokenId }) {
    if (!this.credentialManager?.deriveRuntimeMaterial) {
      throw this.#error('DERIVATION_UNAVAILABLE', 'Derived runtime material is unavailable', 503);
    }
    let provider;
    try { provider = this.providerRegistry.get(providerKey); } catch {
      throw this.#error('DERIVATION_CONFIGURATION_INVALID', 'Provider derivation contract is unavailable', 422);
    }
    const derivation = RuntimeDerivationContract.from(provider.runtimeDerivation ?? provider.providerProfile?.contract?.runtimeDerivation ?? {});
    if (!derivation.supportsRuntimeDerivation || derivedNames.some((name) => !derivation.derivedFields.includes(name))) {
      throw this.#error('DERIVATION_CONFIGURATION_INVALID', 'Requested derived field is not supported by the provider contract', 422);
    }
    const durableNames = new Set(credential.secrets.map((secret) => secret.name));
    if (derivation.requiredDurableInputs.some((name) => !durableNames.has(name))) {
      throw this.#error('DURABLE_IDENTITY_INVALID', 'Required durable derivation material is unavailable', 422);
    }
    const metadata = credential.metadata?.toJSON?.() ?? credential.metadata ?? {};
    const configured = metadata.custom?.runtimeDerivation ?? {};
    const audience = configured.audience ?? null;
    const scopes = Array.isArray(configured.scopes) ? configured.scopes : [];
    if (!derivation.accepts({ audience, scopes })) {
      throw this.#error('AUDIENCE_OR_SCOPE_INCOMPATIBLE', 'Derived runtime material is incompatible with the requested provider contract', 403);
    }

    const result = await this.credentialManager.deriveRuntimeMaterial(credential, {
      fieldNames: derivedNames,
      audience,
      scopes,
      runtimeContext: {
        consumerId: consumerId ?? null,
        apiTokenId: apiTokenId ?? null,
        operation: 'resolve'
      },
      auditContext: {
        consumerId: consumerId ?? null,
        apiTokenId: apiTokenId ?? null,
        derivationMethod: derivation.derivationMethod
      }
    });
    if (!result?.success) {
      const error = this.#error(
        result?.error?.code ?? 'DERIVATION_FAILED',
        'Derived runtime material could not be created',
        Number(result?.error?.statusCode) || 422
      );
      error.classification = result?.error?.classification ?? 'validation_operation_failed';
      throw error;
    }

    let material;
    try { material = DerivedRuntimeMaterial.from(result.data); } catch {
      throw this.#error('PROVIDER_CONTRACT_INCOMPATIBLE', 'Provider returned invalid derived runtime material', 502);
    }
    const currentProfile = provider.providerProfile?.identity?.() ?? provider.providerProfile;
    if (material.credentialIdentity !== credential.credentialId
      || material.providerProfile.digest !== currentProfile?.digest
      || material.derivationMethod !== derivation.derivationMethod
      || material.sourceVersion !== credential.version
      || material.audience !== audience
      || material.effectiveScopes.some((scope) => !scopes.includes(scope))
      || material.runtimeContext.consumerId !== (consumerId ?? null)
      || material.runtimeContext.apiTokenId !== (apiTokenId ?? null)
      || material.runtimeContext.operation !== 'resolve') {
      throw this.#error('PROVIDER_CONTRACT_INCOMPATIBLE', 'Provider returned incompatible derived runtime material', 502);
    }
    if (material.isExpired({ safetyWindowMs: derivation.refreshThresholdMs })) {
      throw this.#error('DERIVED_MATERIAL_EXPIRED', 'Derived runtime material is expired', 422);
    }
    try { return material.toAuthorizedSecrets(derivedNames); } catch {
      throw this.#error('PROVIDER_CONTRACT_INCOMPATIBLE', 'Provider omitted requested derived runtime material', 502);
    }
  }

  async #audit({ consumerId, apiTokenId = null, credentialId, providerKey, result, reason, secretFieldCount }) {
    if (!this.auditLogService?.record) {
      throw this.#error('INTERNAL_ERROR', 'Credential resolution could not be completed', 500);
    }
    await this.auditLogService.record({
      actorType: 'consumer', userId: null, consumerId: consumerId ?? null, apiTokenId: apiTokenId ?? null,
      action: 'consumer-credential.resolve', targetType: 'credential', targetId: credentialId ?? null, result,
      details: { consumerId: consumerId ?? null, providerKey: providerKey ?? null, reason, secretFieldCount }
    });
  }

  #safeId(value) { return typeof value === 'string' && value.trim() !== '' ? value.trim() : null; }
  #profileCompatible(credential) {
    const profile = credential?.providerProfile ?? credential?.metadata?.custom?.providerProfile ?? null;
    try {
      const current = this.providerRegistry.get(credential.providerKey)?.providerProfile;
      // Providers without a profile are legacy/test-compatible providers and
      // have no profile-dependent contract to gate. Profile-bearing providers
      // require an explicit, verified migration state and an exact digest.
      if (!current) return true;
      return Boolean(profile?.digest)
        && isProviderProfileMigrationVerified(credential)
        && profile.digest === current.digest;
    } catch {
      return false;
    }
  }
  async #refreshIfDue(credential) {
    if (!this.credentialManager?.refreshIfDue) return credential;
    return this.credentialManager.refreshIfDue(credential);
  }
  #diagnosticError(code) { const diagnostic = resolveDiagnostic(code); return this.#error(diagnostic.code, diagnostic.message, diagnostic.statusCode); }
  #publicBatchError(error) {
    const diagnostic = resolveDiagnostic(error?.code, { publicResponse: true });
    const internal = !error?.code || error.code === 'INTERNAL_ERROR';
    return {
      code: internal ? 'INTERNAL_ERROR' : diagnostic.code,
      message: internal ? 'Credential resolution could not be completed' : diagnostic.message
    };
  }
  #error(code, message, statusCode) { const error = new Error(message); error.code = code; error.statusCode = statusCode; return error; }
}
