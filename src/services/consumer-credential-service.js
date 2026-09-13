import { LifecycleState } from '../models/lifecycle-state.js';
import { isProviderProfileMigrationVerified } from '../models/credential.js';
import { DerivedRuntimeMaterial } from '../models/derived-runtime-material.js';
import { RuntimeDerivationContract } from '../models/runtime-derivation-contract.js';
import { ResolveDiagnosticCode, resolveDiagnostic } from './resolve-diagnostics.js';
import { bindingValidationResult } from './binding-validation-result.js';
import { validateNamedIdentifier, AuthorizationIdentifierError } from '../security/authorization-identifier.js';
import { withBindingCommitLock } from '../storage/binding-commit-coordinator.js';

export const BATCH_RESOLVE_MAX_REQUESTS = 20;

export class ConsumerCredentialService {
  constructor({ credentialStore, consumerGrantService, providerRegistry, credentialManager = null, runtimePublicProjectionService = null, auditLogService = null, apiTokenService = null } = {}) {
    if (!credentialStore?.load) throw new Error('ConsumerCredentialService requires CredentialStore');
    if (!consumerGrantService?.findGrant) throw new Error('ConsumerCredentialService requires ConsumerGrantService');
    if (!providerRegistry?.get) throw new Error('ConsumerCredentialService requires ProviderRegistry');

    this.credentialStore = credentialStore;
    this.consumerGrantService = consumerGrantService;
    this.providerRegistry = providerRegistry;
    this.credentialManager = credentialManager;
    this.runtimePublicProjectionService = runtimePublicProjectionService;
    this.auditLogService = auditLogService;
    this.apiTokenService = apiTokenService;
  }

  /**
   * Authoritative, secret-free Core projection of a Consumer's current access.
   * This deliberately reuses the same lifecycle, generation, provider and
   * field-contract checks as Discovery/Resolve; callers must not rebuild this
   * relationship from management tables.
   */
  async getAccessScope({ consumerId, grants = null } = {}) {
    const normalizedConsumerId = this.#requiredConsumerId(consumerId);
    await this.#assertConsumerIdentity(normalizedConsumerId);
    const sourceGrants = grants ?? await this.consumerGrantService.listGrants({ consumerId: normalizedConsumerId });
    const projection = await this.#buildAccessScope(normalizedConsumerId, sourceGrants);
    return projection;
  }

  async getCredentialAccessScope({ credentialId } = {}) {
    const normalizedCredentialId = this.#requiredConsumerId(credentialId, 'credentialId');
    const metadata = await this.#loadCredentialMetadata(normalizedCredentialId);
    const grants = await this.consumerGrantService.listGrants({ credentialId: normalizedCredentialId });
    const consumers = [];
    for (const grant of grants) {
      if (!grant?.consumerId) continue;
      try {
        await this.#assertConsumerIdentity(grant.consumerId);
        const scope = await this.#buildAccessScope(grant.consumerId, [grant]);
        const entry = scope.credentials.find((item) => item.credentialId === normalizedCredentialId);
        if (entry) consumers.push({ consumerId: grant.consumerId, grantedSecretFields: entry.permittedSecretFields });
      } catch (error) {
        if (error?.code === 'CONSUMER_NOT_FOUND') continue;
        throw error;
      }
    }
    const assignments = consumers.reduce((count, consumer) => count + consumer.grantedSecretFields.length, 0);
    return {
      credential: this.#credentialScopeMetadata(metadata),
      consumers,
      summary: { consumerCount: consumers.length, secretFieldAssignmentCount: assignments }
    };
  }

  async previewGrant({ consumerId, credentialId, credentialGeneration, providerKey, providerProfile, secretNames, grantId = null } = {}) {
    const normalizedConsumerId = this.#requiredConsumerId(consumerId);
    const currentGrants = await this.consumerGrantService.listGrants({ consumerId: normalizedConsumerId });
    const existing = grantId ? currentGrants.find((grant) => grant.grantId === grantId) : null;
    if (grantId && !existing) throw this.#error('GRANT_NOT_FOUND', 'Consumer grant not found', 404);
    const proposalInput = {
      ...(existing?.toJSON?.() ?? existing ?? {}),
      consumerId: normalizedConsumerId,
      credentialId: credentialId ?? existing?.credentialId,
      credentialGeneration: credentialGeneration ?? existing?.credentialGeneration,
      providerKey: providerKey ?? existing?.providerKey,
      providerProfile: providerProfile ?? existing?.providerProfile,
      secretNames: secretNames ?? existing?.secretNames,
      ...(grantId ? { grantId } : {})
    };
    const binding = this.consumerGrantService.validateBinding
      ? await this.consumerGrantService.validateBinding(proposalInput, { pathId: grantId ? 'BIND-GRANT-UPDATE' : 'BIND-GRANT-CREATE', grantId })
      : bindingValidationResult({ decision: 'CAN_BE_SAVED', pathId: grantId ? 'BIND-GRANT-UPDATE' : 'BIND-GRANT-CREATE', referenceType: 'Credential', referenceOwner: 'Core', consumerId: normalizedConsumerId, credentialId: proposalInput.credentialId, providerKey: proposalInput.providerKey });
    const current = await this.getAccessScope({ consumerId: normalizedConsumerId, grants: currentGrants });
    const proposal = await this.consumerGrantService.prepareGrant(proposalInput);
    const proposed = currentGrants.filter((grant) => !grantId || grant.grantId !== grantId);
    if (proposed.some((grant) => grant.consumerId === proposal.consumerId && grant.credentialId === proposal.credentialId && grant.providerKey === proposal.providerKey)) {
      throw this.#error('CONSUMER_GRANT_DUPLICATE', 'A grant for this consumer and credential already exists', 400);
    }
    proposed.push(proposal);
    const next = await this.#buildAccessScope(normalizedConsumerId, proposed, { allowHypothetical: true });
    return { binding, referenceCheck: binding, current, proposed: next, delta: this.#scopeDelta(current, next) };
  }

  async listAccessScopes() {
    if (!this.apiTokenService?.listTokens) return [];
    const tokens = await this.apiTokenService.listTokens();
    const scopes = [];
    for (const token of tokens) {
      try {
        if (this.apiTokenService.getEffectiveConsumerIdentity) {
          const identity = await this.apiTokenService.getEffectiveConsumerIdentity(token.id);
          if (!identity) continue;
        }
        scopes.push(await this.getAccessScope({ consumerId: token.id }));
      } catch (error) {
        if (error?.code !== 'CONSUMER_NOT_FOUND') throw error;
      }
    }
    return scopes;
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
      // The final authorization read, success audit and delivery-result
      // construction share the same bounded commit domain as Credential and
      // authority mutations. This prevents a stale success audit or secret
      // delivery after revoke, scope removal or RBAC mutation.
      return withBindingCommitLock(async () => {
        const finalConsistency = await this.#revalidateResolveAuthorization({
          consumerId,
          credential: materializedCredential,
          providerKey,
          requestedNames
        });
        if (finalConsistency.credential.version !== materializedCredential.version) {
          throw this.#diagnosticError(ResolveDiagnosticCode.CREDENTIAL_NOT_CONSUMABLE);
        }
        await this.#revalidateDeliveryConsumerIdentity({ consumerId, apiTokenId });
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
      });
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
      let credentialKey = null;
      try { credentialKey = validateNamedIdentifier('credentialKey', request?.credentialKey); } catch { credentialKey = null; }
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

  async #buildAccessScope(consumerId, grants, { allowHypothetical = false } = {}) {
    const metadataList = typeof this.credentialStore.listMetadata === 'function'
      ? await this.credentialStore.listMetadata()
      : typeof this.credentialStore.list === 'function' ? await this.credentialStore.list() : [];
    const metadataById = new Map(metadataList.map((credential) => [credential.credentialId, credential]));
    const credentials = new Map();
    const effectiveGrants = [];

    for (const grant of grants ?? []) {
      if (!grant?.credentialId || !grant.providerKey || grant.consumerId !== consumerId) continue;
      const credential = metadataById.get(grant.credentialId) ?? await this.#safeLoadMetadata(grant.credentialId);
      if (!credential) continue;
      const entry = await this.#effectiveScopeEntry({ consumerId, grant, credential, allowHypothetical });
      if (!entry) continue;
      effectiveGrants.push(this.#safeGrantProjection(grant, entry.permittedSecretFields));
      const existing = credentials.get(entry.credentialId);
      if (existing) {
        existing.permittedSecretFields = [...new Set([...existing.permittedSecretFields, ...entry.permittedSecretFields])].sort();
      } else {
        credentials.set(entry.credentialId, entry);
      }
    }

    const credentialEntries = [...credentials.values()].sort((left, right) => left.credentialId.localeCompare(right.credentialId));
    const secretFieldAssignmentCount = credentialEntries.reduce((count, entry) => count + entry.permittedSecretFields.length, 0);
    return {
      consumer: { consumerId },
      grants: effectiveGrants,
      credentials: credentialEntries,
      summary: {
        credentialCount: credentialEntries.length,
        secretFieldAssignmentCount,
        providerCount: new Set(credentialEntries.map((entry) => entry.providerKey)).size,
        activeGrantCount: effectiveGrants.length
      }
    };
  }

  async #effectiveScopeEntry({ consumerId, grant, credential, allowHypothetical = false }) {
    if (credential.lifecycleState !== LifecycleState.ACTIVE || credential.providerKey !== grant.providerKey) return null;
    if (this.#isExpired(credential) || !this.#profileCompatible(credential)) return null;
    if (!await this.#hasValidGrant({ consumerId, grant, credential, requirePersistedGrant: !allowHypothetical })) return null;
    let provider;
    try { provider = this.providerRegistry.get(credential.providerKey); } catch { return null; }
    const method = provider.getCredentialMethod?.(credential.credentialMethodKey);
    const binding = provider.getProviderMethodBinding?.(credential.credentialMethodKey);
    if (!method || !binding) return null;
    const fields = new Map((method.credentialFields ?? []).map((field) => [field.key, field]));
    const inventory = Array.isArray(credential.secretInventory) ? credential.secretInventory : [];
    const stored = new Set(inventory.length > 0
      ? inventory.filter((secret) => secret?.hasValue === true).map((secret) => secret.name)
      : (credential.secrets ?? []).filter((secret) => secret?.value !== undefined && secret?.value !== null && secret?.value !== '').map((secret) => secret.name));
    const derivation = RuntimeDerivationContract.from(provider.runtimeDerivation ?? provider.providerProfile?.contract?.runtimeDerivation ?? {});
    const configured = credential.metadata?.toJSON?.()?.custom?.runtimeDerivation ?? credential.metadata?.custom?.runtimeDerivation ?? {};
    const durable = stored;
    const permittedSecretFields = [...new Set((grant.secretNames ?? []).filter((name) => {
      const field = fields.get(name);
      if (!field?.secret) return false;
      if (field.materialization !== 'derived') return stored.has(name);
      return derivation.supportsRuntimeDerivation
        && derivation.derivedFields.includes(name)
        && derivation.requiredDurableInputs.every((input) => durable.has(input))
        && derivation.accepts({ audience: configured.audience ?? null, scopes: Array.isArray(configured.scopes) ? configured.scopes : [] });
    }))].sort();
    if (permittedSecretFields.length === 0) return null;
    return {
      credentialId: credential.credentialId,
      displayName: this.#publicDiscoveryMetadata(credential).displayName,
      providerKey: credential.providerKey,
      status: credential.lifecycleState,
      permittedSecretFields
    };
  }

  #scopeDelta(current, proposed) {
    const keySet = (scope) => new Set((scope.credentials ?? []).flatMap((credential) => (credential.permittedSecretFields ?? []).map((name) => `${credential.credentialId}:${name}`)));
    const currentSet = keySet(current);
    const proposedSet = keySet(proposed);
    const added = [...proposedSet].filter((key) => !currentSet.has(key)).sort();
    const removed = [...currentSet].filter((key) => !proposedSet.has(key)).sort();
    const status = added.length === 0 && removed.length === 0
      ? 'unchanged'
      : removed.length === 0
        ? 'increased'
        : added.length === 0
          ? 'reduced'
          : 'changed';
    return { added, removed, status };
  }

  #safeGrantProjection(grant, permittedSecretFields) {
    return {
      grantId: grant.grantId ?? null,
      consumerId: grant.consumerId,
      credentialId: grant.credentialId,
      providerKey: grant.providerKey,
      permittedSecretFields: [...permittedSecretFields]
    };
  }

  #credentialScopeMetadata(credential) {
    const metadata = this.#publicDiscoveryMetadata(credential);
    return {
      credentialId: credential.credentialId,
      displayName: metadata.displayName,
      providerKey: credential.providerKey,
      status: credential.lifecycleState
    };
  }

  async #loadCredentialMetadata(credentialId) {
    try {
      return typeof this.credentialStore.loadMetadata === 'function'
        ? await this.credentialStore.loadMetadata(credentialId)
        : await this.credentialStore.load(credentialId);
    } catch (error) {
      if (error?.code === 'NOT_FOUND') throw this.#error('CREDENTIAL_NOT_FOUND', 'Credential not found', 404);
      throw error;
    }
  }

  async #safeLoadMetadata(credentialId) {
    try { return await this.#loadCredentialMetadata(credentialId); } catch (error) {
      if (error?.code === 'CREDENTIAL_NOT_FOUND') return null;
      throw error;
    }
  }

  #requiredConsumerId(value, name = 'consumerId') {
    try { return validateNamedIdentifier('consumerId', value); } catch (error) {
      if (error instanceof AuthorizationIdentifierError) throw this.#error('INVALID_CONSUMER_ID', `${name} is invalid`, 400);
      throw error;
    }
  }

  async #assertConsumerIdentity(consumerId) {
    if (this.apiTokenService?.getEffectiveConsumerIdentity) {
      const identity = await this.apiTokenService.getEffectiveConsumerIdentity(consumerId);
      if (!identity) throw this.#error('CONSUMER_NOT_FOUND', `Consumer '${consumerId}' not found`, 404);
      return identity;
    }
    if (!this.apiTokenService?.getToken) return;
    try { await this.apiTokenService.getToken(consumerId); } catch (error) {
      if (error?.code === 'NOT_FOUND') throw this.#error('CONSUMER_NOT_FOUND', `Consumer '${consumerId}' not found`, 404);
      throw error;
    }
  }

  async #revalidateDeliveryConsumerIdentity({ consumerId, apiTokenId }) {
    if (!apiTokenId || !this.apiTokenService?.getEffectiveConsumerIdentity) return;
    const identity = await this.apiTokenService.getEffectiveConsumerIdentity(apiTokenId);
    if (!identity || identity.id !== consumerId) {
      throw this.#diagnosticError(ResolveDiagnosticCode.CONSUMER_NOT_FOUND);
    }
  }

  #requestedNames(secretNames) {
    if (!Array.isArray(secretNames) || secretNames.length === 0) {
      throw this.#diagnosticError(ResolveDiagnosticCode.INVALID_SECRET_REQUEST);
    }
    let names;
    try { names = secretNames.map((name) => validateNamedIdentifier('secretFieldKey', name)); } catch {
      throw this.#diagnosticError(ResolveDiagnosticCode.INVALID_SECRET_REQUEST);
    }
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

  async #hasValidGrant({ consumerId, grant, credential, requirePersistedGrant = true }) {
    if (grant.credentialId !== credential.credentialId
      || grant.providerKey !== credential.providerKey
      || (grant.credentialGeneration ?? `legacy:${grant.credentialId}`)
        !== (credential.credentialGeneration ?? `legacy:${credential.credentialId}`)) return false;
    const profile = credential.providerProfile ?? credential.metadata?.custom?.providerProfile ?? null;
    if (profile && grant.providerProfile && profile.digest !== grant.providerProfile.digest) return false;
    if (Object.hasOwn(grant, 'consumerId') && grant.consumerId !== consumerId) return false;

    if (!requirePersistedGrant) return true;

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
    try { validateNamedIdentifier('credentialKey', credentialKey); } catch {
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
