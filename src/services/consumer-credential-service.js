import { LifecycleState } from '../models/lifecycle-state.js';
import { ResolveDiagnosticCode, resolveDiagnostic } from './resolve-diagnostics.js';

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

  async discover({ consumerId }) {
    const grants = await this.consumerGrantService.listGrants({ consumerId });
    const seen = new Set();
    const credentials = [];

    for (const grant of grants) {
      if (!grant?.credentialId || !grant?.providerKey) continue;

      let credential;
      try {
        credential = await this.credentialStore.load(grant.credentialId);
      } catch (error) {
        if (error?.code === 'NOT_FOUND') continue;
        throw error;
      }
      if (!credential || credential.lifecycleState !== LifecycleState.ACTIVE || credential.providerKey !== grant.providerKey) continue;
      if (!await this.#hasValidGrant({ consumerId, grant, credential })) continue;
      if (seen.has(credential.credentialId)) continue;
      seen.add(credential.credentialId);
      credentials.push(credential);
    }

    this.#assertUniqueCredentialKeys(credentials);

    return {
      credentials: (await Promise.all(credentials.map((credential) => this.#discoveryProjection(credential))))
        .filter(Boolean)
    };
  }

  async resolve({ consumerId, credentialKey, secretNames }) {
    let credential = null;
    let providerKey = null;
    try {
      const requestedNames = this.#requestedNames(secretNames);
      credential = await this.#resolveCredential(credentialKey);
      providerKey = credential.providerKey;

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

      const contract = this.#secretContract(providerKey, credential.credentialMethodKey, requestedNames);
      const values = new Map(credential.secrets.map((secret) => [secret.name, secret.value]));
      if (requestedNames.some((name) => !values.has(name))) {
        throw this.#diagnosticError(ResolveDiagnosticCode.SECRET_NOT_GRANTED);
      }

      const secrets = Object.fromEntries(requestedNames.map((name) => [name, values.get(name)]));
      await this.#audit({ consumerId, credentialId: credential.credentialId, providerKey, result: 'success', reason: 'resolved', secretFieldCount: contract.length });
      return {
        credentialKey,
        providerKey,
        lifecycleState: credential.lifecycleState,
        secrets
      };
    } catch (error) {
      await this.#audit({ consumerId, credentialId: credential?.credentialId ?? this.#safeId(credentialKey), providerKey, result: 'failure', reason: error.code ?? 'INTERNAL_ERROR', secretFieldCount: 0 });
      throw error;
    }
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
      const values = new Map(credential.secrets.map((secret) => [secret.name, secret.value]));
      if (requestedNames.some((name) => !values.has(name))) throw this.#diagnosticError(ResolveDiagnosticCode.SECRET_NOT_GRANTED);
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

    const metadata = credential.metadata?.toJSON?.() ?? credential.metadata ?? {};
    const projection = {
      credentialKey: credential.credentialKey,
      metadata: {
        displayName: metadata.displayName ?? credential.externalReference ?? credential.credentialKey,
        ...(metadata.description ? { description: metadata.description } : {})
      },
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

  async #hasValidGrant({ consumerId, grant, credential }) {
    if (grant.credentialId !== credential.credentialId || grant.providerKey !== credential.providerKey) return false;
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

    if (this.credentialStore.list) {
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

  async #audit({ consumerId, credentialId, providerKey, result, reason, secretFieldCount }) {
    if (!this.auditLogService?.record) return;
    await this.auditLogService.record({
      userId: consumerId ?? 'system', action: 'consumer-credential.resolve', targetType: 'credential', targetId: credentialId ?? null, result,
      details: { consumerId: consumerId ?? null, providerKey: providerKey ?? null, reason, secretFieldCount }
    });
  }

  #safeId(value) { return typeof value === 'string' && value.trim() !== '' ? value.trim() : null; }
  async #refreshIfDue(credential) {
    if (!this.credentialManager?.refreshIfDue) return credential;
    return this.credentialManager.refreshIfDue(credential);
  }
  #diagnosticError(code) { const diagnostic = resolveDiagnostic(code); return this.#error(diagnostic.code, diagnostic.message, diagnostic.statusCode); }
  #error(code, message, statusCode) { const error = new Error(message); error.code = code; error.statusCode = statusCode; return error; }
}
