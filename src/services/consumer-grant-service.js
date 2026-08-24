import { ConsumerGrant } from '../models/consumer-grant.js';

export class ConsumerGrantService {
  constructor({ store = null, auditLogService = null, apiTokenService = null, credentialStore = null, providerRegistry = null } = {}) {
    this.store = store;
    this.auditLogService = auditLogService;
    // These collaborators are optional only to retain support for isolated
    // legacy callers.  The application container always supplies them, which
    // makes grant provisioning validate against the live consumer/credential
    // contracts before it is persisted.
    this.apiTokenService = apiTokenService;
    this.credentialStore = credentialStore;
    this.providerRegistry = providerRegistry;
    this.grants = [];
  }

  async createGrant(input = {}, { actorUserId = 'system' } = {}) {
    const grant = ConsumerGrant.from(input);
    const grants = await this.#load();
    if (grants.some((item) => item.grantId === grant.grantId)) {
      throw this.#badRequest(`Consumer grant '${grant.grantId}' already exists`);
    }
    if (grants.some((item) => this.#sameBinding(item, grant))) {
      throw this.#badRequest('A grant for this consumer and credential already exists', 'CONSUMER_GRANT_DUPLICATE');
    }
    await this.#validateGrant(grant);
    grants.push(grant);
    await this.#save(grants);
    await this.#audit({
      userId: actorUserId,
      action: 'consumer-grant.created',
      targetId: grant.grantId,
      details: {
        consumerId: grant.consumerId,
        credentialId: grant.credentialId,
        providerKey: grant.providerKey,
        secretFieldCount: grant.secretNames.length
      }
    });
    return grant;
  }

  async updateGrant(grantId, input = {}, { actorUserId = 'system' } = {}) {
    const normalizedGrantId = this.#requiredString(grantId, 'grantId');
    const grants = await this.#load();
    const index = grants.findIndex((item) => item.grantId === normalizedGrantId);
    if (index === -1) throw this.#notFound(`Consumer grant '${normalizedGrantId}' not found`);

    const current = grants[index];
    const next = new ConsumerGrant({
      ...current.toJSON(),
      consumerId: input.consumerId ?? current.consumerId,
      credentialId: input.credentialId ?? current.credentialId,
      providerKey: input.providerKey ?? current.providerKey,
      secretNames: input.secretNames ?? current.secretNames,
      updatedAt: new Date()
    });
    if (grants.some((item, itemIndex) => itemIndex !== index && this.#sameBinding(item, next))) {
      throw this.#badRequest('A grant for this consumer and credential already exists', 'CONSUMER_GRANT_DUPLICATE');
    }
    await this.#validateGrant(next);
    grants[index] = next;
    await this.#save(grants);
    await this.#audit({
      userId: actorUserId,
      action: 'consumer-grant.updated',
      targetId: next.grantId,
      details: {
        consumerId: next.consumerId,
        credentialId: next.credentialId,
        providerKey: next.providerKey,
        secretFieldCount: next.secretNames.length
      }
    });
    return next;
  }

  async listGrants(filters = {}) {
    const grants = await this.#load();
    return grants.filter((grant) =>
      (!filters.consumerId || grant.consumerId === filters.consumerId) &&
      (!filters.credentialId || grant.credentialId === filters.credentialId) &&
      (!filters.providerKey || grant.providerKey === filters.providerKey)
    );
  }

  async findGrant({ consumerId, credentialId, providerKey }) {
    const grants = await this.listGrants({ consumerId, credentialId, providerKey });
    return grants[0] ?? null;
  }

  async #validateGrant(grant) {
    await this.#validateConsumer(grant.consumerId);
    const credential = await this.#loadCredential(grant.credentialId);
    if (!credential) return;

    if (credential.providerKey !== grant.providerKey) {
      throw this.#badRequest(`Credential '${grant.credentialId}' does not belong to provider '${grant.providerKey}'`, 'CONSUMER_GRANT_PROVIDER_MISMATCH');
    }

    if (!credential.credentialMethodKey) {
      throw this.#badRequest(`Credential '${grant.credentialId}' has no injectable credential method`, 'CONSUMER_GRANT_METHOD_INVALID');
    }

    const provider = this.#provider(grant.providerKey);
    const method = provider.getCredentialMethod?.(credential.credentialMethodKey);
    const binding = provider.getProviderMethodBinding?.(credential.credentialMethodKey);
    if (!method || !binding) {
      throw this.#badRequest(`Credential method '${credential.credentialMethodKey}' is not injectable for provider '${grant.providerKey}'`, 'CONSUMER_GRANT_METHOD_INVALID');
    }

    const methodFields = new Map((method.credentialFields ?? []).map((field) => [field.key, field]));
    const credentialSecretNames = new Set((credential.secrets ?? []).map((secret) => secret.name));
    for (const name of grant.secretNames) {
      if (methodFields.get(name)?.secret !== true || !credentialSecretNames.has(name)) {
        throw this.#badRequest(`Secret field '${name}' is not injectable for credential '${grant.credentialId}'`, 'CONSUMER_GRANT_SECRET_INVALID');
      }
    }
  }

  async #validateConsumer(consumerId) {
    if (!this.apiTokenService?.getToken) return;
    try {
      await this.apiTokenService.getToken(consumerId);
    } catch (error) {
      if (error?.code === 'NOT_FOUND') {
        throw this.#notFound(`Consumer '${consumerId}' not found`, 'CONSUMER_NOT_FOUND');
      }
      throw error;
    }
  }

  async #loadCredential(credentialId) {
    if (this.credentialStore?.loadMetadata) {
      try {
        return await this.credentialStore.loadMetadata(credentialId);
      } catch (error) {
        if (error?.code === 'NOT_FOUND') throw this.#notFound(`Credential '${credentialId}' not found`, 'CREDENTIAL_NOT_FOUND');
        throw error;
      }
    }
    if (!this.credentialStore?.load) return null;
    try {
      return await this.credentialStore.load(credentialId);
    } catch (error) {
      if (error?.code === 'NOT_FOUND') {
        throw this.#notFound(`Credential '${credentialId}' not found`, 'CREDENTIAL_NOT_FOUND');
      }
      throw error;
    }
  }

  #provider(providerKey) {
    if (!this.providerRegistry?.get) return { getCredentialMethod: () => null, getProviderMethodBinding: () => null };
    try {
      return this.providerRegistry.get(providerKey);
    } catch {
      throw this.#badRequest(`Provider '${providerKey}' is not registered`, 'CONSUMER_GRANT_PROVIDER_INVALID');
    }
  }

  async #load() {
    if (!this.store?.load) return this.grants.map((grant) => ConsumerGrant.from(grant));
    const data = await this.store.load();
    return data.grants.map((grant) => ConsumerGrant.from(grant));
  }

  async #save(grants) {
    if (!this.store?.save) {
      this.grants = grants.map((grant) => ConsumerGrant.from(grant));
      return;
    }
    await this.store.save({ grants: grants.map((grant) => grant.toJSON()) });
  }

  #requiredString(value, name) {
    if (typeof value !== 'string' || value.trim() === '') throw this.#badRequest(`${name} is required`);
    return value.trim();
  }

  #sameBinding(left, right) {
    return left.consumerId === right.consumerId && left.credentialId === right.credentialId && left.providerKey === right.providerKey;
  }

  #badRequest(message, code = 'BAD_REQUEST') {
    const error = new Error(message);
    error.statusCode = 400;
    error.code = code;
    return error;
  }

  #notFound(message, code = 'NOT_FOUND') {
    const error = new Error(message);
    error.statusCode = 404;
    error.code = code;
    return error;
  }

  async #audit({ userId, action, targetId, details }) {
    if (!this.auditLogService?.record) return;
    await this.auditLogService.record({
      userId,
      action,
      targetType: 'consumer-grant',
      targetId,
      result: 'success',
      details
    });
  }
}
