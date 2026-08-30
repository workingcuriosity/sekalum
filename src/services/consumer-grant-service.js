import { ConsumerGrant } from '../models/consumer-grant.js';
import { RuntimeDerivationContract } from '../models/runtime-derivation-contract.js';
import { SerializedMutationQueue } from '../storage/serialized-mutation-queue.js';

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
    this.mutationQueue = new SerializedMutationQueue();
  }

  async createGrant(input = {}, { actorUserId = 'system' } = {}) {
    return this.mutationQueue.run(async () => {
      const grant = await this.#bindProviderProfile(ConsumerGrant.from(input));
      const state = await this.#loadState();
      const grants = state.grants;
      if (grants.some((item) => item.grantId === grant.grantId)) {
        throw this.#badRequest(`Consumer grant '${grant.grantId}' already exists`);
      }
      if (grants.some((item) => this.#sameBinding(item, grant))) {
        throw this.#badRequest('A grant for this consumer and credential already exists', 'CONSUMER_GRANT_DUPLICATE');
      }
      await this.#validateGrant(grant);
      grants.push(grant);
      await this.#save(grants, state.revision);
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
    });
  }

  async updateGrant(grantId, input = {}, { actorUserId = 'system' } = {}) {
    return this.mutationQueue.run(async () => {
      const normalizedGrantId = this.#requiredString(grantId, 'grantId');
      const state = await this.#loadState();
      const grants = state.grants;
      const index = grants.findIndex((item) => item.grantId === normalizedGrantId);
      if (index === -1) throw this.#notFound(`Consumer grant '${normalizedGrantId}' not found`);

      const current = grants[index];
      const next = new ConsumerGrant({
        ...current.toJSON(),
        consumerId: input.consumerId ?? current.consumerId,
        credentialId: input.credentialId ?? current.credentialId,
        providerKey: input.providerKey ?? current.providerKey,
        providerProfile: input.providerProfile ?? current.providerProfile,
        secretNames: input.secretNames ?? current.secretNames,
        updatedAt: new Date()
      });
      if (grants.some((item, itemIndex) => itemIndex !== index && this.#sameBinding(item, next))) {
        throw this.#badRequest('A grant for this consumer and credential already exists', 'CONSUMER_GRANT_DUPLICATE');
      }
      await this.#validateGrant(next);
      grants[index] = next;
      await this.#save(grants, state.revision);
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
    });
  }

  async deleteGrant(grantId, { actorUserId = 'system' } = {}) {
    return this.mutationQueue.run(async () => {
      const normalizedGrantId = this.#requiredString(grantId, 'grantId');
      const state = await this.#loadState();
      const grants = state.grants;
      const index = grants.findIndex((item) => item.grantId === normalizedGrantId);
      if (index === -1) throw this.#notFound(`Consumer grant '${normalizedGrantId}' not found`);
      const [grant] = grants.splice(index, 1);
      await this.#save(grants, state.revision);
      await this.#audit({
        userId: actorUserId,
        action: 'consumer-grant.deleted',
        targetId: grant.grantId,
        details: { consumerId: grant.consumerId, credentialId: grant.credentialId, providerKey: grant.providerKey }
      });
      return grant;
    });
  }

  async listGrants(filters = {}) {
    const grants = (await this.#loadState()).grants;
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

    const credentialGeneration = credential.credentialGeneration ?? `legacy:${credential.credentialId}`;
    const grantGeneration = grant.credentialGeneration ?? `legacy:${grant.credentialId}`;
    if (grantGeneration !== credentialGeneration) {
      throw this.#badRequest(`Credential '${grant.credentialId}' generation does not match the grant`, 'CONSUMER_GRANT_GENERATION_MISMATCH');
    }

    if (credential.providerKey !== grant.providerKey) {
      throw this.#badRequest(`Credential '${grant.credentialId}' does not belong to provider '${grant.providerKey}'`, 'CONSUMER_GRANT_PROVIDER_MISMATCH');
    }
    const credentialProfile = credential.providerProfile ?? credential.metadata?.custom?.providerProfile ?? null;
    if (credentialProfile && grant.providerProfile && credentialProfile.digest !== grant.providerProfile.digest) {
      throw this.#badRequest(`Credential '${grant.credentialId}' does not match the provider profile bound to the grant`, 'CONSUMER_GRANT_PROFILE_MISMATCH');
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
      if (!this.#isInjectableSecret({ field: methodFields.get(name), name, credentialSecretNames, provider })) {
        throw this.#badRequest(`Secret field '${name}' is not injectable for credential '${grant.credentialId}'`, 'CONSUMER_GRANT_SECRET_INVALID');
      }
    }
  }

  #isInjectableSecret({ field, name, credentialSecretNames, provider }) {
    if (field?.secret !== true) return false;
    if (field.materialization !== 'derived') return credentialSecretNames.has(name);

    try {
      const contract = RuntimeDerivationContract.from(provider.runtimeDerivation ?? {});
      return contract.supportsRuntimeDerivation && contract.derivedFields.includes(name);
    } catch {
      return false;
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

  async #bindProviderProfile(grant) {
    const credential = await this.#loadCredential(grant.credentialId);
    if (credential && !grant.credentialGeneration) {
      return new ConsumerGrant({
        ...grant.toJSON(),
        credentialGeneration: credential.credentialGeneration ?? `legacy:${credential.credentialId}`
      });
    }
    if (credential && grant.credentialGeneration !== (credential.credentialGeneration ?? `legacy:${credential.credentialId}`)) {
      throw this.#badRequest(`Credential '${grant.credentialId}' generation does not match the grant`, 'CONSUMER_GRANT_GENERATION_MISMATCH');
    }
    const profile = credential?.providerProfile ?? credential?.metadata?.providerProfile
      ?? credential?.metadata?.custom?.providerProfile ?? null;
    if (!profile || grant.providerProfile) return grant;
    return new ConsumerGrant({ ...grant.toJSON(), providerProfile: profile });
  }

  #provider(providerKey) {
    if (!this.providerRegistry?.get) return { getCredentialMethod: () => null, getProviderMethodBinding: () => null };
    try {
      return this.providerRegistry.get(providerKey);
    } catch {
      throw this.#badRequest(`Provider '${providerKey}' is not registered`, 'CONSUMER_GRANT_PROVIDER_INVALID');
    }
  }

  async #loadState() {
    const state = this.store?.load ? await this.store.load() : { revision: 0, grants: this.grants };
    const rawGrants = state.grants;
    const grants = rawGrants.map((grant) => ConsumerGrant.from(grant));
    return { revision: state.revision ?? 0, grants: await Promise.all(grants.map(async (grant) => {
      if (grant.credentialGeneration) return grant;
      try {
        return await this.#bindProviderProfile(grant);
      } catch (error) {
        if (error?.code === 'CREDENTIAL_NOT_FOUND') return grant;
        throw error;
      }
    })) };
  }

  async #save(grants, expectedRevision = undefined) {
    if (!this.store?.save) {
      this.grants = grants.map((grant) => ConsumerGrant.from(grant));
      return;
    }
    await this.store.save({ grants: grants.map((grant) => grant.toJSON()) }, { expectedRevision });
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
