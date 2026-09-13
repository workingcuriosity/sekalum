import { ConsumerGrant } from '../models/consumer-grant.js';
import { validateNamedIdentifier } from '../security/authorization-identifier.js';
import { isProviderProfileMigrationVerified } from '../models/credential.js';
import { RuntimeDerivationContract } from '../models/runtime-derivation-contract.js';
import { SerializedMutationQueue } from '../storage/serialized-mutation-queue.js';
import { bindingValidationResult } from './binding-validation-result.js';
import { safeErrorMessage } from '../utils/safe-diagnostics.js';

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
      let grant;
      try {
        grant = await this.prepareGrant(input);
      } catch (error) {
        this.#attachBindingError(error, input, 'BIND-GRANT-CREATE');
        throw error;
      }
      const state = await this.#loadState();
      const grants = state.grants;
      if (grants.some((item) => item.grantId === grant.grantId)) {
        throw this.#badRequest(`Consumer grant '${grant.grantId}' already exists`);
      }
      if (grants.some((item) => this.#sameBinding(item, grant))) {
        throw this.#badRequest('A grant for this consumer and credential already exists', 'CONSUMER_GRANT_DUPLICATE');
      }
      grants.push(grant);
      try {
        await this.#save(grants, state.revision, {
          beforeCommit: () => this.#revalidateBindingBeforeCommit(grant)
        });
      } catch (error) {
        this.#attachBindingError(error, grant.toJSON(), 'BIND-GRANT-CREATE');
        throw error;
      }
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
      try {
        this.#assertBindingIdentityUnchanged(current, input);
      } catch (error) {
        this.#attachBindingError(error, input, 'BIND-GRANT-UPDATE');
        throw error;
      }
      const proposed = new ConsumerGrant({
        ...current.toJSON(),
        consumerId: input.consumerId ?? current.consumerId,
        credentialId: input.credentialId ?? current.credentialId,
        providerKey: input.providerKey ?? current.providerKey,
        providerProfile: input.providerProfile ?? current.providerProfile,
        secretNames: input.secretNames ?? current.secretNames,
        updatedAt: new Date()
      });
      let next;
      try {
        next = await this.prepareGrant(proposed.toJSON());
      } catch (error) {
        this.#attachBindingError(error, proposed.toJSON(), 'BIND-GRANT-UPDATE');
        throw error;
      }
      if (grants.some((item, itemIndex) => itemIndex !== index && this.#sameBinding(item, next))) {
        throw this.#badRequest('A grant for this consumer and credential already exists', 'CONSUMER_GRANT_DUPLICATE');
      }
      grants[index] = next;
      try {
        await this.#save(grants, state.revision, {
          beforeCommit: () => this.#revalidateBindingBeforeCommit(next)
        });
      } catch (error) {
        this.#attachBindingError(error, next.toJSON(), 'BIND-GRANT-UPDATE');
        throw error;
      }
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

  async cleanupForCredential({ credentialId, credentialGeneration }) {
    return this.mutationQueue.run(async () => {
      const state = await this.#loadState();
      const generation = credentialGeneration ?? `legacy:${credentialId}`;
      const retained = state.grants.filter((grant) => !(
        grant.credentialId === credentialId
        && (grant.credentialGeneration ?? `legacy:${grant.credentialId}`) === generation
      ));
      const removed = state.grants.length - retained.length;
      if (removed > 0) await this.#save(retained, state.revision);
      return { removed, complete: true };
    });
  }

  async findGrant({ consumerId, credentialId, providerKey }) {
    const grants = await this.listGrants({ consumerId, credentialId, providerKey });
    return grants[0] ?? null;
  }

  /**
   * Validate and bind a hypothetical Grant using exactly the same Core rules
   * as create/update, without loading or mutating persisted grant state.
   */
  async prepareGrant(input = {}) {
    const grant = await this.#bindProviderProfile(ConsumerGrant.from(input));
    await this.#validateGrant(grant);
    return grant;
  }

  /**
   * Public, secret-free binding-time check used by Preview/Reference Check.
   * The write boundary continues to call prepareGrant() independently.
   */
  async validateBinding(input = {}, { pathId = 'BIND-GRANT-CREATE', grantId = null } = {}) {
    const identity = {
      consumerId: input.consumerId ?? null,
      credentialId: input.credentialId ?? null,
      providerKey: input.providerKey ?? null
    };
    try {
      const grant = await this.prepareGrant({ ...input, ...(grantId ? { grantId } : {}) });
      return bindingValidationResult({
        decision: 'CAN_BE_SAVED',
        pathId,
        consumerId: grant.consumerId,
        credentialId: grant.credentialId,
        providerKey: grant.providerKey
      });
    } catch (error) {
      const result = bindingValidationResult({
        decision: 'BLOCKED',
        pathId,
        consumerId: identity.consumerId,
        credentialId: identity.credentialId,
        providerKey: identity.providerKey,
        reasonCode: error?.code ?? 'BINDING_NOT_AUTHORIZED',
        reason: safeErrorMessage(error, 'Binding cannot be authorized'),
        remediationHint: this.#remediationHint(error?.code)
      });
      if (error?.details?.binding) error.details.binding = result;
      else if (error && typeof error === 'object') error.details = { ...(error.details ?? {}), binding: result };
      throw error;
    }
  }

  async #validateGrant(grant) {
    await this.#validateConsumer(grant.consumerId);
    const credential = await this.#loadCredential(grant.credentialId);
    if (!credential) {
      throw this.#notFound(`Credential '${grant.credentialId}' not found`, 'CREDENTIAL_NOT_FOUND');
    }

    if (credential.lifecycleState !== 'active') {
      throw this.#badRequest(
        `Credential '${grant.credentialId}' is not consumable in lifecycle state '${credential.lifecycleState}'`,
        'CONSUMER_GRANT_CREDENTIAL_NOT_CONSUMABLE'
      );
    }

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
    const currentProfile = provider.providerProfile?.identity?.() ?? provider.providerProfile ?? null;
    if (currentProfile) {
      const credentialProfile = credential.providerProfile ?? credential.metadata?.custom?.providerProfile ?? null;
      if (!credentialProfile || !isProviderProfileMigrationVerified(credential)
        || credentialProfile.digest !== currentProfile.digest) {
        throw this.#badRequest(`Credential '${grant.credentialId}' is not bound to the current verified provider profile`, 'CONSUMER_GRANT_PROFILE_MISMATCH');
      }
    }
    const method = provider.getCredentialMethod?.(credential.credentialMethodKey);
    const binding = provider.getProviderMethodBinding?.(credential.credentialMethodKey);
    if (!method || !binding) {
      throw this.#badRequest(`Credential method '${credential.credentialMethodKey}' is not injectable for provider '${grant.providerKey}'`, 'CONSUMER_GRANT_METHOD_INVALID');
    }

    const methodFields = new Map((method.credentialFields ?? []).map((field) => [field.key, field]));
    const credentialSecretNames = this.#storedSecretNames(credential);
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

  #storedSecretNames(credential) {
    // Production CredentialStore metadata is deliberately secret-free.  An
    // explicit inventory is authoritative, including an empty inventory or a
    // hasValue=false entry; never infer availability from secretNames in that
    // case or materialize the encrypted Secret payload merely to validate a
    // Grant.
    if (Array.isArray(credential?.secretInventory)) {
      return new Set(credential.secretInventory
        .filter((secret) => secret?.hasValue === true && typeof secret.name === 'string')
        .map((secret) => secret.name));
    }
    if (Array.isArray(credential?.secretNames)) {
      return new Set(credential.secretNames.filter((name) => typeof name === 'string'));
    }
    // Legacy full Credential callers do expose Secret objects.  This fallback
    // is retained for compatibility when no metadata projection exists.
    return new Set((credential?.secrets ?? [])
      .filter((secret) => secret?.value !== undefined && secret?.value !== null && secret?.value !== '')
      .map((secret) => secret.name));
  }

  async #validateConsumer(consumerId) {
    if (this.apiTokenService?.getEffectiveConsumerIdentity) {
      const identity = await this.apiTokenService.getEffectiveConsumerIdentity(consumerId);
      if (!identity) throw this.#notFound(`Consumer '${consumerId}' not found`, 'CONSUMER_NOT_FOUND');
      return;
    }
    if (!this.apiTokenService?.getToken) {
      throw this.#bindingError('CONSUMER_AUTHORITY_UNAVAILABLE', 'Consumer authority is unavailable; binding cannot be authorized');
    }
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
    if (!this.credentialStore?.load) {
      throw this.#bindingError('CREDENTIAL_AUTHORITY_UNAVAILABLE', 'Credential authority is unavailable; binding cannot be authorized');
    }
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
    let bound = grant;
    if (credential && !bound.credentialGeneration) {
      bound = new ConsumerGrant({
        ...grant.toJSON(),
        credentialGeneration: credential.credentialGeneration ?? `legacy:${credential.credentialId}`
      });
    }
    if (credential && bound.credentialGeneration !== (credential.credentialGeneration ?? `legacy:${credential.credentialId}`)) {
      throw this.#badRequest(`Credential '${grant.credentialId}' generation does not match the grant`, 'CONSUMER_GRANT_GENERATION_MISMATCH');
    }
    const profile = credential?.providerProfile ?? credential?.metadata?.providerProfile
      ?? credential?.metadata?.custom?.providerProfile ?? null;
    if (!profile || bound.providerProfile) return bound;
    return new ConsumerGrant({ ...bound.toJSON(), providerProfile: profile });
  }

  #provider(providerKey) {
    if (!this.providerRegistry?.get) return { getCredentialMethod: () => null, getProviderMethodBinding: () => null };
    try {
      return this.providerRegistry.get(providerKey);
    } catch {
      throw this.#badRequest(`Provider '${providerKey}' is not registered`, 'CONSUMER_GRANT_PROVIDER_INVALID');
    }
  }

  #assertBindingIdentityUnchanged(current, input) {
    for (const field of ['consumerId', 'credentialId']) {
      if (Object.hasOwn(input, field) && input[field] !== current[field]) {
        throw this.#bindingError('CONSUMER_GRANT_BINDING_IMMUTABLE', `Grant ${field} is fixed after creation`);
      }
    }
    if (Object.hasOwn(input, 'providerKey') && input.providerKey !== current.providerKey) {
      throw this.#badRequest(`Credential '${current.credentialId}' does not belong to provider '${input.providerKey}'`, 'CONSUMER_GRANT_PROVIDER_MISMATCH');
    }
    if (Object.hasOwn(input, 'providerProfile') && JSON.stringify(input.providerProfile ?? null) !== JSON.stringify(current.providerProfile ?? null)) {
      throw this.#bindingError('CONSUMER_GRANT_BINDING_IMMUTABLE', 'Grant provider profile is fixed after creation');
    }
  }

  async #revalidateBindingBeforeCommit(grant) {
    await this.prepareGrant(grant.toJSON?.() ?? grant);
  }

  #bindingError(code, message) {
    const error = new Error(message);
    error.statusCode = 409;
    error.code = code;
    return error;
  }

  #remediationHint(code) {
    const hints = {
      CONSUMER_NOT_FOUND: 'Select an active Consumer and run Reference Check again.',
      CREDENTIAL_NOT_FOUND: 'Select an active Credential and run Reference Check again.',
      CONSUMER_AUTHORITY_UNAVAILABLE: 'Restore Core Consumer authority before saving this binding.',
      CREDENTIAL_AUTHORITY_UNAVAILABLE: 'Restore Core Credential authority before saving this binding.',
      CONSUMER_GRANT_GENERATION_MISMATCH: 'Refresh the Credential and run Reference Check again.',
      CONSUMER_GRANT_CREDENTIAL_NOT_CONSUMABLE: 'Choose an active Credential and run Reference Check again.',
      CONSUMER_GRANT_PROFILE_MISMATCH: 'Refresh the provider profile and run Reference Check again.',
      CONSUMER_GRANT_METHOD_INVALID: 'Choose a Credential with a currently injectable method.',
      CONSUMER_GRANT_SECRET_INVALID: 'Choose only currently available injectable secret fields.',
      CONSUMER_GRANT_BINDING_IMMUTABLE: 'Create a new Grant for a different Consumer or Credential.'
    };
    return hints[code] ?? 'Refresh authoritative state and run Reference Check again.';
  }

  #attachBindingError(error, input, pathId) {
    if (!error || error.details?.binding) return;
    error.details = {
      ...(error.details ?? {}),
      binding: bindingValidationResult({
        decision: 'BLOCKED',
        pathId,
        consumerId: input?.consumerId ?? null,
        credentialId: input?.credentialId ?? null,
        providerKey: input?.providerKey ?? null,
        reasonCode: error.code ?? 'BINDING_NOT_AUTHORIZED',
        reason: safeErrorMessage(error, 'Binding cannot be authorized'),
        remediationHint: this.#remediationHint(error.code)
      })
    };
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

  async #save(grants, expectedRevision = undefined, { beforeCommit = null } = {}) {
    if (!this.store?.save) {
      this.grants = grants.map((grant) => ConsumerGrant.from(grant));
      return;
    }
    await this.store.save({ grants: grants.map((grant) => grant.toJSON()) }, { expectedRevision, beforeCommit });
  }

  #requiredString(value, name) {
    try { return validateNamedIdentifier(name, value); } catch {
      throw this.#badRequest(`${name} is invalid`, 'IDENTIFIER_INVALID');
    }
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
