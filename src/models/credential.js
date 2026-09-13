import crypto from 'node:crypto';
import { CredentialSecret } from './credential-secret.js';
import { CredentialMetadata } from './credential-metadata.js';
import { LifecycleState, isLifecycleState } from './lifecycle-state.js';
import { validateNamedIdentifier } from '../security/authorization-identifier.js';
import { OAuthCredentialBinding } from './oauth-context-binding.js';

function profileIdentity(profile) {
  if (!profile || typeof profile !== 'object') return null;
  return {
    ...(profile.providerKey ? { providerKey: profile.providerKey } : {}),
    ...(profile.version ? { version: profile.version } : {}),
    ...(profile.providerKind ? { providerKind: profile.providerKind } : {}),
    ...(profile.digest ? { digest: profile.digest } : {})
  };
}

function migrationStateFor(profile, state = null, { legacyCustomProfile = false } = {}) {
  if (state && typeof state === 'object') {
    return Object.freeze({
      migrationComplete: state.migrationComplete === true,
      migrationVerified: state.migrationVerified === true,
      profileDigest: typeof state.profileDigest === 'string' ? state.profileDigest : null,
      source: typeof state.source === 'string' ? state.source : 'legacy'
    });
  }
  const identity = profileIdentity(profile);
  const verified = Boolean(identity?.digest) && !legacyCustomProfile;
  return Object.freeze({
    migrationComplete: verified,
    migrationVerified: verified,
    profileDigest: identity?.digest ?? null,
    source: identity?.digest ? (legacyCustomProfile ? 'legacy' : 'bound') : 'legacy'
  });
}

const DECOMMISSIONING_STEP_NAMES = Object.freeze([
  'providerCleanup',
  'grantCleanup',
  'secretHistoryCleanup'
]);
const DECOMMISSIONING_STATUSES = Object.freeze([
  'pending',
  'complete',
  'not_required',
  'failed_retryable'
]);

function normalizeDecommissioningStep(step = {}, fieldName) {
  if (!step || typeof step !== 'object' || Array.isArray(step)) {
    throw new Error(`Credential: invalid decommissioning.${fieldName}`);
  }
  const status = step.status ?? 'pending';
  if (!DECOMMISSIONING_STATUSES.includes(status)) {
    throw new Error(`Credential: invalid decommissioning.${fieldName}.status`);
  }
  const lastAttemptAt = step.lastAttemptAt ?? null;
  if (lastAttemptAt !== null && (typeof lastAttemptAt !== 'string' || Number.isNaN(new Date(lastAttemptAt).getTime()))) {
    throw new Error(`Credential: invalid decommissioning.${fieldName}.lastAttemptAt`);
  }
  const failureCode = step.failureCode ?? null;
  if (failureCode !== null && (typeof failureCode !== 'string' || !/^[A-Z][A-Z0-9_]{2,63}$/.test(failureCode))) {
    throw new Error(`Credential: invalid decommissioning.${fieldName}.failureCode`);
  }
  return Object.freeze({ status, lastAttemptAt, failureCode });
}

function normalizeDecommissioning(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error("Credential: 'decommissioning' must be an object or null");
  }
  if (!['revoke', 'delete'].includes(value.intent)) {
    throw new Error("Credential: invalid decommissioning.intent");
  }
  if (typeof value.requestedAt !== 'string' || Number.isNaN(new Date(value.requestedAt).getTime())) {
    throw new Error("Credential: invalid decommissioning.requestedAt");
  }
  const normalized = {
    intent: value.intent,
    requestedAt: value.requestedAt
  };
  for (const name of DECOMMISSIONING_STEP_NAMES) {
    normalized[name] = normalizeDecommissioningStep(value[name], name);
  }
  return Object.freeze(normalized);
}

export function decommissioningAggregateStatus(decommissioning) {
  if (!decommissioning) return null;
  const steps = DECOMMISSIONING_STEP_NAMES.map((name) => decommissioning[name]);
  if (steps.some((step) => step.status === 'failed_retryable')) return 'failed_retryable';
  if (steps.every((step) => ['complete', 'not_required'].includes(step.status))) return 'complete';
  return 'pending';
}

export function isProviderProfileMigrationVerified(credential) {
  const profile = credential?.providerProfile ?? credential?.metadata?.custom?.providerProfile ?? null;
  const state = credential?.providerProfileMigration ?? null;
  return Boolean(profile?.digest
    && state?.migrationComplete === true
    && state?.migrationVerified === true
    && state.profileDigest === profile.digest);
}

export class Credential {
  constructor(input = {}) {
    const {
    credentialId = crypto.randomUUID(),
    credentialGeneration = `legacy:${credentialId}`,
    providerKey,
    providerProfile = null,
    providerProfileMigration = null,
    providerConfigurationId = null,
    credentialMethodKey = null,
    oauthCredentialBinding = null,
    externalReference = null,
    lifecycleState = LifecycleState.REGISTERED,
    decommissioning = null,
    secrets = [],
    metadata = {},
    createdAt = new Date(),
    updatedAt = new Date(),
    version = 1
    } = input;
    const credentialKey = Object.hasOwn(input, 'credentialKey')
      ? input.credentialKey
      : crypto.randomUUID();

    if (typeof credentialKey !== 'string' || credentialKey.trim() === '') {
      throw new Error("Credential: 'credentialKey' is required");
    }
    validateNamedIdentifier('credentialId', credentialId);
    validateNamedIdentifier('credentialGeneration', credentialGeneration);
    validateNamedIdentifier('credentialKey', credentialKey);
    validateNamedIdentifier('providerKey', providerKey);
    if (credentialMethodKey !== null) validateNamedIdentifier('credentialMethodKey', credentialMethodKey);
    if (externalReference !== null && externalReference !== undefined) validateNamedIdentifier('externalReference', externalReference);
    if (providerConfigurationId !== null && providerConfigurationId !== undefined) validateNamedIdentifier('providerConfigurationId', providerConfigurationId);
    if (!isLifecycleState(lifecycleState)) {
      throw new Error(`Credential: invalid lifecycleState '${lifecycleState}'`);
    }

    this.credentialId = credentialId;
    this.credentialGeneration = credentialGeneration;
    this.credentialKey = credentialKey;
    this.providerKey = providerKey;
    // null is retained only for records persisted before the method model.
    // Callers creating a method-based credential must provide its explicit key.
    this.credentialMethodKey = credentialMethodKey ?? null;
    this.externalReference = externalReference;
    this.lifecycleState = lifecycleState;
    this.decommissioning = normalizeDecommissioning(decommissioning);
    this.secrets = Object.freeze(secrets.map((secret) => CredentialSecret.from(secret)));
    this.metadata = CredentialMetadata.from(metadata);
    const metadataJSON = this.metadata.toJSON();
    const legacyCustomProfile = !providerProfile && Boolean(metadataJSON.custom?.providerProfile);
    const normalizedProfile = profileIdentity(providerProfile ?? metadataJSON.custom?.providerProfile);
    if (normalizedProfile?.providerKey) validateNamedIdentifier('providerKey', normalizedProfile.providerKey);
    this.providerProfile = normalizedProfile ? Object.freeze(normalizedProfile) : null;
    this.providerProfileMigration = migrationStateFor(this.providerProfile, providerProfileMigration, { legacyCustomProfile });
    this.providerConfigurationId = providerConfigurationId
      ?? metadataJSON.custom?.providerConfigurationId
      ?? null;
    if (this.providerConfigurationId !== null) validateNamedIdentifier('providerConfigurationId', this.providerConfigurationId);
    this.oauthCredentialBinding = OAuthCredentialBinding.from(oauthCredentialBinding);
    this.createdAt = createdAt instanceof Date ? createdAt : new Date(createdAt);
    this.updatedAt = updatedAt instanceof Date ? updatedAt : new Date(updatedAt);
    this.version = version;

    Object.freeze(this);
  }

  withLifecycleState(lifecycleState) {
    return new Credential({
      ...this.toJSON(),
      lifecycleState,
      updatedAt: new Date(),
      version: this.version + 1
    });
  }

  toJSON() {
    return {
      credentialId: this.credentialId,
      credentialGeneration: this.credentialGeneration,
      credentialKey: this.credentialKey,
      providerKey: this.providerKey,
      ...(this.providerProfile ? { providerProfile: { ...this.providerProfile } } : {}),
      providerProfileMigration: { ...this.providerProfileMigration },
      ...(this.providerConfigurationId ? { providerConfigurationId: this.providerConfigurationId } : {}),
      ...(this.oauthCredentialBinding ? { oauthCredentialBinding: this.oauthCredentialBinding.toJSON() } : {}),
      credentialMethodKey: this.credentialMethodKey,
      externalReference: this.externalReference,
      lifecycleState: this.lifecycleState,
      ...(this.decommissioning ? { decommissioning: this.decommissioningJSON() } : {}),
      secrets: this.secrets.map((secret) => secret.toJSON()),
      metadata: this.metadata.toJSON(),
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString(),
      version: this.version
    };
  }

  decommissioningJSON() {
    if (!this.decommissioning) return null;
    return {
      intent: this.decommissioning.intent,
      requestedAt: this.decommissioning.requestedAt,
      ...Object.fromEntries(DECOMMISSIONING_STEP_NAMES.map((name) => [name, { ...this.decommissioning[name] }]))
    };
  }

  // This is the safe public projection used by list, status, discovery and
  // presentation paths. Secret values and internal routing metadata are absent.
  toMetadataJSON() {
    return {
      credentialId: this.credentialId,
      credentialGeneration: this.credentialGeneration,
      credentialKey: this.credentialKey,
      providerKey: this.providerKey,
      credentialMethodKey: this.credentialMethodKey,
      externalReference: this.externalReference,
      lifecycleState: this.lifecycleState,
      metadata: this.metadata.toPublicJSON(),
      secretNames: this.secrets.map((secret) => secret.name),
      secretInventory: this.secrets.map((secret) => ({
        name: secret.name,
        type: secret.type ?? null,
        required: secret.required ?? null,
        hasValue: secret.value !== undefined && secret.value !== null && secret.value !== ''
      })),
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString(),
      version: this.version
    };
  }

  // The encrypted metadata index may retain non-public routing/profile state,
  // but never contains secret values or the sensitive metadata namespace.
  toInternalMetadataJSON() {
    return {
      ...this.toMetadataJSON(),
      ...(this.providerProfile ? { providerProfile: { ...this.providerProfile } } : {}),
      providerProfileMigration: { ...this.providerProfileMigration },
      ...(this.providerConfigurationId ? { providerConfigurationId: this.providerConfigurationId } : {}),
      ...(this.oauthCredentialBinding ? { oauthCredentialBinding: this.oauthCredentialBinding.toJSON() } : {}),
      ...(this.decommissioning ? { decommissioning: this.decommissioningJSON() } : {})
    };
  }

  toPublicMetadataJSON() { return this.toMetadataJSON(); }

  static from(data) {
    if (data instanceof Credential) return data;
    return new Credential(data);
  }
}
