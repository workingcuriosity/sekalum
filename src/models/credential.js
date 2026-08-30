import crypto from 'node:crypto';
import { CredentialSecret } from './credential-secret.js';
import { CredentialMetadata } from './credential-metadata.js';
import { LifecycleState, isLifecycleState } from './lifecycle-state.js';

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
    externalReference = null,
    lifecycleState = LifecycleState.REGISTERED,
    secrets = [],
    metadata = {},
    createdAt = new Date(),
    updatedAt = new Date(),
    version = 1
    } = input;
    const credentialKey = Object.hasOwn(input, 'credentialKey')
      ? input.credentialKey
      : crypto.randomUUID();

    if (!credentialId) throw new Error("Credential: 'credentialId' is required");
    if (typeof credentialGeneration !== 'string' || credentialGeneration.trim() === '') {
      throw new Error("Credential: 'credentialGeneration' is required");
    }
    if (typeof credentialKey !== 'string' || credentialKey.trim() === '') {
      throw new Error("Credential: 'credentialKey' is required");
    }
    if (!providerKey) throw new Error("Credential: 'providerKey' is required");
    if (credentialMethodKey !== null && (typeof credentialMethodKey !== 'string' || credentialMethodKey.trim() === '')) {
      throw new Error("Credential: 'credentialMethodKey' must be a non-empty string or null");
    }
    if (!isLifecycleState(lifecycleState)) {
      throw new Error(`Credential: invalid lifecycleState '${lifecycleState}'`);
    }

    this.credentialId = credentialId;
    this.credentialGeneration = credentialGeneration.trim();
    this.credentialKey = credentialKey;
    this.providerKey = providerKey;
    // null is retained only for records persisted before the method model.
    // Callers creating a method-based credential must provide its explicit key.
    this.credentialMethodKey = credentialMethodKey?.trim() ?? null;
    this.externalReference = externalReference;
    this.lifecycleState = lifecycleState;
    this.secrets = Object.freeze(secrets.map((secret) => CredentialSecret.from(secret)));
    this.metadata = CredentialMetadata.from(metadata);
    const metadataJSON = this.metadata.toJSON();
    const legacyCustomProfile = !providerProfile && Boolean(metadataJSON.custom?.providerProfile);
    const normalizedProfile = profileIdentity(providerProfile ?? metadataJSON.custom?.providerProfile);
    this.providerProfile = normalizedProfile ? Object.freeze(normalizedProfile) : null;
    this.providerProfileMigration = migrationStateFor(this.providerProfile, providerProfileMigration, { legacyCustomProfile });
    this.providerConfigurationId = providerConfigurationId
      ?? metadataJSON.custom?.providerConfigurationId
      ?? null;
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
      credentialMethodKey: this.credentialMethodKey,
      externalReference: this.externalReference,
      lifecycleState: this.lifecycleState,
      secrets: this.secrets.map((secret) => secret.toJSON()),
      metadata: this.metadata.toJSON(),
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString(),
      version: this.version
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
      ...(this.providerConfigurationId ? { providerConfigurationId: this.providerConfigurationId } : {})
    };
  }

  toPublicMetadataJSON() { return this.toMetadataJSON(); }

  static from(data) {
    if (data instanceof Credential) return data;
    return new Credential(data);
  }
}
