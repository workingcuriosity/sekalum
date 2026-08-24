import crypto from 'node:crypto';
import { CredentialSecret } from './credential-secret.js';
import { CredentialMetadata } from './credential-metadata.js';
import { LifecycleState, isLifecycleState } from './lifecycle-state.js';

export class Credential {
  constructor(input = {}) {
    const {
    credentialId = crypto.randomUUID(),
    providerKey,
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
    this.credentialKey = credentialKey;
    this.providerKey = providerKey;
    // null is retained only for records persisted before the method model.
    // Callers creating a method-based credential must provide its explicit key.
    this.credentialMethodKey = credentialMethodKey?.trim() ?? null;
    this.externalReference = externalReference;
    this.lifecycleState = lifecycleState;
    this.secrets = Object.freeze(secrets.map((secret) => CredentialSecret.from(secret)));
    this.metadata = CredentialMetadata.from(metadata);
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
      credentialKey: this.credentialKey,
      providerKey: this.providerKey,
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

  // Metadata projections are the default boundary for list, status, discovery
  // and presentation paths. Secret values are intentionally not included.
  toMetadataJSON() {
    return {
      credentialId: this.credentialId,
      credentialKey: this.credentialKey,
      providerKey: this.providerKey,
      credentialMethodKey: this.credentialMethodKey,
      externalReference: this.externalReference,
      lifecycleState: this.lifecycleState,
      metadata: this.metadata.toJSON(),
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

  static from(data) {
    if (data instanceof Credential) return data;
    return new Credential(data);
  }
}
