import { LegacyTokenCredentialStoreAdapter } from './legacy-token-credential-store-adapter.js';

export class CredentialStore {
  constructor({ storageAdapter = null, tokenStore = null } = {}) {
    if (storageAdapter) {
      this.storageAdapter = storageAdapter;
      return;
    }

    if (tokenStore) {
      this.storageAdapter = new LegacyTokenCredentialStoreAdapter({ tokenStore });
      return;
    }

    throw new Error('CredentialStore requires a storageAdapter');
  }

  async load(credentialId) {
    return this.storageAdapter.load(credentialId);
  }

  async save(credentialInput) {
    return this.storageAdapter.save(credentialInput);
  }

  async create(credentialInput) {
    if (typeof this.storageAdapter.create === 'function') return this.storageAdapter.create(credentialInput);
    return this.saveConditional(credentialInput, { requireExisting: false });
  }

  async saveConditional(credentialInput, options = {}) {
    if (typeof this.storageAdapter.saveConditional === 'function') {
      return this.storageAdapter.saveConditional(credentialInput, options);
    }
    return this.storageAdapter.save(credentialInput);
  }

  async applyBatch(changes, options = {}) {
    if (typeof this.storageAdapter.applyBatch !== 'function') {
      throw new Error('CredentialStore.applyBatch() requires an atomic storage adapter');
    }
    return this.storageAdapter.applyBatch(changes, options);
  }

  async delete(credentialId) {
    return this.storageAdapter.delete(credentialId);
  }

  async deleteConditional(credentialId, options = {}) {
    if (typeof this.storageAdapter.deleteConditional === 'function') {
      return this.storageAdapter.deleteConditional(credentialId, options);
    }
    return this.storageAdapter.delete(credentialId);
  }

  async exists(credentialId) {
    return this.storageAdapter.exists(credentialId);
  }

  async list() {
    return this.storageAdapter.list();
  }

  async listMetadata() {
    if (typeof this.storageAdapter.listMetadata === 'function') {
      return this.storageAdapter.listMetadata();
    }
    return (await this.storageAdapter.list()).map((credential) => (
      typeof credential?.toMetadataJSON === 'function'
        ? credential.toMetadataJSON()
        : credential
    ));
  }

  async loadMetadata(credentialId) {
    if (typeof this.storageAdapter.loadMetadata === 'function') {
      return this.storageAdapter.loadMetadata(credentialId);
    }
    const credential = (await this.listMetadata()).find((entry) => entry.credentialId === credentialId);
    if (!credential) {
      const error = new Error(`Credential '${credentialId}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    return credential;
  }

  async loadByCredentialKey(credentialKey) {
    if (typeof this.storageAdapter.loadByCredentialKey === 'function') {
      return this.storageAdapter.loadByCredentialKey(credentialKey);
    }
    const metadata = (await this.listMetadata()).find((entry) => entry.credentialKey === credentialKey);
    if (!metadata) {
      const error = new Error(`Credential '${credentialKey}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    return this.load(metadata.credentialId);
  }

  async loadByExternalReference(providerKey, externalReference) {
    if (typeof this.storageAdapter.loadByExternalReference === 'function') {
      return this.storageAdapter.loadByExternalReference(providerKey, externalReference);
    }

    const matches = (await this.list()).filter((credential) => (
      credential.providerKey === providerKey && credential.externalReference === externalReference
    ));
    if (matches.length === 0) {
      const error = new Error(`Credential '${providerKey}:${externalReference}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    if (matches.length > 1) {
      const error = new Error(`External Credential reference '${providerKey}:${externalReference}' is ambiguous`);
      error.code = 'CREDENTIAL_IDENTITY_AMBIGUOUS';
      throw error;
    }
    return matches[0];
  }

  async listLegacyTokens() {
    if (!this.storageAdapter.listLegacyTokens) {
      throw new Error('CredentialStore.listLegacyTokens() requires a legacy token storage adapter during MS8 migration');
    }

    return this.storageAdapter.listLegacyTokens();
  }
}
