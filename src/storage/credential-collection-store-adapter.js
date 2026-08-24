// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import path from 'node:path';

import { Credential } from '../models/credential.js';

function assertUniqueCredentialKeys(credentials) {
  const byKey = new Map();
  const byId = new Map();
  for (const credential of credentials) {
    const existingById = byId.get(credential.credentialId);
    if (existingById && existingById.credentialKey !== credential.credentialKey) {
      const error = new Error(`Credential identity '${credential.credentialId}' has conflicting persisted projections`);
      error.code = 'CREDENTIAL_IDENTITY_CONFLICT';
      throw error;
    }
    const existing = byKey.get(credential.credentialKey);
    if (existing && existing.credentialId !== credential.credentialId) {
      const error = new Error(`Credential key '${credential.credentialKey}' is assigned to credentials '${existing.credentialId}' and '${credential.credentialId}'`);
      error.code = 'CREDENTIAL_KEY_DUPLICATE';
      throw error;
    }
    byId.set(credential.credentialId, credential);
    byKey.set(credential.credentialKey, credential);
  }
}

export class CredentialCollectionStoreAdapter {
  constructor({ jsonStore, metadataJsonStore = null, basePath }) {
    if (!jsonStore?.load || !jsonStore?.save || !jsonStore?.exists) {
      throw new Error('CredentialCollectionStoreAdapter requires JsonStore');
    }

    this.jsonStore = jsonStore;
    this.metadataJsonStore = metadataJsonStore;
    this.filePath = path.join(basePath, 'credentials.json');
    this.metadataFilePath = path.join(basePath, 'credential-metadata.json');
    this.mutationQueue = Promise.resolve();
  }

  async load(credentialId) {
    const credential = (await this.list()).find((entry) => entry.credentialId === credentialId);
    if (!credential) {
      const error = new Error(`Credential '${credentialId}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    return credential;
  }

  async save(credentialInput) {
    let savedCredential;
    await this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      const input = credentialInput instanceof Credential ? credentialInput.toJSON() : credentialInput;
      const credentials = data.credentials.map((entry) => Credential.from(entry));
      const existing = credentials.find((entry) => entry.credentialId === input.credentialId);
      const hasCredentialKey = Object.hasOwn(input, 'credentialKey');
      if (existing && hasCredentialKey && input.credentialKey !== existing.credentialKey) {
        const error = new Error(`Credential '${existing.credentialId}' credentialKey cannot be changed`);
        error.code = 'CREDENTIAL_KEY_IMMUTABLE';
        throw error;
      }
      const credential = Credential.from({
        ...(existing ?? {}),
        ...input,
        ...(hasCredentialKey || !existing ? {} : { credentialKey: existing.credentialKey })
      });
      savedCredential = credential;
      const index = credentials.findIndex((entry) => entry.credentialId === credential.credentialId);
      if (index === -1) credentials.push(credential);
      else credentials[index] = credential;
      assertUniqueCredentialKeys(credentials);

      await this.jsonStore.save(this.filePath, {
        ...data,
        credentials: credentials.map((entry) => entry.toJSON())
      });
      await this.#saveMetadata(credentials);
    });
    return savedCredential;
  }

  async delete(credentialId) {
    return this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      const credentials = data.credentials.filter((entry) => entry.credentialId !== credentialId);
      if (credentials.length === data.credentials.length) return false;
      await this.jsonStore.save(this.filePath, { ...data, credentials });
      await this.#saveMetadata(credentials.map((entry) => Credential.from(entry)));
      return true;
    });
  }

  async exists(credentialId) {
    return (await this.list()).some((entry) => entry.credentialId === credentialId);
  }

  async list() {
    return this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      const credentials = data.credentials.map((credential) => Credential.from(credential));
      assertUniqueCredentialKeys(credentials);
      const migrated = credentials.some((credential, index) => !data.credentials[index].credentialKey);
      if (migrated) {
        await this.jsonStore.save(this.filePath, {
          ...data,
          credentials: credentials.map((credential) => credential.toJSON())
        });
        await this.#saveMetadata(credentials);
      }
      return credentials;
    });
  }

  async listMetadata() {
    return this.#serializeMutation(async () => {
      if (!this.metadataJsonStore) {
        const credentials = (await this.#loadRaw()).credentials.map((credential) => Credential.from(credential));
        assertUniqueCredentialKeys(credentials);
        return credentials.map((credential) => credential.toMetadataJSON());
      }
      if (await this.metadataJsonStore.exists(this.metadataFilePath)) {
        const data = await this.metadataJsonStore.load(this.metadataFilePath);
        if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.credentials)) {
          const error = new Error('Credential metadata persistence contains an invalid credential collection');
          error.code = 'CREDENTIAL_METADATA_PERSISTENCE_INVALID';
          throw error;
        }
        const credentials = data.credentials.map((credential) => ({ ...credential }));
        assertUniqueCredentialKeys(credentials);
        return credentials;
      }

      // One-time migration. Normal metadata reads never load the secret-bearing file.
      const data = await this.#loadRaw();
      const credentials = data.credentials.map((credential) => Credential.from(credential));
      assertUniqueCredentialKeys(credentials);
      const migrated = credentials.some((credential, index) => !data.credentials[index].credentialKey);
      if (migrated) {
        await this.jsonStore.save(this.filePath, {
          ...data,
          credentials: credentials.map((credential) => credential.toJSON())
        });
      }
      await this.#saveMetadata(credentials);
      return credentials.map((credential) => credential.toMetadataJSON());
    });
  }

  async loadMetadata(credentialId) {
    const credential = (await this.listMetadata()).find((entry) => entry.credentialId === credentialId);
    if (!credential) {
      const error = new Error(`Credential '${credentialId}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    return credential;
  }

  async loadByCredentialKey(credentialKey) {
    const metadata = (await this.listMetadata()).find((entry) => entry.credentialKey === credentialKey);
    if (!metadata) {
      const error = new Error(`Credential '${credentialKey}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    try {
      return await this.load(metadata.credentialId);
    } catch (error) {
      if (error?.code !== 'NOT_FOUND') throw error;
      throw this.#orphanedIdentity({ credentialKey, credentialId: metadata.credentialId });
    }
  }

  async loadByExternalReference(providerKey, externalReference) {
    const matches = (await this.listMetadata()).filter((entry) => (
      entry.providerKey === providerKey && entry.externalReference === externalReference
    ));
    if (matches.length === 0) {
      const error = new Error(`Credential '${providerKey}:${externalReference}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    if (matches.length > 1) {
      const error = new Error(`External Credential reference '${providerKey}:${externalReference}' is ambiguous`);
      error.code = 'CREDENTIAL_IDENTITY_AMBIGUOUS';
      error.details = { providerKey, externalReference, credentialIds: matches.map((entry) => entry.credentialId) };
      throw error;
    }
    try {
      return await this.load(matches[0].credentialId);
    } catch (error) {
      if (error?.code !== 'NOT_FOUND') throw error;
      throw this.#orphanedIdentity({
        providerKey,
        externalReference,
        credentialId: matches[0].credentialId
      });
    }
  }

  async #loadRaw() {
    if (!(await this.jsonStore.exists(this.filePath))) return { credentials: [] };
    const data = await this.jsonStore.load(this.filePath);
    if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.credentials)) {
      const error = new Error('Credential persistence contains an invalid credential collection');
      error.code = 'CREDENTIAL_PERSISTENCE_INVALID';
      throw error;
    }
    return { ...data, credentials: [...data.credentials] };
  }

  async #saveMetadata(credentials) {
    if (!this.metadataJsonStore) return;
    await this.metadataJsonStore.save(this.metadataFilePath, {
      schemaVersion: 1,
      credentials: credentials.map((credential) => Credential.from(credential).toMetadataJSON())
    });
  }

  #serializeMutation(operation) {
    const result = this.mutationQueue.then(operation, operation);
    this.mutationQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  #orphanedIdentity(details) {
    const error = new Error('Credential metadata references a missing canonical Credential identity');
    error.code = 'CREDENTIAL_IDENTITY_ORPHANED';
    error.details = details;
    return error;
  }
}
