// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import path from 'node:path';

import { Credential } from '../models/credential.js';
import { SerializedMutationQueue } from './serialized-mutation-queue.js';

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
    this.mutationQueue = new SerializedMutationQueue();
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
    return this.#serializeMutation(() => this.#saveWithinMutation(credentialInput));
  }

  async create(credentialInput) {
    return this.#serializeMutation(() => this.#saveWithinMutation(credentialInput, { insertOnly: true }));
  }

  async saveConditional(credentialInput, { expectedVersion = undefined, requireExisting = true } = {}) {
    return this.#serializeMutation(() => this.#saveWithinMutation(credentialInput, { expectedVersion, requireExisting }));
  }

  async applyBatch(changes = [], { afterCommit = null } = {}) {
    if (!Array.isArray(changes)) {
      throw new Error('CredentialCollectionStoreAdapter.applyBatch() requires an array');
    }

    return this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      const credentials = data.credentials.map((entry) => Credential.from(entry));
      const touchedIds = new Set();

      for (const change of changes) {
        const mode = change?.mode;
        const input = Credential.from(change?.credential);
        if (!['create', 'update'].includes(mode)) {
          throw this.#atomicityError('CREDENTIAL_IMPORT_OPERATION_INVALID', 'Credential import operation is invalid', 400);
        }
        if (touchedIds.has(input.credentialId)) {
          throw this.#atomicityError('CREDENTIAL_IMPORT_DUPLICATE_TARGET', 'Credential import targets the same identity more than once', 409);
        }
        touchedIds.add(input.credentialId);

        const index = credentials.findIndex((entry) => entry.credentialId === input.credentialId);
        const existing = index === -1 ? null : credentials[index];
        if (mode === 'create') {
          if (existing) {
            throw this.#atomicityError('CREDENTIAL_ALREADY_EXISTS', `Credential '${input.credentialId}' already exists`, 409);
          }
          if (data.tombstones.some((entry) => entry.credentialId === input.credentialId)) {
            throw this.#lifecycleConflict(`Credential '${input.credentialId}' has a deleted identity barrier`, {
              credentialId: input.credentialId,
              expectedVersion: undefined,
              actualVersion: null,
              reason: 'DELETED_IDENTITY_BARRIER'
            });
          }
          credentials.push(input);
          continue;
        }

        if (!existing) {
          throw this.#lifecycleConflict(`Credential '${input.credentialId}' no longer exists`, {
            credentialId: input.credentialId,
            expectedVersion: change.expectedVersion,
            actualVersion: null,
            reason: 'MISSING'
          });
        }
        if (change.expectedVersion !== undefined && existing.version !== change.expectedVersion) {
          throw this.#lifecycleConflict(`Credential '${input.credentialId}' changed before lifecycle persistence`, {
            credentialId: input.credentialId,
            expectedVersion: change.expectedVersion,
            actualVersion: existing.version,
            reason: 'VERSION_MISMATCH'
          });
        }
        if (existing.lifecycleState === 'revoked' && input.lifecycleState !== 'revoked') {
          throw this.#lifecycleConflict(`Credential '${input.credentialId}' is terminally revoked`, {
            credentialId: input.credentialId,
            expectedVersion: change.expectedVersion,
            actualVersion: existing.version,
            reason: 'TERMINAL_REVOCATION'
          });
        }
        if (existing.lifecycleState === 'deleted' && input.lifecycleState !== 'deleted') {
          throw this.#lifecycleConflict(`Credential '${input.credentialId}' is terminally deleted`, {
            credentialId: input.credentialId,
            expectedVersion: change.expectedVersion,
            actualVersion: existing.version,
            reason: 'TERMINAL_DELETION'
          });
        }
        if (input.credentialKey !== existing.credentialKey) {
          throw this.#atomicityError('CREDENTIAL_KEY_IMMUTABLE', `Credential '${input.credentialId}' credentialKey cannot be changed`, 409);
        }
        credentials[index] = input;
      }

      assertUniqueCredentialKeys(credentials);
      const nextData = { ...data, credentials: credentials.map((entry) => entry.toJSON()) };
      await this.#saveCollectionState(nextData, credentials, data);

      try {
        const callbackResult = await afterCommit?.({ credentials: [...credentials], changes });
        return { credentials, callbackResult };
      } catch (error) {
        await this.#saveCollectionState(data, data.credentials.map((entry) => Credential.from(entry)), data);
        throw error;
      }
    });
  }

  async delete(credentialId) {
    return this.#deleteWithinMutation(credentialId);
  }

  async deleteConditional(credentialId, { expectedVersion = undefined } = {}) {
    return this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      const current = data.credentials.find((entry) => entry.credentialId === credentialId);
      if (expectedVersion !== undefined && (!current || current.version !== expectedVersion)) {
        throw this.#lifecycleConflict(`Credential '${credentialId}' changed before deletion`, {
          credentialId,
          expectedVersion,
          actualVersion: current?.version ?? null,
          reason: current ? 'VERSION_MISMATCH' : 'MISSING'
        });
      }
      return this.#deleteWithinMutationData(data, credentialId);
    });
  }

  async #deleteWithinMutation(credentialId) {
    return this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      return this.#deleteWithinMutationData(data, credentialId);
    });
  }

  async #deleteWithinMutationData(data, credentialId) {
    const deleted = data.credentials.find((entry) => entry.credentialId === credentialId);
    const credentials = data.credentials.filter((entry) => entry.credentialId !== credentialId);
    if (credentials.length === data.credentials.length) return false;
    const tombstones = Array.isArray(data.tombstones) ? [...data.tombstones] : [];
    if (!tombstones.some((entry) => entry.credentialId === credentialId)) {
      tombstones.push({
        credentialId: deleted.credentialId,
        credentialKey: deleted.credentialKey,
        credentialGeneration: deleted.credentialGeneration ?? `legacy:${deleted.credentialId}`,
        deletedAt: new Date().toISOString(),
        version: deleted.version
      });
    }
    await this.jsonStore.save(this.filePath, { ...data, credentials, tombstones });
    await this.#saveMetadata(credentials.map((entry) => Credential.from(entry)));
    return true;
  }

  async exists(credentialId) {
    return (await this.list()).some((entry) => entry.credentialId === credentialId);
  }

  async isDeletedIdentity(credentialId) {
    return this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      return data.tombstones.some((entry) => entry.credentialId === credentialId);
    });
  }

  async list() {
    return this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      const credentials = data.credentials.map((credential) => Credential.from(credential));
      assertUniqueCredentialKeys(credentials);
      const migrated = credentials.some((credential, index) => !data.credentials[index].credentialKey || !data.credentials[index].credentialGeneration);
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
        return credentials.map((credential) => credential.toInternalMetadataJSON?.() ?? credential.toMetadataJSON());
      }
      if (await this.metadataJsonStore.exists(this.metadataFilePath)) {
        const data = await this.metadataJsonStore.load(this.metadataFilePath);
        if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.credentials)) {
          const error = new Error('Credential metadata persistence contains an invalid credential collection');
          error.code = 'CREDENTIAL_METADATA_PERSISTENCE_INVALID';
          throw error;
        }
        const credentials = data.credentials.map((credential) => ({
          ...credential,
          credentialGeneration: credential.credentialGeneration ?? `legacy:${credential.credentialId}`
        }));
        assertUniqueCredentialKeys(credentials);
        return credentials;
      }

      // One-time migration. Normal metadata reads never load the secret-bearing file.
      const data = await this.#loadRaw();
      const credentials = data.credentials.map((credential) => Credential.from(credential));
      assertUniqueCredentialKeys(credentials);
      const migrated = credentials.some((credential, index) => !data.credentials[index].credentialKey || !data.credentials[index].credentialGeneration);
      if (migrated) {
        await this.jsonStore.save(this.filePath, {
          ...data,
          credentials: credentials.map((credential) => credential.toJSON())
        });
      }
      await this.#saveMetadata(credentials);
      return credentials.map((credential) => credential.toInternalMetadataJSON?.() ?? credential.toMetadataJSON());
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
    if (!(await this.jsonStore.exists(this.filePath))) return { credentials: [], tombstones: [] };
    const data = await this.jsonStore.load(this.filePath);
    if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.credentials)) {
      const error = new Error('Credential persistence contains an invalid credential collection');
      error.code = 'CREDENTIAL_PERSISTENCE_INVALID';
      throw error;
    }
    return { ...data, credentials: [...data.credentials], tombstones: Array.isArray(data.tombstones) ? [...data.tombstones] : [] };
  }

  async #saveMetadata(credentials) {
    if (!this.metadataJsonStore) return;
    await this.metadataJsonStore.save(this.metadataFilePath, {
      schemaVersion: 1,
      credentials: credentials.map((credential) => Credential.from(credential).toInternalMetadataJSON())
    });
  }

  async #saveCollectionState(nextData, nextCredentials, previousData) {
    try {
      await this.jsonStore.save(this.filePath, nextData);
      await this.#saveMetadata(nextCredentials);
    } catch (error) {
      try {
        await this.jsonStore.save(this.filePath, previousData);
        await this.#saveMetadata(previousData.credentials.map((entry) => Credential.from(entry)));
      } catch (rollbackError) {
        throw this.#atomicityError(
          'CREDENTIAL_ATOMIC_ROLLBACK_FAILED',
          'Credential import persistence could not be rolled back safely',
          500,
          { causeCode: rollbackError?.code ?? 'ROLLBACK_FAILED' }
        );
      }
      throw this.#atomicityError(
        'CREDENTIAL_ATOMIC_COMMIT_FAILED',
        'Credential import could not be committed atomically',
        500,
        { causeCode: error?.code ?? 'COMMIT_FAILED' }
      );
    }
  }

  #serializeMutation(operation) {
    return this.mutationQueue.run(operation);
  }

  async #saveWithinMutation(credentialInput, { expectedVersion = undefined, requireExisting = false, insertOnly = false } = {}) {
    const data = await this.#loadRaw();
    const input = credentialInput instanceof Credential ? credentialInput.toJSON() : credentialInput;
    const credentials = data.credentials.map((entry) => Credential.from(entry));
    const existing = credentials.find((entry) => entry.credentialId === input.credentialId);
    if (insertOnly && existing) {
      const error = new Error(`Credential '${input.credentialId}' already exists`);
      error.code = 'CREDENTIAL_ALREADY_EXISTS';
      throw error;
    }
    if (requireExisting && !existing) {
      throw this.#lifecycleConflict(`Credential '${input.credentialId}' no longer exists`, {
        credentialId: input.credentialId,
        expectedVersion,
        actualVersion: null,
        reason: 'MISSING'
      });
    }
    if (!existing && data.tombstones.some((entry) => entry.credentialId === input.credentialId)) {
      throw this.#lifecycleConflict(`Credential '${input.credentialId}' has a deleted identity barrier`, {
        credentialId: input.credentialId,
        expectedVersion,
        actualVersion: null,
        reason: 'DELETED_IDENTITY_BARRIER'
      });
    }
    if (expectedVersion !== undefined && (!existing || existing.version !== expectedVersion)) {
      throw this.#lifecycleConflict(`Credential '${input.credentialId}' changed before lifecycle persistence`, {
        credentialId: input.credentialId,
        expectedVersion,
        actualVersion: existing?.version ?? null,
        reason: existing ? 'VERSION_MISMATCH' : 'MISSING'
      });
    }
    if (existing?.lifecycleState === 'revoked' && input.lifecycleState !== 'revoked') {
      throw this.#lifecycleConflict(`Credential '${input.credentialId}' is terminally revoked`, {
        credentialId: input.credentialId,
        expectedVersion,
        actualVersion: existing.version,
        reason: 'TERMINAL_REVOCATION'
      });
    }
    if (existing?.lifecycleState === 'deleted' && input.lifecycleState !== 'deleted') {
      throw this.#lifecycleConflict(`Credential '${input.credentialId}' is terminally deleted`, {
        credentialId: input.credentialId,
        expectedVersion,
        actualVersion: existing.version,
        reason: 'TERMINAL_DELETION'
      });
    }

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
    const index = credentials.findIndex((entry) => entry.credentialId === credential.credentialId);
    if (index === -1) credentials.push(credential);
    else credentials[index] = credential;
    assertUniqueCredentialKeys(credentials);

    await this.jsonStore.save(this.filePath, {
      ...data,
      credentials: credentials.map((entry) => entry.toJSON())
    });
    await this.#saveMetadata(credentials);
    return credential;
  }

  #lifecycleConflict(message, details) {
    const error = new Error(message);
    error.code = 'CREDENTIAL_LIFECYCLE_CONFLICT';
    error.details = details;
    return error;
  }

  #atomicityError(code, message, statusCode, details = {}) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    error.details = details;
    return error;
  }

  #orphanedIdentity(details) {
    const error = new Error('Credential metadata references a missing canonical Credential identity');
    error.code = 'CREDENTIAL_IDENTITY_ORPHANED';
    error.details = details;
    return error;
  }
}
