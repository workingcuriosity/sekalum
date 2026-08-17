// Copyright (C) 2026 Working Curiosity
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import path from 'node:path';

import { Credential } from '../models/credential.js';

function assertUniqueCredentialKeys(credentials) {
  const byKey = new Map();
  for (const credential of credentials) {
    const existing = byKey.get(credential.credentialKey);
    if (existing && existing.credentialId !== credential.credentialId) {
      const error = new Error(`Credential key '${credential.credentialKey}' is assigned to credentials '${existing.credentialId}' and '${credential.credentialId}'`);
      error.code = 'CREDENTIAL_KEY_DUPLICATE';
      throw error;
    }
    byKey.set(credential.credentialKey, credential);
  }
}

export class CredentialCollectionStoreAdapter {
  constructor({ jsonStore, basePath }) {
    if (!jsonStore?.load || !jsonStore?.save || !jsonStore?.exists) {
      throw new Error('CredentialCollectionStoreAdapter requires JsonStore');
    }

    this.jsonStore = jsonStore;
    this.filePath = path.join(basePath, 'credentials.json');
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
    });
    return savedCredential;
  }

  async delete(credentialId) {
    return this.#serializeMutation(async () => {
      const data = await this.#loadRaw();
      const credentials = data.credentials.filter((entry) => entry.credentialId !== credentialId);
      if (credentials.length === data.credentials.length) return false;
      await this.jsonStore.save(this.filePath, { ...data, credentials });
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
      }
      return credentials;
    });
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

  #serializeMutation(operation) {
    const result = this.mutationQueue.then(operation, operation);
    this.mutationQueue = result.then(() => undefined, () => undefined);
    return result;
  }
}
