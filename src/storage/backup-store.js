import path from 'path';
import { TokenRecord } from '../models/token-record.js';
import { assertBackupPath, backupFilePath, backupPathError, validateBackupIdentifier } from './backup-path-policy.js';

export class BackupStore {
  constructor({ jsonStore, basePath }) {
    this.jsonStore = jsonStore;
    this.basePath = basePath;
  }

  async createBackup(tokenRecord) {
    if (!(tokenRecord instanceof TokenRecord)) {
      throw new Error('BackupStore.createBackup() requires a TokenRecord');
    }

    const backupId = this.#createBackupId();
    const directory = this.#directoryPath(tokenRecord.providerId);
    const filePath = this.#filePath(tokenRecord.providerId, backupId);
    await assertBackupPath(filePath, directory, { allowMissing: true });

    await this.jsonStore.save(
      filePath,
      this.#serialize(tokenRecord)
    );

    return backupId;
  }

  async restore(providerId, backupId, { existingCredentialKey } = {}) {
    const directory = this.#directoryPath(providerId);
    const filePath = this.#filePath(providerId, backupId);
    await assertBackupPath(filePath, directory, { allowMissing: true });
    const data = await this.jsonStore.load(filePath);
    const migratedData = Object.hasOwn(data, 'credentialKey')
      ? data
      : { ...data, ...(existingCredentialKey === undefined ? {} : { credentialKey: existingCredentialKey }) };
    return new TokenRecord(migratedData);
  }

  async listBackups(providerId) {
    const directory = this.#directoryPath(providerId);

    if (!(await this.jsonStore.exists(directory))) {
      return [];
    }

    const fs = await import('fs/promises');
    await assertBackupPath(directory, directory, { kind: 'directory' });
    const entries = await fs.readdir(directory, { withFileTypes: true });

    return entries
      .filter(entry => {
        if (entry.isSymbolicLink()) throw backupPathError('Symlinks are not allowed in the backup directory');
        return entry.name.endsWith('.json');
      })
      .map(entry => {
        if (!entry.isFile()) throw backupPathError('Backup directory contains a non-regular file');
        return entry.name.replace(/\.json$/, '');
      })
      .sort();
  }

  async deleteBackup(providerId, backupId) {
    const directory = this.#directoryPath(providerId);
    const filePath = this.#filePath(providerId, backupId);
    await assertBackupPath(filePath, directory, { allowMissing: true });
    return this.jsonStore.delete(filePath);
  }

  #filePath(providerId, backupId) {
    validateBackupIdentifier(backupId);
    const directory = this.#directoryPath(providerId);
    return backupFilePath(directory, [`${backupId}.json`]);
  }

  #directoryPath(providerId) {
    const { provider, account } = this.#parseProviderId(providerId);
    return path.join(this.basePath, 'backups', provider, account);
  }

  #parseProviderId(providerId) {
    const parts = typeof providerId === 'string' ? providerId.split(':') : [];
    if (parts.length !== 2) {
      throw backupPathError('providerId must contain one provider and one account identifier');
    }
    const [provider, account] = parts;

    validateBackupIdentifier(provider, 'providerId provider');
    validateBackupIdentifier(account, 'providerId account');

    return { provider, account };
  }

  #createBackupId() {
    return new Date().toISOString().replace(/[:.]/g, '-');
  }

  #serialize(tokenRecord) {
    return {
      id: tokenRecord.id,
      credentialKey: tokenRecord.credentialKey,
      providerId: tokenRecord.providerId,
      provider: tokenRecord.provider,
      accountId: tokenRecord.accountId,
      accountName: tokenRecord.accountName,
      ...(tokenRecord.credentialGeneration ? { credentialGeneration: tokenRecord.credentialGeneration } : {}),
      accessToken: tokenRecord.accessToken,
      refreshToken: tokenRecord.refreshToken,
      expiresAt: tokenRecord.expiresAt,
      scopes: tokenRecord.scopes,
      metadata: tokenRecord.metadata,
      createdAt: tokenRecord.createdAt,
      updatedAt: tokenRecord.updatedAt,
      lastRefreshAt: tokenRecord.lastRefreshAt,
      lastHealthCheckAt: tokenRecord.lastHealthCheckAt,
      version: tokenRecord.version
    };
  }
}
