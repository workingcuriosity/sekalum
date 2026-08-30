import fs from 'node:fs/promises';
import path from 'node:path';
import { assertBackupPath, backupFilePath, backupPathError, validateBackupIdentifier } from './backup-path-policy.js';

export class ManagementBackupStore {
  constructor({ jsonStore, basePath }) {
    if (!jsonStore?.load || !jsonStore?.save) {
      throw new Error('ManagementBackupStore requires JsonStore');
    }

    this.jsonStore = jsonStore;
    this.directoryPath = path.join(basePath, 'management-backups');
  }

  async save(backup) {
    const filePath = this.#filePath(backup.backupId);
    await assertBackupPath(filePath, this.directoryPath, { allowMissing: true });
    await this.jsonStore.save(filePath, backup);
  }

  async load(backupId) {
    const filePath = this.#filePath(backupId);
    await assertBackupPath(filePath, this.directoryPath, { allowMissing: true });
    return this.jsonStore.load(filePath);
  }

  async list() {
    try {
      await assertBackupPath(this.directoryPath, this.directoryPath, { kind: 'directory' });
      const entries = await fs.readdir(this.directoryPath, { withFileTypes: true });
      return entries
        .filter((entry) => {
          if (entry.isSymbolicLink()) throw backupPathError('Symlinks are not allowed in the backup directory');
          return entry.name.endsWith('.json');
        })
        .map((entry) => {
          if (!entry.isFile()) throw backupPathError('Backup directory contains a non-regular file');
          return entry.name.replace(/\.json$/, '');
        })
        .sort()
        .reverse();
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  #filePath(backupId) {
    validateBackupIdentifier(backupId);
    return backupFilePath(this.directoryPath, [`${backupId}.json`]);
  }
}
