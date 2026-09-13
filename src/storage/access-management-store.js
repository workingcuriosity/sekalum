import path from 'node:path';

export class AccessManagementStore {
  constructor({ jsonStore, basePath }) {
    if (!jsonStore?.load || !jsonStore?.save) {
      throw new Error('AccessManagementStore requires JsonStore');
    }

    this.jsonStore = jsonStore;
    this.filePath = path.join(basePath, 'access-management.json');
    this.tombstoneFilePath = path.join(basePath, 'access-management-tombstones.json');
  }

  async load() {
    return this.jsonStore.load(this.filePath);
  }

  async save(data) {
    await this.jsonStore.save(this.filePath, data);
  }

  async loadPrincipalTombstones() {
    return this.jsonStore.load(this.tombstoneFilePath);
  }

  async savePrincipalTombstones(data) {
    await this.jsonStore.save(this.tombstoneFilePath, data);
  }
}
