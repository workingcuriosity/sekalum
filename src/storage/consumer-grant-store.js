import path from 'node:path';
import { SerializedMutationQueue } from './serialized-mutation-queue.js';
import { withBindingCommitLock } from './binding-commit-coordinator.js';

export class ConsumerGrantStore {
  constructor({ jsonStore, basePath }) {
    if (!jsonStore?.load || !jsonStore?.save || !jsonStore?.exists) {
      throw new Error('ConsumerGrantStore requires JsonStore');
    }

    this.jsonStore = jsonStore;
    this.filePath = path.join(basePath, 'consumer-grants.json');
    this.mutationQueue = new SerializedMutationQueue();
  }

  async load() {
    if (!(await this.jsonStore.exists(this.filePath))) return { revision: 0, grants: [] };
    const data = await this.jsonStore.load(this.filePath);
    if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.grants)) {
      throw new Error('ConsumerGrantStore: invalid consumer grant collection');
    }
    return { ...data, revision: Number.isInteger(data.revision) && data.revision >= 0 ? data.revision : 0, grants: [...data.grants] };
  }

  async save(data, { expectedRevision = undefined, beforeCommit = null } = {}) {
    if (!data || !Array.isArray(data.grants)) {
      throw new Error('ConsumerGrantStore: grants must be an array');
    }
    await withBindingCommitLock(() => this.mutationQueue.run(async () => {
      const current = await this.load();
      if (expectedRevision !== undefined && current.revision !== expectedRevision) {
        const error = new Error('Consumer grant collection changed before persistence');
        error.code = 'CONSUMER_GRANT_CONFLICT';
        throw error;
      }
      if (beforeCommit) await beforeCommit({ currentRevision: current.revision });
      await this.jsonStore.save(this.filePath, { ...data, revision: current.revision + 1, grants: [...data.grants] });
    }));
  }
}
