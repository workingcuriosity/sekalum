import path from 'node:path';
import { SerializedMutationQueue } from './serialized-mutation-queue.js';

export class ProviderConfigurationStore {
  constructor({ jsonStore, basePath }) {
    if (!jsonStore?.load || !jsonStore?.save || !jsonStore?.exists) {
      throw new Error('ProviderConfigurationStore requires JsonStore');
    }

    this.jsonStore = jsonStore;
    this.filePath = path.join(basePath, 'provider-configurations.json');
    this.mutationQueue = new SerializedMutationQueue();
  }

  async load(configurationId) {
    const record = (await this.#loadRaw()).configurations.find(
      (entry) => entry.configurationId === configurationId
    );

    if (!record) {
      const error = new Error('Provider configuration not found');
      error.code = 'PROVIDER_CONFIGURATION_MISSING';
      error.statusCode = 400;
      throw error;
    }

    return structuredClone(record);
  }

  async list() {
    return structuredClone((await this.#loadRaw()).configurations);
  }

  async save(record) {
    return this.mutationQueue.run(async () => {
      const data = await this.#loadRaw();
      const index = data.configurations.findIndex(
        (entry) => entry.configurationId === record.configurationId
      );
      const serialized = structuredClone(record);

      if (index === -1) data.configurations.push(serialized);
      else data.configurations[index] = serialized;

      await this.jsonStore.save(this.filePath, data);
      return structuredClone(serialized);
    });
  }

  async delete(configurationId) {
    return this.mutationQueue.run(async () => {
      const data = await this.#loadRaw();
      const configurations = data.configurations.filter(
        (entry) => entry.configurationId !== configurationId
      );

      if (configurations.length === data.configurations.length) return false;
      await this.jsonStore.save(this.filePath, { configurations });
      return true;
    });
  }

  async #loadRaw() {
    if (!(await this.jsonStore.exists(this.filePath))) {
      return { configurations: [] };
    }

    const data = await this.jsonStore.load(this.filePath);
    if (!data || typeof data !== 'object' || !Array.isArray(data.configurations)) {
      throw new Error('ProviderConfigurationStore: invalid provider configuration file');
    }

    return { configurations: [...data.configurations] };
  }
}
