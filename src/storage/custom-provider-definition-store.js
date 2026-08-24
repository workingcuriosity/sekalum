import path from 'node:path';

/** Stores declarative custom-provider definitions only; credentials remain in CredentialStore. */
export class CustomProviderDefinitionStore {
  constructor({ jsonStore, basePath }) {
    this.jsonStore = jsonStore;
    this.filePath = path.join(basePath, 'custom-provider-definitions.json');
  }

  async list() {
    const data = await this.#load();
    return structuredClone(data.providers);
  }

  async get(key) {
    const data = await this.#load();
    const definition = data.providers.find((entry) => entry.key === key);
    return definition ? structuredClone(definition) : null;
  }

  async save(definition) {
    const data = await this.#load();
    if (data.providers.some((entry) => entry.key === definition.key)) {
      const error = new Error(`Provider '${definition.key}' already exists`);
      error.code = 'PROVIDER_ALREADY_EXISTS';
      error.statusCode = 409;
      throw error;
    }
    data.providers.push(structuredClone(definition));
    await this.jsonStore.save(this.filePath, data);
    return structuredClone(definition);
  }

  async delete(key) {
    const data = await this.#load();
    const index = data.providers.findIndex((entry) => entry.key === key);
    if (index === -1) return false;
    data.providers.splice(index, 1);
    await this.jsonStore.save(this.filePath, data);
    return true;
  }

  async update(key, updater) {
    const data = await this.#load();
    const index = data.providers.findIndex((entry) => entry.key === key);
    if (index === -1) return null;

    const current = structuredClone(data.providers[index]);
    const updated = await updater(current);
    data.providers[index] = structuredClone(updated);
    await this.jsonStore.saveAtomic(this.filePath, data);
    return structuredClone(updated);
  }

  async #load() {
    if (!(await this.jsonStore.exists(this.filePath))) return { providers: [] };
    const data = await this.jsonStore.load(this.filePath);
    if (!data || typeof data !== 'object' || !Array.isArray(data.providers)) {
      throw new Error('CustomProviderDefinitionStore: invalid custom provider definition file');
    }
    return { providers: data.providers };
  }
}
