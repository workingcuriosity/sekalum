import path from 'node:path';

import { ApiToken } from '../models/api-token.js';
import { SerializedMutationQueue } from './serialized-mutation-queue.js';

export class ApiTokenStore {
  constructor({ jsonStore, basePath }) {
    if (!jsonStore?.load || !jsonStore?.save || !jsonStore?.exists) {
      throw new Error('ApiTokenStore requires JsonStore');
    }

    this.jsonStore = jsonStore;
    this.filePath = path.join(basePath, 'api-tokens.json');
    this.mutationQueue = new SerializedMutationQueue();
  }

  async list() {
    const data = await this.#loadRaw();
    return data.tokens.map((tokenData) => ApiToken.from(tokenData));
  }

  async load(tokenId) {
    const token = (await this.list()).find((entry) => entry.id === tokenId);

    if (!token) {
      const error = new Error(`API token '${tokenId}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }

    return token;
  }

  async save(apiTokenInput) {
    return this.mutationQueue.run(async () => {
      const apiToken = ApiToken.from(apiTokenInput);
      const data = await this.#loadRaw();
      const index = data.tokens.findIndex((entry) => entry.id === apiToken.id);
      const current = index === -1 ? null : ApiToken.from(data.tokens[index]);
      const serialized = this.#mergeTerminalRevocation(current, apiToken).toJSON();

      if (index === -1) {
        data.tokens.push(serialized);
      } else {
        data.tokens[index] = serialized;
      }

      await this.jsonStore.save(this.filePath, data);
      return ApiToken.from(serialized);
    });
  }

  async delete(tokenId) {
    const data = await this.#loadRaw();
    const nextTokens = data.tokens.filter((entry) => entry.id !== tokenId);

    if (nextTokens.length === data.tokens.length) {
      return false;
    }

    await this.jsonStore.save(this.filePath, { ...data, tokens: nextTokens });
    return true;
  }

  async exists(tokenId) {
    return (await this.list()).some((entry) => entry.id === tokenId);
  }

  async findByPrefix(tokenPrefix) {
    return (await this.list()).filter((entry) => entry.tokenPrefix === tokenPrefix);
  }

  #mergeTerminalRevocation(current, incoming) {
    if (!current?.revokedAt || incoming.revokedAt) return incoming;

    return new ApiToken({
      ...incoming.toJSON(),
      revokedAt: current.revokedAt,
      version: Math.max(current.version, incoming.version) + 1
    });
  }

  async #loadRaw() {
    if (!(await this.jsonStore.exists(this.filePath))) {
      return { tokens: [] };
    }

    const data = await this.jsonStore.load(this.filePath);

    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('ApiTokenStore: api-tokens.json must contain an object');
    }

    if (data.tokens === undefined) {
      return { ...data, tokens: [] };
    }

    if (!Array.isArray(data.tokens)) {
      throw new Error('ApiTokenStore: tokens must be an array');
    }

    return { ...data, tokens: [...data.tokens] };
  }
}
