import fs from 'fs/promises';
import path from 'path';
import { TokenRecord } from '../models/token-record.js';
import { safeErrorMessage } from '../utils/safe-diagnostics.js';

const TOKEN_FILE_NAME_PATTERN = /^[A-Za-z0-9_-]+\.json$/;

export class TokenStore {
  constructor({
    jsonStore,
    basePath,
    logger
}) {
    this.jsonStore = jsonStore;
    this.basePath = basePath;
    this.logger = logger;
}

  async load(providerId) {
    const filePath = this.#filePath(providerId);
    const data = await this.jsonStore.load(filePath);
    const record = new TokenRecord(data);
    const { records } = await this.#readRecords();
    this.#assertUniqueCredentialKeys([...records.filter((entry) => entry.providerId !== record.providerId), record]);
    if (!Object.hasOwn(data, 'credentialKey') || !Object.hasOwn(data, 'id')) await this.save(record);
    return record;
  }

  async loadById(id) {
    const record = (await this.list()).find((entry) => entry.id === id);
    if (!record) {
      const error = new Error(`Token record '${id}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    return record;
  }

  async save(tokenRecord) {
    if (!(tokenRecord instanceof TokenRecord)) {
      throw new Error('TokenStore.save() requires a TokenRecord');
    }

    const { records, legacyProviderIds } = await this.#readRecords();
    const existing = records.find((entry) => entry.providerId === tokenRecord.providerId);
    if (existing && !legacyProviderIds.has(existing.providerId) && existing.credentialKey !== tokenRecord.credentialKey) {
      const error = new Error(`Credential '${tokenRecord.providerId}' credentialKey cannot be changed`);
      error.code = 'CREDENTIAL_KEY_IMMUTABLE';
      throw error;
    }
    this.#assertUniqueCredentialKeys([...records.filter((entry) => entry.providerId !== tokenRecord.providerId), tokenRecord]);

    await this.jsonStore.save(
      this.#filePath(tokenRecord.providerId),
      this.#serialize(tokenRecord)
    );
  }

  async delete(providerId) {
    return this.jsonStore.delete(this.#filePath(providerId));
  }

  async exists(providerId) {
    return this.jsonStore.exists(this.#filePath(providerId));
  }

  async list() {
    const { records, migrate } = await this.#readRecords();
    this.#assertUniqueCredentialKeys(records);
    const snapshots = migrate.map(({ filePath, data }) => ({ filePath, data }));
    let migrated = 0;
    try {
      for (const { record } of migrate) {
        await this.save(record);
        migrated += 1;
      }
    } catch (error) {
      let restored = 0;
      let rollbackError = null;
      for (const snapshot of snapshots) {
        try {
          await this.jsonStore.save(snapshot.filePath, snapshot.data);
          restored += 1;
        } catch (restoreError) {
          rollbackError ??= restoreError;
        }
      }
      if (rollbackError) {
        this.logger?.error?.(`[TokenStore] Legacy credential-key migration rollback failed after ${migrated} writes; restored ${restored} of ${snapshots.length} files`);
        error.rollbackCode = rollbackError.code ?? 'UNKNOWN';
      }
      throw error;
    }
    return records;
  }

  async #readRecords() {
    const tokensRoot = path.join(this.basePath, 'tokens');
    if (!(await this.jsonStore.exists(tokensRoot))) return { records: [], migrate: [], legacyProviderIds: new Set() };

    const records = [];
    const migrate = [];
    const legacyProviderIds = new Set();
    const providers = await fs.readdir(tokensRoot, { withFileTypes: true });
    for (const providerEntry of providers) {
      if (!providerEntry.isDirectory()) continue;

      const providerDir = path.join(tokensRoot, providerEntry.name);
      const files = await fs.readdir(providerDir, { withFileTypes: true });
      for (const fileEntry of files) {
        if (!fileEntry.isFile() || !TOKEN_FILE_NAME_PATTERN.test(fileEntry.name)) continue;

        const filePath = path.join(providerDir, fileEntry.name);
        try {
          const data = await this.jsonStore.load(filePath);
          const record = new TokenRecord(data);
          records.push(record);
          if (!Object.hasOwn(data, 'credentialKey') || !Object.hasOwn(data, 'id')) {
            migrate.push({ record, filePath, data });
            legacyProviderIds.add(record.providerId);
          }
        } catch (error) {
          console.warn(`[TokenStore] Ignoring invalid token file '${filePath}': ${safeErrorMessage(error, 'invalid token file')}`);
        }
      }
    }
    return { records, migrate, legacyProviderIds };
  }

  #assertUniqueCredentialKeys(records) {
    const byKey = new Map();
    for (const record of records) {
      const existing = byKey.get(record.credentialKey);
      if (existing && existing.providerId !== record.providerId) {
        const error = new Error(`Credential key '${record.credentialKey}' is assigned to credentials '${existing.providerId}' and '${record.providerId}'`);
        error.code = 'CREDENTIAL_KEY_DUPLICATE';
        throw error;
      }
      byKey.set(record.credentialKey, record);
    }
  }

  #filePath(providerId) {
    const { provider, account } = this.#parseProviderId(providerId);
    return path.join(this.basePath, 'tokens', provider, `${account}.json`);
  }

  #parseProviderId(providerId) {
    const [provider, account] = String(providerId).split(':');

    if (!provider || !account) {
      throw new Error(
        `Invalid providerId '${providerId}'. Expected format: provider:account`
      );
    }

    return { provider, account };
  }

  #validateTokenData(data, filePath) {
    if (!data || typeof data !== 'object') {
      throw new Error(`Token file is not an object: ${filePath}`);
    }

    if (!data.providerId) {
      throw new Error(`Missing providerId in token file: ${filePath}`);
    }

    if (!data.provider) {
      throw new Error(`Missing provider in token file: ${filePath}`);
    }

    if (!data.accountId) {
      throw new Error(`Missing accountId in token file: ${filePath}`);
    }
  }

  #serialize(tokenRecord) {
    return {
      id: tokenRecord.id,
      credentialKey: tokenRecord.credentialKey,
      providerId: tokenRecord.providerId,
      provider: tokenRecord.provider,
      accountId: tokenRecord.accountId,
      accountName: tokenRecord.accountName,
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
