import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const ENCRYPTED_JSON_TYPE = 'credential-hub-encrypted-json';
const ENCRYPTED_JSON_VERSION = 1;
const DEFAULT_KEY_VERSION = 1;
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const ENCODING = 'base64';

export class EncryptedJsonStoreError extends Error {
  constructor(code, message, { cause = undefined, details = {}, classification = null } = {}) {
    super(message, { cause });
    this.name = 'EncryptedJsonStoreError';
    this.code = code;
    this.classification = classification ?? EncryptedJsonStoreError.classificationFor(code);
    this.details = details;
  }

  static classificationFor(code) {
    if (code === 'ENCRYPTED_JSON_MISSING_KEY_VERSION') {
      return 'ENCRYPTION_KEY_MISMATCH';
    }
    if (['ENCRYPTED_JSON_INVALID_KEY_LENGTH', 'ENCRYPTED_JSON_KEYS_INVALID_JSON', 'ENCRYPTED_JSON_KEYS_INVALID_STRUCTURE', 'ENCRYPTED_JSON_KEYS_INVALID_KEY'].includes(code)) {
      return 'ENCRYPTION_KEY_CONFIGURATION_INVALID';
    }
    return 'ENCRYPTED_PAYLOAD_UNREADABLE';
  }
}

export class EncryptedJsonStore {
  constructor({ jsonStore, config }) {
    this.jsonStore = jsonStore;
    this.config = config;
  }

  async load(filePath) {
    const payload = await this.jsonStore.load(filePath);

    if (!this.#isEncryptedPayload(payload)) {
      return payload;
    }

    const decrypted = this.#decrypt(payload);
    return JSON.parse(decrypted);
  }

  async save(filePath, data) {
    const serialized = JSON.stringify(data);
    await this.jsonStore.save(filePath, this.#encrypt(serialized));
  }

  async exists(filePath) {
    return this.jsonStore.exists(filePath);
  }

  async delete(filePath) {
    return this.jsonStore.delete(filePath);
  }

  async ensureDirectory(directoryPath) {
    return this.jsonStore.ensureDirectory(directoryPath);
  }

  async getEncryptionMetadata(filePath) {
    const diagnostics = await this.getEncryptionDiagnostics(filePath);

    return {
      encrypted: diagnostics.encrypted,
      keyVersion: diagnostics.keyVersion,
      algorithm: diagnostics.algorithm,
      version: diagnostics.payloadVersion,
      currentKeyVersion: diagnostics.currentKeyVersion,
      needsReEncryption: diagnostics.needsReEncryption
    };
  }

  async getEncryptionDiagnostics(filePath) {
    const payload = await this.jsonStore.load(filePath);
    const currentKeyVersion = this.#currentKeyVersion();

    if (!this.#isEncryptedPayload(payload)) {
      return {
        encrypted: false,
        legacyPlaintext: true,
        algorithm: null,
        keyVersion: null,
        currentKeyVersion,
        payloadVersion: null,
        needsReEncryption: true
      };
    }

    const keyVersion = payload.keyVersion ?? DEFAULT_KEY_VERSION;

    return {
      encrypted: true,
      legacyPlaintext: false,
      algorithm: payload.algorithm,
      keyVersion,
      currentKeyVersion,
      payloadVersion: payload.version,
      needsReEncryption: keyVersion !== currentKeyVersion
    };
  }

  async needsReEncryption(filePath) {
    const metadata = await this.getEncryptionMetadata(filePath);

    return metadata.encrypted === false || metadata.needsReEncryption === true;
  }

  async reEncrypt(filePath) {
    const before = await this.getEncryptionMetadata(filePath);
    const data = await this.load(filePath);
    await this.save(filePath, data);
    const after = await this.getEncryptionMetadata(filePath);

    return {
      reEncrypted: before.encrypted === false || before.needsReEncryption === true,
      before,
      after
    };
  }

  assertConfigured() {
    this.#key(this.#currentKeyVersion());
  }

  async migrateBeforeServing({
    rootPath,
    rootFiles = [],
    recursiveDirectories = []
  }) {
    this.assertConfigured();
    const filePaths = await this.#storageFilePaths({ rootPath, rootFiles, recursiveDirectories });
    const migrated = [];
    let inspected = 0;

    for (const filePath of filePaths) {
      if (!(await this.exists(filePath))) continue;
      inspected += 1;
      const payload = await this.jsonStore.load(filePath);
      if (!this.#isEncryptedPayload(payload) && !this.#isSupportedLegacyPayload(rootPath, filePath, payload)) {
        throw new EncryptedJsonStoreError(
          'ENCRYPTED_JSON_UNKNOWN_LEGACY_FORMAT',
          'Secure storage contains an unsupported legacy format and cannot be served safely.',
          { details: { relativePath: path.relative(rootPath, filePath) } }
        );
      }

      await this.load(filePath);
      const before = await this.getEncryptionMetadata(filePath);
      if (before.encrypted === false || before.needsReEncryption === true) {
        await this.reEncrypt(filePath);
        migrated.push(path.relative(rootPath, filePath));
      }

      const after = await this.getEncryptionMetadata(filePath);
      if (after.encrypted !== true || after.needsReEncryption === true) {
        throw new EncryptedJsonStoreError(
          'ENCRYPTED_JSON_MIGRATION_INCOMPLETE',
          'Secure storage migration did not produce the active encrypted format.',
          { details: { relativePath: path.relative(rootPath, filePath) } }
        );
      }
    }

    return { inspected, migrated };
  }

  async #storageFilePaths({ rootPath, rootFiles, recursiveDirectories }) {
    const filePaths = rootFiles.map((fileName) => path.join(rootPath, fileName));
    for (const directoryName of recursiveDirectories) {
      const directoryPath = path.join(rootPath, directoryName);
      filePaths.push(...await this.#jsonFilesInDirectory(directoryPath));
    }
    return [...new Set(filePaths)].sort();
  }

  async #jsonFilesInDirectory(directoryPath) {
    let entries;
    try {
      entries = await fs.readdir(directoryPath, { withFileTypes: true });
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw error;
    }

    const files = [];
    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        throw new EncryptedJsonStoreError(
          'ENCRYPTED_JSON_STORAGE_LINK_UNSUPPORTED',
          'Secure storage cannot be migrated through a symbolic link.'
        );
      }
      const entryPath = path.join(directoryPath, entry.name);
      if (entry.isDirectory()) {
        files.push(...await this.#jsonFilesInDirectory(entryPath));
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        files.push(entryPath);
      }
    }
    return files;
  }

  #isSupportedLegacyPayload(rootPath, filePath, payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
    const relativePath = path.relative(rootPath, filePath);
    if (relativePath.includes(path.sep)) return Object.keys(payload).length > 0;

    const collectionFieldByFile = {
      'credentials.json': 'credentials',
      'credential-metadata.json': 'credentials',
      'access-management.json': 'users',
      'api-tokens.json': 'tokens',
      'audit-log.json': 'events',
      'consumer-grants.json': 'grants',
      'credential-policies.json': 'policies',
      'credential-secret-versions.json': 'versions',
      'lifecycle-notifications.json': 'notifications',
      'provider-configurations.json': 'configurations'
    };
    const field = collectionFieldByFile[path.basename(filePath)];
    return Boolean(field && Array.isArray(payload[field]));
  }

  #isEncryptedPayload(payload) {
    return Boolean(
      payload &&
      typeof payload === 'object' &&
      !Array.isArray(payload) &&
      payload.type === ENCRYPTED_JSON_TYPE
    );
  }

  #encrypt(plaintext) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.#key(this.#currentKeyVersion()), iv, {
      authTagLength: AUTH_TAG_LENGTH
    });

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);

    return {
      type: ENCRYPTED_JSON_TYPE,
      version: ENCRYPTED_JSON_VERSION,
      keyVersion: this.#currentKeyVersion(),
      algorithm: ALGORITHM,
      iv: iv.toString(ENCODING),
      tag: cipher.getAuthTag().toString(ENCODING),
      data: encrypted.toString(ENCODING)
    };
  }

  #decrypt(payload) {
    this.#validatePayload(payload);

    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      this.#key(payload.keyVersion ?? DEFAULT_KEY_VERSION),
      Buffer.from(payload.iv, ENCODING),
      { authTagLength: AUTH_TAG_LENGTH }
    );

    decipher.setAuthTag(Buffer.from(payload.tag, ENCODING));

    try {
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(payload.data, ENCODING)),
        decipher.final()
      ]);

      return decrypted.toString('utf8');
    } catch (error) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_DECRYPT_FAILED',
        'Encrypted JSON payload could not be decrypted. The key or payload integrity is invalid.',
        { cause: error, details: { keyVersion: payload.keyVersion ?? DEFAULT_KEY_VERSION, algorithm: payload.algorithm } }
      );
    }
  }

  #validatePayload(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_INVALID_PAYLOAD',
        'Invalid encrypted JSON payload: expected object.',
        { details: { reason: 'expected-object' } }
      );
    }

    if (payload.type !== ENCRYPTED_JSON_TYPE) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_UNSUPPORTED_TYPE',
        'Invalid encrypted JSON payload: unsupported type.',
        { details: { type: payload.type } }
      );
    }

    if (payload.version !== ENCRYPTED_JSON_VERSION) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_UNSUPPORTED_VERSION',
        `Unsupported encrypted JSON version: ${payload.version}`,
        { details: { version: payload.version } }
      );
    }

    if (payload.algorithm !== ALGORITHM) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_UNSUPPORTED_ALGORITHM',
        `Unsupported encrypted JSON algorithm: ${payload.algorithm}`,
        { details: { algorithm: payload.algorithm } }
      );
    }

    if (payload.keyVersion !== undefined) {
      this.#validateKeyVersion(payload.keyVersion);
    }

    const keyVersion = payload.keyVersion ?? DEFAULT_KEY_VERSION;
    this.#key(keyVersion);

    this.#validateBase64Field(payload, 'iv', IV_LENGTH);
    this.#validateBase64Field(payload, 'tag', AUTH_TAG_LENGTH);
    this.#validateBase64Field(payload, 'data');
  }

  #validateBase64Field(payload, fieldName, expectedLength = null) {
    const value = payload[fieldName];

    if (typeof value !== 'string' || value.length === 0) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_INVALID_FIELD',
        `Invalid encrypted JSON payload: ${fieldName} must be a non-empty base64 string.`,
        { details: { field: fieldName, reason: 'non-empty-base64-string-required' } }
      );
    }

    const decoded = Buffer.from(value, ENCODING);

    if (decoded.length === 0 || decoded.toString(ENCODING) !== value) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_INVALID_BASE64',
        `Invalid encrypted JSON payload: ${fieldName} must be valid base64.`,
        { details: { field: fieldName } }
      );
    }

    if (expectedLength !== null && decoded.length !== expectedLength) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_INVALID_FIELD_LENGTH',
        `Invalid encrypted JSON payload: ${fieldName} must decode to ${expectedLength} bytes.`,
        { details: { field: fieldName, expectedLength, actualLength: decoded.length } }
      );
    }
  }

  #currentKeyVersion() {
    const configured = this.config.get('TOKEN_ENCRYPTION_KEY_VERSION');

    if (configured !== null && configured !== undefined && configured !== '') {
      return this.#parseKeyVersion(configured, 'TOKEN_ENCRYPTION_KEY_VERSION');
    }

    const keys = this.#configuredKeys();
    return Math.max(...Object.keys(keys).map((version) => Number(version)));
  }

  #key(version = this.#currentKeyVersion()) {
    const keyVersion = this.#parseKeyVersion(version, 'encrypted JSON key version');
    const keys = this.#configuredKeys();
    const key = keys[keyVersion];

    if (!key) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_MISSING_KEY_VERSION',
        `Missing TOKEN_ENCRYPTION_KEY for encrypted JSON key version: ${keyVersion}`,
        { details: { keyVersion } }
      );
    }

    if (key.length !== 32) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_INVALID_KEY_LENGTH',
        `TOKEN_ENCRYPTION_KEY for version ${keyVersion} must contain exactly 32 characters.`,
        { details: { keyVersion, expectedLength: 32, actualLength: key.length } }
      );
    }

    if (this.config.get('NODE_ENV', 'development') === 'production'
      && key === 'DEV_ONLY_NOT_FOR_PRODUCTION_0000') {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_DEVELOPMENT_KEY_REJECTED',
        'The configured encryption key is a development sentinel and cannot be used in production.'
      );
    }

    return Buffer.from(key, 'utf8');
  }

  #configuredKeys() {
    const configuredKeys = this.config.get('TOKEN_ENCRYPTION_KEYS');

    if (!configuredKeys) {
      return { [DEFAULT_KEY_VERSION]: this.config.require('TOKEN_ENCRYPTION_KEY') };
    }

    let parsed;
    try {
      parsed = JSON.parse(configuredKeys);
    } catch (error) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_KEYS_INVALID_JSON',
        'TOKEN_ENCRYPTION_KEYS must be valid JSON.',
        { cause: error }
      );
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).length === 0) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_KEYS_INVALID_STRUCTURE',
        'TOKEN_ENCRYPTION_KEYS must be a non-empty object keyed by numeric key version.'
      );
    }

    const keys = {};

    for (const [version, key] of Object.entries(parsed)) {
      const normalizedVersion = this.#parseKeyVersion(version, 'TOKEN_ENCRYPTION_KEYS version');

      if (typeof key !== 'string' || key.length === 0) {
        throw new EncryptedJsonStoreError(
          'ENCRYPTED_JSON_KEYS_INVALID_KEY',
          `TOKEN_ENCRYPTION_KEYS version ${normalizedVersion} must contain a non-empty string key.`,
          { details: { keyVersion: normalizedVersion } }
        );
      }

      keys[normalizedVersion] = key;
    }

    return keys;
  }

  #validateKeyVersion(version) {
    this.#parseKeyVersion(version, 'encrypted JSON key version');
  }

  #parseKeyVersion(version, label) {
    const parsed = Number(version);

    if (!Number.isInteger(parsed) || parsed < 1) {
      throw new EncryptedJsonStoreError(
        'ENCRYPTED_JSON_INVALID_KEY_VERSION',
        `Invalid ${label}: expected positive integer.`,
        { details: { label, value: version } }
      );
    }

    return parsed;
  }
}
