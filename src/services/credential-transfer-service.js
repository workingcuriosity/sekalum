import crypto from 'node:crypto';

import { Credential } from '../models/credential.js';
import { safeError } from '../utils/safe-diagnostics.js';

const TRANSFER_FORMAT = 'credential-hub-credential-transfer';
const SCHEMA_VERSION = 1;
const CONFLICT_STRATEGIES = Object.freeze(['skip', 'overwrite', 'rename']);
const CSV_IMPORT_REQUIRED_HEADERS = Object.freeze(['providerKey', 'externalReference']);
const CSV_IMPORT_DIRECT_SECRET_HEADERS = Object.freeze(['username', 'password', 'pass', 'apiKey', 'api_key', 'token', 'accessToken', 'refreshToken', 'clientId', 'clientSecret', 'client_secret']);
const EXPORT_ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const EXPORT_ENCRYPTION_KDF = 'pbkdf2';
const EXPORT_ENCRYPTION_DIGEST = 'sha256';
const EXPORT_ENCRYPTION_ITERATIONS = 210000;
const EXPORT_ENCRYPTION_KEY_LENGTH = 32;
const EXPORT_ENCRYPTION_SALT_LENGTH = 16;
const EXPORT_ENCRYPTION_IV_LENGTH = 12;

export const MAX_IMPORT_PAYLOAD_BYTES = 5 * 1024 * 1024;
export const MAX_IMPORT_RECORDS = 100;
export const MAX_CONCURRENT_IMPORT_KDF = 2;
export const MAX_PENDING_IMPORTS = 0;
export const MAX_IMPORT_RETRIES = 0;

export class CredentialTransferService {
  constructor({ credentialManager, providerManager = null, auditLogService = null, clock = () => new Date(), idGenerator = () => crypto.randomUUID() } = {}) {
    if (!credentialManager) {
      throw new Error('CredentialTransferService requires CredentialManager');
    }

    this.credentialManager = credentialManager;
    this.providerManager = providerManager;
    this.auditLogService = auditLogService;
    this.clock = clock;
    this.idGenerator = idGenerator;
    this.activeImportKdf = 0;
  }

  async exportCredentials(options = {}, context = {}) {
    try {
      const encryptionPassword = this.#requireExportEncryptionPassword(options);
      const credentials = await this.#selectCredentials(options);
      const generatedAt = this.#timestamp();
      const payload = {
        format: TRANSFER_FORMAT,
        schemaVersion: SCHEMA_VERSION,
        generatedAt,
        metadata: {
          credentialCount: credentials.length,
          selection: options.all === true ? 'all' : 'credentialIds'
        },
        credentials: credentials.map((credential) => this.#toCredential(credential).toJSON())
      };

      const exportEnvelope = await this.#buildExportEnvelope(payload, { encryptionPassword });

      await this.#recordAudit({
        action: 'credential-export.created',
        targetId: null,
        result: 'success',
        context,
        details: {
          credentialCount: credentials.length,
          selection: payload.metadata.selection,
          encrypted: exportEnvelope.encrypted === true
        }
      });

      return {
        format: TRANSFER_FORMAT,
        schemaVersion: SCHEMA_VERSION,
        generatedAt,
        filename: this.#filename(generatedAt, exportEnvelope.encrypted === true),
        contentType: 'application/json; charset=utf-8',
        payload: exportEnvelope,
        content: JSON.stringify(exportEnvelope, null, 2),
        encrypted: exportEnvelope.encrypted === true
      };
    } catch (error) {
      await this.#recordAudit({
        action: 'credential-export.created',
        targetId: null,
        result: 'failure',
        context,
        details: { error: safeError(error, { fallbackMessage: 'Credential export failed' }) }
      });
      throw error;
    }
  }

  async previewImport(transferInput, optionsOrContext = {}, maybeContext = {}) {
    const { importOptions, context } = this.#normalizeImportArguments(optionsOrContext, maybeContext);

    try {
      const payload = await this.#parseTransferInput(transferInput, importOptions);
      const credentials = payload.credentials.map((credential) => this.#toCredential(credential));
      const existingCredentials = (await this.credentialManager.listCredentials()).map((credential) => this.#toCredential(credential));
      const items = credentials.map((credential) => this.#previewCredential(credential, existingCredentials));
      const summary = this.#summarizePreview(items);

      await this.#recordAudit({
        action: 'credential-import.previewed',
        targetId: null,
        result: 'success',
        context,
        details: summary
      });

      return {
        format: payload.format,
        schemaVersion: payload.schemaVersion,
        generatedAt: payload.generatedAt,
        summary,
        items
      };
    } catch (error) {
      await this.#recordAudit({
        action: 'credential-import.previewed',
        targetId: null,
        result: 'failure',
        context,
        details: { error: safeError(error, { fallbackMessage: 'Credential import preview failed' }) }
      });
      throw error;
    }
  }

  async importCredentials(transferInput, options = {}, context = {}) {
    const strategy = this.#normalizeConflictStrategy(options.conflictStrategy ?? 'skip');

    try {
      const payload = await this.#parseTransferInput(transferInput, options);
      const existingCredentials = (await this.credentialManager.listCredentials()).map((credential) => this.#toCredential(credential));
      const results = [];
      const operations = [];

      for (const inputCredential of payload.credentials.map((credential) => this.#toCredential(credential))) {
        const preview = this.#previewCredential(inputCredential, existingCredentials);

        if (preview.conflict && strategy === 'skip') {
          results.push({
            credentialId: inputCredential.credentialId,
            action: 'skipped',
            success: true,
            conflict: preview.conflict
          });
          continue;
        }

        if (preview.conflict && strategy === 'overwrite') {
          operations.push({
            action: 'overwrite',
            targetCredentialId: preview.conflict.targetCredentialId,
            expectedVersion: preview.conflict.expectedVersion,
            sourceCredentialId: inputCredential.credentialId,
            credential: inputCredential.toJSON()
          });
          results.push({
            credentialId: preview.conflict.targetCredentialId,
            sourceCredentialId: inputCredential.credentialId,
            action: 'overwritten',
            success: true,
            conflict: preview.conflict
          });
          continue;
        }

        const credentialToRegister = preview.conflict && strategy === 'rename'
          ? this.#renameCredential(inputCredential, existingCredentials)
          : inputCredential;

        operations.push({
          action: 'create',
          sourceCredentialId: inputCredential.credentialId,
          resultAction: preview.conflict ? 'renamed' : 'created',
          credential: credentialToRegister.toJSON()
        });
        existingCredentials.push(credentialToRegister);
        results.push({
          credentialId: credentialToRegister.credentialId,
          sourceCredentialId: inputCredential.credentialId,
          action: preview.conflict ? 'renamed' : 'created',
          success: true,
          conflict: preview.conflict ?? null
        });
      }

      const summary = {
        requested: payload.credentials.length,
        created: results.filter((result) => result.action === 'created').length,
        overwritten: results.filter((result) => result.action === 'overwritten').length,
        renamed: results.filter((result) => result.action === 'renamed').length,
        skipped: results.filter((result) => result.action === 'skipped').length,
        failed: results.filter((result) => result.success === false).length,
        conflictStrategy: strategy
      };

      if (typeof this.credentialManager.importCredentialBatch !== 'function') {
        throw this.#atomicityError('CREDENTIAL_IMPORT_ATOMICITY_UNSUPPORTED', 'Credential import requires an atomic credential store', 500);
      }

      await this.credentialManager.importCredentialBatch(operations, {
        createdBy: context.userId ?? 'system',
        onCommitted: () => this.#recordAudit({
          action: 'credential-import.completed',
          targetId: null,
          result: 'success',
          context,
          details: summary
        })
      });

      return { summary, results };
    } catch (error) {
      await this.#recordAudit({
        action: 'credential-import.completed',
        targetId: null,
        result: 'failure',
        context,
        details: { error: safeError(error, { fallbackMessage: 'Credential import failed' }), conflictStrategy: strategy }
      });
      throw error;
    }
  }

  async previewCsvImport(csvInput, optionsOrContext = {}, maybeContext = {}) {
    const { importOptions, context } = this.#normalizeImportArguments(optionsOrContext, maybeContext);

    try {
      const transferPayload = await this.#csvToTransferPayload(csvInput, importOptions);
      const result = await this.previewImport(transferPayload, context);

      await this.#recordAudit({
        action: 'credential-csv-import.previewed',
        targetId: null,
        result: 'success',
        context,
        details: result.summary
      });

      return {
        ...result,
        sourceFormat: 'csv',
        csv: transferPayload.metadata.csv
      };
    } catch (error) {
      await this.#recordAudit({
        action: 'credential-csv-import.previewed',
        targetId: null,
        result: 'failure',
        context,
        details: { error: safeError(error, { fallbackMessage: 'Credential CSV import preview failed' }) }
      });
      throw error;
    }
  }

  async importCsvCredentials(csvInput, options = {}, context = {}) {
    try {
      const transferPayload = await this.#csvToTransferPayload(csvInput, options);
      const result = await this.importCredentials(transferPayload, options, context);

      await this.#recordAudit({
        action: 'credential-csv-import.completed',
        targetId: null,
        result: 'success',
        context,
        details: result.summary
      });

      return {
        ...result,
        sourceFormat: 'csv',
        csv: transferPayload.metadata.csv
      };
    } catch (error) {
      await this.#recordAudit({
        action: 'credential-csv-import.completed',
        targetId: null,
        result: 'failure',
        context,
        details: { error: safeError(error, { fallbackMessage: 'Credential CSV import failed' }), conflictStrategy: options.conflictStrategy ?? 'skip' }
      });
      throw error;
    }
  }

  async #selectCredentials(options = {}) {
    if (options.all === true) {
      return this.credentialManager.listCredentials();
    }

    if (!Array.isArray(options.credentialIds) || options.credentialIds.length === 0) {
      throw this.#badRequest('credentialIds must contain at least one credentialId unless all is true');
    }

    const credentials = [];
    for (const credentialId of options.credentialIds) {
      const credential = await this.credentialManager.getCredential(credentialId);
      if (!credential) {
        throw this.#notFound(`Credential '${credentialId}' not found`);
      }
      credentials.push(credential);
    }
    return credentials;
  }

  #toCredential(value) {
    if (value instanceof Credential) return value;
    if (value?.toJSON && typeof value.toJSON === 'function') {
      return Credential.from(value.toJSON());
    }
    return Credential.from(value);
  }

  async #parseTransferInput(input, options = {}) {
    this.#assertImportPayloadSize(input);
    const envelope = typeof input === 'string' ? this.#parseJson(input) : input;

    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      throw this.#badRequest('transfer payload must be an object');
    }

    const payload = envelope.encrypted === true
      ? await this.#decryptTransferEnvelope(envelope, options)
      : envelope;

    this.#validatePlainTransferPayload(payload);
    return payload;
  }


  async #csvToTransferPayload(csvInput, options = {}) {
    this.#assertImportPayloadSize(csvInput);
    const csv = this.#parseCsv(csvInput);
    this.#validateCsvHeaders(csv.headers);
    const generatedAt = this.#timestamp();
    const credentials = [];
    const mappings = [];

    for (const [index, row] of csv.rows.entries()) {
      const rowNumber = index + 2;
      const normalized = await this.#normalizeCsvRow(row, rowNumber);
      credentials.push(this.#csvRowToCredential(normalized.row, rowNumber, options, normalized.fields).toJSON());
      mappings.push({
        rowNumber,
        providerKey: normalized.row.providerKey,
        fields: normalized.mappings
      });
    }

    return {
      format: TRANSFER_FORMAT,
      schemaVersion: SCHEMA_VERSION,
      generatedAt,
      metadata: {
        credentialCount: credentials.length,
        selection: 'csv-import',
        csv: {
          rowCount: csv.rows.length,
          headers: csv.headers,
          mappings
        }
      },
      credentials
    };
  }

  #parseCsv(input) {
    if (typeof input !== 'string') {
      throw this.#badRequest('CSV import content must be a string');
    }

    const text = input.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    if (text.trim() === '') {
      throw this.#badRequest('CSV import content must not be empty');
    }

    const records = [];
    let record = [];
    let field = '';
    let inQuotes = false;

    for (let index = 0; index < text.length; index += 1) {
      const char = text[index];
      const next = text[index + 1];

      if (char === '"') {
        if (inQuotes && next === '"') {
          field += '"';
          index += 1;
        } else {
          inQuotes = !inQuotes;
        }
        continue;
      }

      if (char === ',' && !inQuotes) {
        record.push(field);
        field = '';
        continue;
      }

      if (char === '\n' && !inQuotes) {
        record.push(field);
        records.push(record);
        record = [];
        field = '';
        continue;
      }

      field += char;
    }

    if (inQuotes) {
      throw this.#badRequest('CSV import content contains an unterminated quoted field');
    }

    record.push(field);
    records.push(record);

    const nonEmptyRecords = records.filter((item) => item.some((value) => String(value ?? '').trim() !== ''));
    if (nonEmptyRecords.length < 2) {
      throw this.#badRequest('CSV import content must include a header row and at least one data row');
    }

    const headers = nonEmptyRecords[0].map((header) => String(header ?? '').trim());
    if (headers.some((header) => header === '')) {
      throw this.#badRequest('CSV import headers must not be empty');
    }

    const rows = nonEmptyRecords.slice(1).map((values, index) => {
      if (values.length !== headers.length) {
        throw this.#badRequest(`CSV row ${index + 2} must contain exactly ${headers.length} fields`);
      }
      return Object.fromEntries(headers.map((header, valueIndex) => [header, String(values[valueIndex] ?? '').trim()]));
    });

    if (rows.length > MAX_IMPORT_RECORDS) {
      throw this.#atomicityError('IMPORT_RECORD_COUNT_EXCEEDED', `Credential import supports at most ${MAX_IMPORT_RECORDS} records`, 413);
    }

    return { headers, rows };
  }

  #validateCsvHeaders(headers) {
    const duplicates = headers.filter((header, index) => headers.indexOf(header) !== index);
    if (duplicates.length > 0) {
      throw this.#badRequest(`CSV import headers must be unique: ${[...new Set(duplicates)].join(', ')}`);
    }

    for (const requiredHeader of CSV_IMPORT_REQUIRED_HEADERS) {
      if (!headers.includes(requiredHeader)) {
        throw this.#badRequest(`CSV import requires header '${requiredHeader}'`);
      }
    }

  }

  async #normalizeCsvRow(row, rowNumber) {
    const provider = await this.#providerDefinitionForCsv(row.providerKey);
    const fields = this.#credentialFieldsForCsv(provider, row.credentialMethodKey, rowNumber);
    if (fields.length === 0) {
      return { row, fields, mappings: [] };
    }

    const aliases = new Map();
    for (const field of fields) {
      for (const alias of [field.key, ...(field.csvAliases ?? [])]) {
        const normalizedAlias = String(alias).trim().toLowerCase();
        const existingTarget = aliases.get(normalizedAlias);
        if (existingTarget && existingTarget !== field.key) {
          throw this.#badRequest(`CSV row ${rowNumber} has ambiguous field alias '${alias}'`);
        }
        aliases.set(normalizedAlias, field.key);
      }
    }

    const normalized = { ...row };
    const mappings = [];
    for (const [header, value] of Object.entries(row)) {
      const target = aliases.get(header.trim().toLowerCase());
      if (!target || target === header) continue;
      if (normalized[target] !== undefined && normalized[target] !== value && normalized[target] !== '') {
        throw this.#badRequest(`CSV row ${rowNumber} maps multiple columns to '${target}'`);
      }
      normalized[target] = value;
      delete normalized[header];
      mappings.push({ source: header, target });
    }

    return { row: normalized, fields, mappings };
  }

  async #providerDefinitionForCsv(providerKey) {
    if (!providerKey || typeof this.providerManager?.getProvider !== 'function') {
      return null;
    }

    try {
      const provider = await this.providerManager.getProvider(providerKey);
      if (!provider) {
        throw this.#badRequest(`CSV provider '${providerKey}' is not registered`);
      }
      return provider;
    } catch {
      throw this.#badRequest(`CSV provider '${providerKey}' is not registered`);
    }
  }

  #csvRowToCredential(row, rowNumber, options = {}, fields = []) {
    const providerKey = row.providerKey;
    const externalReference = row.externalReference;

    if (!providerKey) {
      throw this.#badRequest(`CSV row ${rowNumber} requires providerKey`);
    }
    if (!externalReference) {
      throw this.#badRequest(`CSV row ${rowNumber} requires externalReference`);
    }

    const provider = this.#providerDefinitionForCsvSync(providerKey);
    if ((provider?.credentialMethods ?? []).length > 0 && !row.credentialMethodKey) {
      throw this.#badRequest(`CSV row ${rowNumber} requires credentialMethodKey for provider '${providerKey}'`);
    }

    const secrets = this.#secretsFromCsvRow(row, rowNumber, fields);
    if (secrets.length === 0) {
      const secretFieldKeys = new Set(fields.filter((field) => field.secret).map((field) => field.key));
      const hasSecretColumn = Object.keys(row).some((header) => (
        header.startsWith('secret.')
        || CSV_IMPORT_DIRECT_SECRET_HEADERS.includes(header)
        || secretFieldKeys.has(header)
      ));
      if (!hasSecretColumn) {
        throw this.#badRequest('CSV import requires at least one secret column such as secret.apiKey, apiKey, token, username or password');
      }
      throw this.#badRequest(`CSV row ${rowNumber} requires at least one non-empty secret value`);
    }

    const generatedAt = this.#timestamp();
    return Credential.from({
      credentialId: row.credentialId || this.idGenerator(),
      providerKey,
      credentialMethodKey: row.credentialMethodKey || null,
      externalReference,
      lifecycleState: row.lifecycleState || 'registered',
      secrets,
      metadata: {
        displayName: row.displayName || row.name || externalReference,
        description: row.description || null,
        scopes: this.#splitCsvList(row.scopes),
        tags: this.#splitCsvList(row.tags),
        expiresAt: row.expiresAt || null,
        custom: {
          source: options.source ?? 'csv-import',
          sourceRow: rowNumber,
          ...(row.type ? { type: row.type } : {}),
          ...(row.providerType ? { providerType: row.providerType } : {}),
          ...this.#customValuesFromCsvRow(row, fields)
        }
      },
      createdAt: row.createdAt || generatedAt,
      updatedAt: row.updatedAt || generatedAt,
      version: row.version ? Number(row.version) : 1
    });
  }

  #secretsFromCsvRow(row, rowNumber, fields = []) {
    const secrets = [];
    const usedNames = new Set();
    const secretFieldKeys = new Set(fields.filter((field) => field.secret).map((field) => field.key));
    const methodScoped = fields.length > 0;

    for (const [header, value] of Object.entries(row)) {
      if (!header.startsWith('secret.') && !(methodScoped ? secretFieldKeys.has(header) : CSV_IMPORT_DIRECT_SECRET_HEADERS.includes(header))) {
        continue;
      }
      if (value === '') continue;

      const name = header.startsWith('secret.') ? header.slice('secret.'.length).trim() : header;
      if (!name) {
        throw this.#badRequest(`CSV row ${rowNumber} contains an empty secret column name`);
      }
      if (usedNames.has(name)) {
        throw this.#badRequest(`CSV row ${rowNumber} contains duplicate secret '${name}'`);
      }
      if (methodScoped && !secretFieldKeys.has(name)) {
        throw this.#badRequest(`CSV row ${rowNumber} secret '${name}' is not defined by credentialMethodKey '${row.credentialMethodKey}'`);
      }
      usedNames.add(name);
      secrets.push({ name, value, metadata: { source: 'csv-import' } });
    }

    return secrets;
  }

  #customValuesFromCsvRow(row, fields = []) {
    const standardFields = new Set(['displayName', 'description', 'scopes']);
    const custom = {};
    for (const field of fields) {
      if (field.secret || standardFields.has(field.key) || row[field.key] === undefined || row[field.key] === '') {
        continue;
      }
      custom[field.key] = row[field.key];
    }
    return custom;
  }

  #credentialFieldsForCsv(provider, credentialMethodKey, rowNumber) {
    const methods = provider?.credentialMethods ?? [];
    const bindings = provider?.providerMethodBindings ?? [];
    if (methods.length === 0 && bindings.length === 0) return provider?.credentialFields ?? [];
    if (!credentialMethodKey) {
      throw this.#badRequest(`CSV row ${rowNumber} requires credentialMethodKey for provider '${provider.key}'`);
    }
    const method = methods.find((candidate) => candidate.key === credentialMethodKey);
    const binding = bindings.find((candidate) => candidate.methodKey === credentialMethodKey);
    if (!method || !binding) {
      throw this.#badRequest(`CSV row ${rowNumber} credentialMethodKey '${credentialMethodKey}' is not available for provider '${provider.key}'`);
    }
    return method.credentialFields ?? [];
  }

  #providerDefinitionForCsvSync(providerKey) {
    if (!providerKey || typeof this.providerManager?.getProvider !== 'function') return null;
    try {
      return this.providerManager.getProvider(providerKey);
    } catch {
      return null;
    }
  }

  #splitCsvList(value) {
    if (!value) return [];
    return String(value)
      .split(/[|;]/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  async #buildExportEnvelope(payload, options = {}) {
    const password = options.encryptionPassword;

    const salt = crypto.randomBytes(EXPORT_ENCRYPTION_SALT_LENGTH);
    const iv = crypto.randomBytes(EXPORT_ENCRYPTION_IV_LENGTH);
    const key = await this.#deriveTransferKey(
      password,
      salt,
      EXPORT_ENCRYPTION_ITERATIONS,
      EXPORT_ENCRYPTION_DIGEST
    );
    const cipher = crypto.createCipheriv(EXPORT_ENCRYPTION_ALGORITHM, key, iv);
    const plaintext = JSON.stringify(payload);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      format: TRANSFER_FORMAT,
      schemaVersion: SCHEMA_VERSION,
      encrypted: true,
      generatedAt: payload.generatedAt,
      metadata: payload.metadata,
      encryption: {
        algorithm: EXPORT_ENCRYPTION_ALGORITHM,
        kdf: EXPORT_ENCRYPTION_KDF,
        digest: EXPORT_ENCRYPTION_DIGEST,
        iterations: EXPORT_ENCRYPTION_ITERATIONS,
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64')
      },
      ciphertext: ciphertext.toString('base64')
    };
  }

  #requireExportEncryptionPassword(options = {}) {
    const password = options.encryptionPassword ?? options.password;
    if (typeof password !== 'string' || password.trim() === '') {
      throw this.#badRequest('credential export requires a non-empty encryption password');
    }
    return password;
  }

  async #decryptTransferEnvelope(envelope, options = {}) {
    this.#validateEncryptedEnvelope(envelope);
    const password = options.encryptionPassword ?? options.password ?? null;
    if (!password || typeof password !== 'string') {
      throw this.#badRequest('encrypted credential transfer requires an import password');
    }

    try {
      const salt = Buffer.from(envelope.encryption.salt, 'base64');
      const iv = Buffer.from(envelope.encryption.iv, 'base64');
      const authTag = Buffer.from(envelope.encryption.authTag, 'base64');
      const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
      const key = await this.#deriveTransferKey(
        password,
        salt,
        envelope.encryption.iterations,
        envelope.encryption.digest,
        { admitImport: true }
      );
      const decipher = crypto.createDecipheriv(envelope.encryption.algorithm, key, iv);
      decipher.setAuthTag(authTag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
      return this.#parseJson(plaintext);
    } catch (error) {
      if (error?.code === 'IMPORT_CAPACITY_EXHAUSTED') throw error;
      throw this.#badRequest('encrypted credential transfer could not be decrypted; password or file integrity check failed');
    }
  }

  #validatePlainTransferPayload(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw this.#badRequest('transfer payload must be an object');
    }
    if (payload.format !== TRANSFER_FORMAT) {
      throw this.#badRequest(`transfer payload format must be '${TRANSFER_FORMAT}'`);
    }
    if (payload.schemaVersion !== SCHEMA_VERSION) {
      throw this.#badRequest(`transfer payload schemaVersion must be ${SCHEMA_VERSION}`);
    }
    if (!Array.isArray(payload.credentials)) {
      throw this.#badRequest('transfer payload credentials must be an array');
    }
    if (payload.credentials.length > MAX_IMPORT_RECORDS) {
      throw this.#atomicityError('IMPORT_RECORD_COUNT_EXCEEDED', `Credential import supports at most ${MAX_IMPORT_RECORDS} records`, 413);
    }
  }

  #validateEncryptedEnvelope(envelope) {
    if (envelope.format !== TRANSFER_FORMAT) {
      throw this.#badRequest(`transfer payload format must be '${TRANSFER_FORMAT}'`);
    }
    if (envelope.schemaVersion !== SCHEMA_VERSION) {
      throw this.#badRequest(`transfer payload schemaVersion must be ${SCHEMA_VERSION}`);
    }
    if (!envelope.encryption || typeof envelope.encryption !== 'object') {
      throw this.#badRequest('encrypted transfer payload requires encryption metadata');
    }
    if (envelope.encryption.algorithm !== EXPORT_ENCRYPTION_ALGORITHM) {
      throw this.#badRequest(`encrypted transfer algorithm must be '${EXPORT_ENCRYPTION_ALGORITHM}'`);
    }
    if (envelope.encryption.kdf !== EXPORT_ENCRYPTION_KDF) {
      throw this.#badRequest(`encrypted transfer kdf must be '${EXPORT_ENCRYPTION_KDF}'`);
    }
    if (envelope.encryption.digest !== EXPORT_ENCRYPTION_DIGEST) {
      throw this.#badRequest(`encrypted transfer digest must be '${EXPORT_ENCRYPTION_DIGEST}'`);
    }
    if (envelope.encryption.iterations !== EXPORT_ENCRYPTION_ITERATIONS) {
      throw this.#badRequest(`encrypted transfer iterations must equal ${EXPORT_ENCRYPTION_ITERATIONS}`);
    }
    for (const field of ['salt', 'iv', 'authTag']) {
      if (!envelope.encryption[field] || typeof envelope.encryption[field] !== 'string') {
        throw this.#badRequest(`encrypted transfer requires encryption.${field}`);
      }
    }
    if (!envelope.ciphertext || typeof envelope.ciphertext !== 'string') {
      throw this.#badRequest('encrypted transfer requires ciphertext');
    }
    const declaredCount = envelope.metadata?.credentialCount;
    if (declaredCount !== undefined && (!Number.isInteger(declaredCount) || declaredCount < 0)) {
      throw this.#atomicityError('IMPORT_RECORD_COUNT_INVALID', 'Credential import record count is invalid', 400);
    }
    if (declaredCount > MAX_IMPORT_RECORDS) {
      throw this.#atomicityError('IMPORT_RECORD_COUNT_EXCEEDED', `Credential import supports at most ${MAX_IMPORT_RECORDS} records`, 413);
    }
  }

  #deriveTransferKey(password, salt, iterations, digest, { admitImport = false } = {}) {
    const work = () => new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, EXPORT_ENCRYPTION_KEY_LENGTH, digest, (error, key) => {
        if (error) reject(error);
        else resolve(key);
      });
    });

    if (!admitImport) return work();
    if (this.activeImportKdf >= MAX_CONCURRENT_IMPORT_KDF) {
      throw this.#atomicityError('IMPORT_CAPACITY_EXHAUSTED', 'Credential import capacity is temporarily exhausted', 429);
    }

    this.activeImportKdf += 1;
    return work().finally(() => {
      this.activeImportKdf -= 1;
    });
  }

  #assertImportPayloadSize(input) {
    let bytes;
    try {
      bytes = Buffer.byteLength(typeof input === 'string' ? input : JSON.stringify(input ?? null), 'utf8');
    } catch {
      throw this.#badRequest('transfer payload must be serializable');
    }
    if (bytes > MAX_IMPORT_PAYLOAD_BYTES) {
      throw this.#atomicityError('IMPORT_PAYLOAD_TOO_LARGE', `Credential import payload exceeds ${MAX_IMPORT_PAYLOAD_BYTES} bytes`, 413);
    }
  }

  #normalizeImportArguments(optionsOrContext = {}, maybeContext = {}) {
    if (Object.hasOwn(optionsOrContext, 'password') || Object.hasOwn(optionsOrContext, 'encryptionPassword')) {
      return { importOptions: optionsOrContext, context: maybeContext };
    }
    return { importOptions: {}, context: optionsOrContext };
  }

  #parseJson(input) {
    try {
      return JSON.parse(input);
    } catch (error) {
      throw this.#badRequest('transfer payload must be valid JSON');
    }
  }

  #previewCredential(credential, existingCredentials) {
    const conflict = this.#findConflict(credential, existingCredentials);
    return {
      credentialId: credential.credentialId,
      providerKey: credential.providerKey,
      externalReference: credential.externalReference,
      displayName: credential.metadata?.displayName ?? null,
      action: conflict ? 'conflict' : 'create',
      conflict
    };
  }

  #findConflict(credential, existingCredentials) {
    const byId = existingCredentials.find((existing) => existing.credentialId === credential.credentialId);
    if (byId) {
      return { type: 'credentialId', targetCredentialId: byId.credentialId, expectedVersion: byId.version };
    }

    if (!credential.externalReference) {
      return null;
    }

    const byIdentity = existingCredentials.find((existing) =>
      existing.providerKey === credential.providerKey
      && existing.credentialMethodKey === credential.credentialMethodKey
      && existing.externalReference === credential.externalReference
    );

    if (!byIdentity) {
      return null;
    }

    return { type: 'providerExternalReference', targetCredentialId: byIdentity.credentialId, expectedVersion: byIdentity.version };
  }

  #renameCredential(credential, existingCredentials) {
    const imported = credential.toJSON();
    const credentialId = this.idGenerator();
    const stamp = this.#timestamp().replaceAll(':', '-').replaceAll('.', '-');
    const metadata = {
      ...imported.metadata,
      displayName: imported.metadata?.displayName
        ? `${imported.metadata.displayName} (imported)`
        : null
    };

    let externalReference = imported.externalReference;
    if (externalReference && existingCredentials.some((existing) =>
      existing.providerKey === imported.providerKey
      && existing.credentialMethodKey === imported.credentialMethodKey
      && existing.externalReference === externalReference
    )) {
      externalReference = `${externalReference}-imported-${stamp}`;
    }

    const { credentialKey: _credentialKey, credentialGeneration: _credentialGeneration, ...renamed } = imported;
    return Credential.from({
      ...renamed,
      credentialId,
      externalReference,
      metadata,
      createdAt: this.#timestamp(),
      updatedAt: this.#timestamp(),
      version: 1
    });
  }

  #summarizePreview(items) {
    return {
      total: items.length,
      create: items.filter((item) => item.action === 'create').length,
      conflicts: items.filter((item) => item.action === 'conflict').length
    };
  }

  #normalizeConflictStrategy(value) {
    const strategy = String(value ?? '').trim().toLowerCase();
    if (!CONFLICT_STRATEGIES.includes(strategy)) {
      throw this.#badRequest(`conflictStrategy must be one of: ${CONFLICT_STRATEGIES.join(', ')}`);
    }
    return strategy;
  }

  #timestamp() {
    const value = this.clock();
    const date = value instanceof Date ? value : new Date(value);
    return date.toISOString();
  }

  #filename(generatedAt, encrypted = false) {
    const stamp = generatedAt.replaceAll(':', '-').replaceAll('.', '-');
    return `credential-hub-credentials-${stamp}${encrypted ? '.encrypted' : ''}.json`;
  }

  async #recordAudit({ action, targetId, result, context = {}, details = {} }) {
    if (!this.auditLogService?.record) return;
    await this.auditLogService.record({
      userId: context.userId ?? 'system',
      roleKey: context.roleKey ?? null,
      action,
      targetType: 'credential-transfer',
      targetId,
      result,
      details
    });
  }

  #badRequest(message) {
    const error = new Error(message);
    error.statusCode = 400;
    error.code = 'BAD_REQUEST';
    return error;
  }

  #notFound(message) {
    const error = new Error(message);
    error.statusCode = 404;
    error.code = 'NOT_FOUND';
    return error;
  }

  #atomicityError(code, message, statusCode) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    return error;
  }
}
