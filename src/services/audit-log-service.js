import { sanitizeDiagnostic } from '../utils/safe-diagnostics.js';

const ACTOR_TYPES = Object.freeze(['user', 'consumer', 'api-token', 'service', 'legacy-ambiguous']);

export class AuditLogService {
  constructor({ store = null, clock = () => new Date() } = {}) {
    this.store = store;
    this.clock = clock;
    this.entries = [];
  }

  async record(input = {}) {
    const entry = this.#normalizeEntry(input);
    const entries = await this.#loadEntries();
    entries.push(entry);
    await this.#saveEntries(entries);
    return this.#entryItem(entry);
  }

  async list(filters = {}) {
    const entries = await this.#loadEntries();
    return entries
      .filter((entry) => this.#matchesFilters(entry, filters))
      .sort((left, right) => right.timestamp.localeCompare(left.timestamp))
      .map((entry) => this.#entryItem(entry));
  }

  async get(entryId) {
    const normalizedEntryId = this.#normalizeRequiredString(entryId, 'entryId');
    const entries = await this.#loadEntries();
    const entry = entries.find((item) => item.entryId === normalizedEntryId);

    if (!entry) {
      throw this.#notFound(`Audit entry '${normalizedEntryId}' not found`);
    }

    return this.#entryItem(entry);
  }


  async replaceEntries(entries = []) {
    if (!Array.isArray(entries)) {
      throw this.#badRequest('entries must be an array');
    }

    const records = entries.map((entry) => this.#normalizeStoredEntry(entry));

    await this.#saveEntries(records);
    return records.map((entry) => this.#entryItem(entry));
  }

  async #loadEntries() {
    if (!this.store?.load) {
      return this.entries.map((entry) => this.#normalizeStoredEntry(entry));
    }

    try {
      const data = await this.store.load();
      const entries = Array.isArray(data?.entries) ? data.entries : [];
      return entries.map((entry) => this.#normalizeStoredEntry(entry));
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  async #saveEntries(entries) {
    const records = entries.map((entry) => ({ ...entry, details: this.#cloneDetails(entry.details) }));

    if (!this.store?.save) {
      this.entries = records;
      return;
    }

    await this.store.save({ entries: records });
  }

  #normalizeEntry(input) {
    const timestamp = this.#timestamp();
    const actor = this.#normalizeActorFields(input);

    return {
      entryId: input.entryId ?? this.#createEntryId(timestamp),
      timestamp,
      ...actor,
      roleKey: this.#normalizeOptionalString(input.roleKey),
      action: this.#normalizeRequiredString(input.action, 'action'),
      targetType: this.#normalizeRequiredString(input.targetType, 'targetType'),
      targetId: this.#normalizeOptionalString(input.targetId),
      result: this.#normalizeResult(input.result ?? 'success'),
      details: this.#cloneDetails(input.details ?? null)
    };
  }

  #normalizeStoredEntry(input = {}) {
    const action = this.#normalizeRequiredString(input.action, 'action');
    const details = this.#cloneDetails(input.details ?? null);
    const hasCanonicalActor = Object.hasOwn(input, 'actorType')
      || Object.hasOwn(input, 'consumerId')
      || Object.hasOwn(input, 'apiTokenId');
    const actorInput = hasCanonicalActor
      ? input
      : this.#legacyActorInput({ ...input, action, details });

    return {
      entryId: this.#normalizeRequiredString(input.entryId, 'entryId'),
      timestamp: this.#normalizeRequiredString(input.timestamp, 'timestamp'),
      ...this.#normalizeActorFields(actorInput),
      roleKey: this.#normalizeOptionalString(input.roleKey),
      action,
      targetType: this.#normalizeRequiredString(input.targetType, 'targetType'),
      targetId: this.#normalizeOptionalString(input.targetId),
      result: this.#normalizeResult(input.result),
      details
    };
  }

  #legacyActorInput(input) {
    const legacyUserId = this.#normalizeOptionalString(input.userId);
    const legacyConsumerId = this.#normalizeOptionalString(input.details?.consumerId);

    if (input.action.startsWith('consumer-credential.') && legacyConsumerId) {
      return {
        ...input,
        actorType: 'consumer',
        userId: null,
        consumerId: legacyConsumerId,
        apiTokenId: null,
        ...(legacyUserId && legacyUserId !== 'system' ? { legacyUserId } : {})
      };
    }

    if (legacyUserId && legacyUserId !== 'system') {
      return {
        ...input,
        actorType: 'legacy-ambiguous',
        userId: null,
        consumerId: null,
        apiTokenId: null,
        legacyUserId
      };
    }

    return { ...input, actorType: 'service', userId: 'system', consumerId: null, apiTokenId: null };
  }

  #normalizeActorFields(input = {}) {
    const explicitActorType = this.#normalizeOptionalString(input.actorType);
    const consumerId = this.#normalizeOptionalString(input.consumerId);
    const apiTokenId = this.#normalizeOptionalString(input.apiTokenId);
    const legacyUserId = this.#normalizeOptionalString(input.legacyUserId);
    const actorType = explicitActorType
      ?? (consumerId ? 'consumer' : apiTokenId && !input.userId ? 'api-token' : this.#isSystemActor(input.userId) ? 'service' : 'user');

    if (!ACTOR_TYPES.includes(actorType)) {
      throw this.#badRequest(`actorType must be one of: ${ACTOR_TYPES.join(', ')}`);
    }

    const userId = ['consumer', 'api-token', 'legacy-ambiguous'].includes(actorType)
      ? null
      : this.#normalizeActor(input.userId);

    return { actorType, userId, consumerId, apiTokenId, legacyUserId };
  }

  #matchesFilters(entry, filters = {}) {
    if (filters.userId && entry.userId !== filters.userId) {
      if (entry.legacyUserId !== filters.userId) return false;
    }
    if (filters.consumerId && entry.consumerId !== filters.consumerId) {
      return false;
    }
    if (filters.apiTokenId && entry.apiTokenId !== filters.apiTokenId) {
      return false;
    }
    if (filters.actorType && entry.actorType !== filters.actorType) {
      return false;
    }
    if (filters.action && entry.action !== filters.action) {
      return false;
    }
    if (filters.targetType && entry.targetType !== filters.targetType) {
      return false;
    }
    if (filters.targetId && entry.targetId !== filters.targetId) {
      return false;
    }
    if (filters.result && entry.result !== filters.result) {
      return false;
    }
    if (filters.from && entry.timestamp < filters.from) {
      return false;
    }
    if (filters.to && entry.timestamp > filters.to) {
      return false;
    }
    return true;
  }

  #timestamp() {
    const value = this.clock();
    const date = value instanceof Date ? value : new Date(value);
    return date.toISOString();
  }

  #createEntryId(timestamp) {
    return `${timestamp}-${Math.random().toString(36).slice(2, 10)}`;
  }

  #entryItem(entry) {
    return {
      entryId: entry.entryId,
      timestamp: entry.timestamp,
      actorType: entry.actorType,
      userId: entry.userId,
      consumerId: entry.consumerId,
      apiTokenId: entry.apiTokenId,
      ...(entry.legacyUserId ? { legacyUserId: entry.legacyUserId } : {}),
      roleKey: entry.roleKey,
      action: entry.action,
      targetType: entry.targetType,
      targetId: entry.targetId,
      result: entry.result,
      details: this.#cloneDetails(entry.details)
    };
  }

  #normalizeActor(value) {
    if (typeof value !== 'string' || value.trim() === '') {
      return 'system';
    }
    return value.trim();
  }

  #isSystemActor(value) {
    return value === undefined || value === null || value === '' || value === 'system';
  }

  #normalizeRequiredString(value, name) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw this.#badRequest(`${name} must be a non-empty string`);
    }
    return value.trim();
  }

  #normalizeOptionalString(value) {
    if (value === undefined || value === null || value === '') {
      return null;
    }
    if (typeof value !== 'string') {
      throw this.#badRequest('optional audit values must be strings');
    }
    return value.trim();
  }

  #normalizeResult(value) {
    const result = this.#normalizeRequiredString(value, 'result');
    if (!['success', 'failure'].includes(result)) {
      throw this.#badRequest('result must be success or failure');
    }
    return result;
  }

  #cloneDetails(details) {
    if (details === null || details === undefined) {
      return null;
    }
    return sanitizeDiagnostic(details);
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
}
