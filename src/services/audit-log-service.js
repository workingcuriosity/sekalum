import { sanitizeDiagnostic } from '../utils/safe-diagnostics.js';
import { SerializedMutationQueue } from '../storage/serialized-mutation-queue.js';
import { applyAuditRetentionPolicy } from './audit-retention-policy.js';

const ACTOR_TYPES = Object.freeze(['user', 'consumer', 'api-token', 'service', 'legacy-ambiguous']);

export class AuditLogService {
  constructor({ store = null, clock = () => new Date(), logger = console } = {}) {
    this.store = store;
    this.clock = clock;
    this.logger = logger;
    this.entries = [];
    this.mutationQueue = new SerializedMutationQueue();
  }

  async record(input = {}) {
    return this.mutationQueue.run(() => this.#record(input));
  }

  async #record(input = {}) {
    const entry = this.#normalizeEntry(input);
    const entries = await this.#loadEntries();
    const records = await this.#saveEntries([...entries, entry]);
    if (!records.some((record) => record.entryId === entry.entryId && record.timestamp === entry.timestamp)) {
      throw this.#auditNotRetained();
    }
    return this.#entryItem(entry);
  }

  async list(filters = {}) {
    return this.mutationQueue.run(async () => {
      const entries = await this.#loadEntries({ persistBounded: true });
      return entries
        .filter((entry) => this.#matchesFilters(entry, filters))
        .sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp))
        .map((entry) => this.#entryItem(entry));
    });
  }

  async get(entryId) {
    return this.mutationQueue.run(async () => {
      const normalizedEntryId = this.#normalizeRequiredString(entryId, 'entryId');
      const entries = await this.#loadEntries({ persistBounded: true });
      const entry = entries.find((item) => item.entryId === normalizedEntryId);

      if (!entry) {
        throw this.#notFound(`Audit entry '${normalizedEntryId}' not found`);
      }

      return this.#entryItem(entry);
    });
  }


  async replaceEntries(entries = []) {
    return this.mutationQueue.run(() => this.#replaceEntries(entries));
  }

  async #replaceEntries(entries = []) {
    if (!Array.isArray(entries)) {
      throw this.#badRequest('entries must be an array');
    }

    const records = this.#normalizeStoredEntries(entries);
    const bounded = await this.#saveEntries(records);
    return bounded.map((entry) => this.#entryItem(entry));
  }

  async #loadEntries({ persistBounded = false } = {}) {
    let data;
    if (!this.store?.load) {
      data = { entries: this.entries };
    } else {
      try {
        data = await this.store.load();
      } catch (error) {
        if (error?.code === 'ENOENT') {
          data = { entries: [] };
        } else {
          throw error;
        }
      }
    }

    const malformedEnvelope = data !== null
      && data !== undefined
      && !Array.isArray(data?.entries);
    if (malformedEnvelope) {
      this.#warnMalformedLegacyEnvelope();
    }
    const rawEntries = Array.isArray(data?.entries) ? data.entries : [];
    const records = this.#normalizeStoredEntries(rawEntries);
    const bounded = applyAuditRetentionPolicy(records, { now: this.#clockDate() });
    const changed = malformedEnvelope
      || records.length !== rawEntries.length
      || bounded.dropped > 0
      || JSON.stringify(records) !== JSON.stringify(bounded.entries);

    if (persistBounded && changed) {
      await this.#saveEntries(bounded.entries);
    }

    return bounded.entries;
  }

  async #saveEntries(entries, { now = this.#clockDate() } = {}) {
    const bounded = applyAuditRetentionPolicy(entries, { now, onMalformed: () => this.#warnMalformedLegacyRecord() });
    const records = bounded.entries.map((entry) => ({ ...entry, details: this.#cloneDetails(entry.details) }));

    if (!this.store?.save) {
      this.entries = records;
      return records;
    }

    await this.store.save({ entries: records });
    return records;
  }

  #normalizeEntry(input) {
    const timestamp = this.#timestamp();
    const actor = this.#normalizeActorFields(input);

    return {
      entryId: input.entryId === undefined || input.entryId === null
        ? this.#createEntryId(timestamp)
        : this.#normalizeRequiredString(input.entryId, 'entryId'),
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
      timestamp: this.#normalizeStoredTimestamp(input.timestamp),
      ...this.#normalizeActorFields(actorInput),
      roleKey: this.#normalizeOptionalString(input.roleKey),
      action,
      targetType: this.#normalizeRequiredString(input.targetType, 'targetType'),
      targetId: this.#normalizeOptionalString(input.targetId),
      result: this.#normalizeResult(input.result),
      details
    };
  }

  #normalizeStoredEntries(entries) {
    const records = [];
    for (const entry of entries) {
      try {
        records.push(this.#normalizeStoredEntry(entry));
      } catch {
        this.#warnMalformedLegacyRecord();
      }
    }
    return records;
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
    if (filters.from && this.#filterTimestamp(entry.timestamp) < this.#filterTimestamp(filters.from)) {
      return false;
    }
    if (filters.to && this.#filterTimestamp(entry.timestamp) > this.#filterTimestamp(filters.to)) {
      return false;
    }
    return true;
  }

  #timestamp() {
    return this.#clockDate().toISOString();
  }

  #clockDate() {
    const value = this.clock();
    return value instanceof Date ? new Date(value.getTime()) : new Date(value);
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

  #normalizeStoredTimestamp(value) {
    const timestamp = this.#normalizeRequiredString(value, 'timestamp');
    if (!Number.isFinite(new Date(timestamp).getTime())) {
      throw this.#badRequest('timestamp must be a valid date');
    }
    return timestamp;
  }

  #filterTimestamp(value) {
    const timestamp = new Date(value).getTime();
    return Number.isFinite(timestamp) ? timestamp : Number.NaN;
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

  #auditNotRetained() {
    const error = new Error('Audit event was not retained under the active retention policy');
    error.statusCode = 500;
    error.code = 'AUDIT_EVENT_NOT_RETAINED';
    return error;
  }

  #warnMalformedLegacyRecord() {
    this.logger?.warn?.('Excluded malformed legacy audit record during retention convergence');
  }

  #warnMalformedLegacyEnvelope() {
    this.logger?.warn?.('Replaced malformed legacy audit envelope during retention convergence');
  }
}
