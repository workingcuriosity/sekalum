import { Credential } from '../models/credential.js';
import { CredentialSecretVersion } from '../models/credential-secret-version.js';
import { SerializedMutationQueue } from '../storage/serialized-mutation-queue.js';
import { RestoreAdmissionService } from './restore-admission-service.js';
import { RestoreCommitCoordinator } from '../storage/restore-commit-coordinator.js';

export const SECRET_VERSION_RETENTION_MS = 24 * 60 * 60 * 1000;
export const MAX_VERSIONS_PER_CREDENTIAL = 128;
export const MAX_HISTORY_BYTES_PER_CREDENTIAL = 4 * 1024 * 1024;
const SECRET_VERSION_HISTORY_LIMIT_EXCEEDED = 'SECRET_VERSION_HISTORY_LIMIT_EXCEEDED';
const SECRET_VERSION_STATE_INVALID = 'SECRET_VERSION_STATE_INVALID';

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export class CredentialSecretVersionService {
  constructor({
    store = null,
    credentialManager = null,
    credentialManagerRef = null,
    auditLogService = null,
    restoreAdmissionService = null,
    restoreCommitCoordinator = null,
    clock = () => new Date()
  } = {}) {
    this.store = store;
    this.credentialManager = credentialManager;
    this.credentialManagerRef = credentialManagerRef;
    this.auditLogService = auditLogService;
    this.restoreAdmissionService = restoreAdmissionService ?? new RestoreAdmissionService();
    this.restoreCommitCoordinator = restoreCommitCoordinator ?? new RestoreCommitCoordinator();
    this.clock = clock;
    this.records = [];
    this.highWatermarks = new Map();
    this.mutationQueue = new SerializedMutationQueue();
  }

  async recordCredentialVersion(credentialInput, { reason = 'manual-update', createdBy = 'system', metadata = {} } = {}) {
    return this.mutationQueue.run(() => this.#recordCredentialVersion(credentialInput, { reason, createdBy, metadata }));
  }

  async recordCredentialVersionsAtomically(entries = [], { onCommitted = null } = {}) {
    if (!Array.isArray(entries)) {
      throw new Error('CredentialSecretVersionService.recordCredentialVersionsAtomically() requires an array');
    }

    return this.mutationQueue.run(async () => {
      const originalState = await this.#loadState();
      const now = this.#now();
      const retainedVersions = this.#boundHistory(this.#pruneVersions(originalState.versions, now), originalState.highWatermarks);
      const highWatermarks = new Map(originalState.highWatermarks);
      const rollbackVersions = retainedVersions.map((record) => ({ ...record, secrets: record.secrets.map((secret) => ({ ...secret })) }));
      const rollbackHighWatermarks = new Map(highWatermarks);
      const records = [];

      for (const entry of entries) {
        const credential = Credential.from(entry.credential);
        const nextVersion = this.#nextVersion(highWatermarks, retainedVersions, credential.credentialId);
        const record = new CredentialSecretVersion({
          credentialId: credential.credentialId,
          version: nextVersion,
          secrets: credential.secrets.map((secret) => secret.toJSON()),
          reason: entry.reason ?? 'credential-import',
          createdAt: now,
          createdBy: entry.createdBy ?? 'system',
          metadata: {
            providerKey: credential.providerKey,
            credentialVersion: credential.version,
            credentialGeneration: credential.credentialGeneration,
            ...(entry.metadata ?? {})
          }
        });
        retainedVersions.push(record.toJSON());
        highWatermarks.set(credential.credentialId, nextVersion);
        records.push(record);
      }

      const boundedVersions = this.#boundHistory(retainedVersions, highWatermarks);
      if (records.length > 0 || originalState.needsPersist || boundedVersions.length !== originalState.versions.length) {
        await this.#saveState(boundedVersions, highWatermarks);
      }

      try {
        const callbackResult = await onCommitted?.({ records: [...records] });
        return { records, callbackResult };
      } catch (error) {
        if (records.length > 0) await this.#saveState(rollbackVersions, rollbackHighWatermarks);
        throw error;
      }
    });
  }

  async #recordCredentialVersion(credentialInput, { reason = 'manual-update', createdBy = 'system', metadata = {} } = {}) {
    const credential = Credential.from(credentialInput);
    const now = this.#now();
    const state = await this.#loadState();
    const retainedVersions = this.#boundHistory(this.#pruneVersions(state.versions, now), state.highWatermarks);
    const highWatermarks = new Map(state.highWatermarks);
    const nextVersion = this.#nextVersion(highWatermarks, retainedVersions, credential.credentialId);
    const record = new CredentialSecretVersion({
      credentialId: credential.credentialId,
      version: nextVersion,
      secrets: credential.secrets.map((secret) => secret.toJSON()),
      reason,
      createdAt: now,
      createdBy,
      metadata: {
        providerKey: credential.providerKey,
        credentialVersion: credential.version,
        credentialGeneration: credential.credentialGeneration,
        ...metadata
      }
    });

    retainedVersions.push(record.toJSON());
    highWatermarks.set(credential.credentialId, nextVersion);
    await this.#saveState(this.#boundHistory(retainedVersions, highWatermarks), highWatermarks);
    await this.#recordAudit('credential-secret-version.created', credential.credentialId, 'success', {
      version: record.version,
      reason: record.reason,
      providerKey: credential.providerKey
    });

    return record;
  }

  async listCredentialVersions(credentialId) {
    this.#assertCredentialId(credentialId, 'listCredentialVersions');
    return this.mutationQueue.run(async () => {
      const versions = await this.#loadRetainedVersions();
      return versions
      .filter((record) => record.credentialId === credentialId)
      .sort((left, right) => right.version - left.version)
      .map((record) => CredentialSecretVersion.from(record));
    });
  }

  async getCredentialVersion(credentialId, version) {
    this.#assertCredentialId(credentialId, 'getCredentialVersion');
    const normalizedVersion = this.#normalizeVersion(version);
    return this.mutationQueue.run(async () => {
      const versions = await this.#loadRetainedVersions();
      const record = versions.find((item) => item.credentialId === credentialId && item.version === normalizedVersion);

      if (!record) throw this.#unavailableVersionError();

      return CredentialSecretVersion.from(record);
    });
  }

  async rollbackCredentialSecrets(credentialId, version, context = {}) {
    this.#assertCredentialId(credentialId, 'rollbackCredentialSecrets');
    return this.mutationQueue.run(() => this.#rollbackCredentialSecrets(credentialId, version, context));
  }

  async #rollbackCredentialSecrets(credentialId, version, context = {}) {
    const credentialManager = this.#credentialManager();
    const currentCredential = await credentialManager.getCredential(credentialId);

    if (!currentCredential || this.#isTerminalCredential(currentCredential)) {
      throw this.#unavailableVersionError();
    }

    const targetVersion = await this.#getRetainedVersion(credentialId, version);
    const preflight = this.restoreAdmissionService.preflightSecretVersionRollback({
      currentCredential,
      targetVersion
    });
    this.#assertSecretRollbackAdmission(preflight);

    const rolledBackCredential = await this.restoreCommitCoordinator.run(() => credentialManager.updateCredential(credentialId, {
        secrets: targetVersion.secrets.map((secret) => ({ ...secret })),
        metadata: {
          ...currentCredential.metadata.toJSON(),
          custom: {
            ...(currentCredential.metadata.toJSON().custom ?? {}),
            lastSecretRollbackAt: this.#timestamp(this.#now()),
            lastSecretRollbackVersion: targetVersion.version
          }
        }
      }, {
        versionReason: 'rollback',
        createdBy: context.userId ?? 'system',
        skipSecretVersionRecord: true,
        beforeCommit: ({ currentCredential: finalCredential }) => {
          const finalAdmission = this.restoreAdmissionService.revalidateSecretVersionRollback({
            preflight,
            currentCredential: finalCredential,
            targetVersion
          });
          this.#assertSecretRollbackAdmission(finalAdmission);
        }
      }));

    await this.#recordCredentialVersion(rolledBackCredential, {
      reason: 'rollback',
      createdBy: context.userId ?? 'system',
      metadata: { restoredFromVersion: targetVersion.version }
    });
    await this.#recordAudit('credential-secret-version.rolled-back', credentialId, 'success', {
      restoredFromVersion: targetVersion.version
    });

    return rolledBackCredential;
  }

  async invalidateHistoryForCredential(credentialId, { reason = 'terminal-lifecycle' } = {}) {
    this.#assertCredentialId(credentialId, 'invalidateHistoryForCredential');
    return this.mutationQueue.run(async () => {
      const state = await this.#loadState();
      const now = this.#timestamp(this.#now());
      let invalidated = 0;
      let changed = false;
      const updated = state.versions.map((record) => {
        if (record.credentialId !== credentialId) return record;
        if (record.invalidatedAt && (!Array.isArray(record.secrets) || record.secrets.length === 0)) return record;
        invalidated += 1;
        changed = true;
        return this.#invalidatedRecord(record, now, reason);
      });

      const bounded = this.#boundHistory(this.#pruneVersions(updated, this.#now()), state.highWatermarks);
      if (changed || state.needsPersist || bounded.length !== state.versions.length) await this.#saveState(bounded, state.highWatermarks);
      return { credentialId, invalidated };
    });
  }

  #credentialManager() {
    const manager = this.credentialManager ?? this.credentialManagerRef?.();

    if (!manager?.getCredential || !manager?.updateCredential) {
      throw new Error('CredentialSecretVersionService.rollbackCredentialSecrets() requires credentialManager');
    }

    return manager;
  }

  #normalizePersistedRecord(record) {
    if (!record || typeof record !== 'object' || Array.isArray(record)
      || typeof record.credentialId !== 'string' || record.credentialId.trim() === ''
      || !Number.isSafeInteger(record.version) || record.version < 1
      || !Array.isArray(record.secrets)) throw this.#stateError();
    if (record.secrets.some((secret) => !secret || typeof secret !== 'object' || Array.isArray(secret))) throw this.#stateError();
    return {
      ...record,
      secrets: record.secrets.map((secret) => ({ ...secret }))
    };
  }

  #normalizeHighWatermarks(value) {
    if (value === undefined) return new Map();
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw this.#stateError();
    const highWatermarks = new Map();
    for (const [credentialId, version] of Object.entries(value)) {
      if (!credentialId || !Number.isSafeInteger(version) || version < 0) throw this.#stateError();
      highWatermarks.set(credentialId, version);
    }
    return highWatermarks;
  }

  #observedHighWatermarks(versions) {
    const observed = new Map();
    for (const record of versions) {
      observed.set(record.credentialId, Math.max(observed.get(record.credentialId) ?? 0, record.version));
    }
    return observed;
  }

  #stateError() {
    const error = new Error(SECRET_VERSION_STATE_INVALID);
    error.code = SECRET_VERSION_STATE_INVALID;
    return error;
  }

  #historyLimitError() {
    const error = new Error(SECRET_VERSION_HISTORY_LIMIT_EXCEEDED);
    error.code = SECRET_VERSION_HISTORY_LIMIT_EXCEEDED;
    return error;
  }

  async #loadState() {
    if (!this.store?.load) {
      const versions = this.records.map((record) => ({ ...record, secrets: record.secrets.map((secret) => ({ ...secret })) }));
      const highWatermarks = new Map(this.highWatermarks);
      const observed = this.#observedHighWatermarks(versions);
      let needsPersist = false;
      for (const [credentialId, version] of observed) {
        if ((highWatermarks.get(credentialId) ?? 0) < version) {
          highWatermarks.set(credentialId, version);
          needsPersist = true;
        }
      }
      return { versions, highWatermarks, needsPersist };
    }

    try {
      const data = await this.store.load();
      if (data === null || typeof data !== 'object' || Array.isArray(data)) throw this.#stateError();
      if (data.versions !== undefined && !Array.isArray(data.versions)) throw this.#stateError();
      const versions = (data.versions ?? []).map((record) => this.#normalizePersistedRecord(record));
      const highWatermarks = this.#normalizeHighWatermarks(data.secretVersionHighWatermarks);
      const observed = this.#observedHighWatermarks(versions);
      let needsPersist = data.secretVersionHighWatermarks === undefined;
      for (const [credentialId, version] of observed) {
        if ((highWatermarks.get(credentialId) ?? 0) < version) {
          highWatermarks.set(credentialId, version);
          needsPersist = true;
        }
      }
      return { versions, highWatermarks, needsPersist };
    } catch (error) {
      if (error?.code === 'ENOENT') return { versions: [], highWatermarks: new Map(), needsPersist: false };
      throw error;
    }
  }

  async #loadRetainedVersions() {
    const state = await this.#loadState();
    const now = this.#now();
    const prunedVersions = this.#pruneVersions(state.versions, now);
    const retainedVersions = this.#boundHistory(prunedVersions, state.highWatermarks);
    if (state.needsPersist || JSON.stringify(retainedVersions) !== JSON.stringify(state.versions)) {
      await this.#saveState(retainedVersions, state.highWatermarks);
    }
    return retainedVersions.filter((record) => this.#isAvailable(record, now));
  }

  async #getRetainedVersion(credentialId, version) {
    const normalizedVersion = this.#normalizeVersion(version);
    const versions = await this.#loadRetainedVersions();
    const record = versions.find((item) => item.credentialId === credentialId && item.version === normalizedVersion);
    if (!record) throw this.#unavailableVersionError();
    return CredentialSecretVersion.from(record);
  }

  #pruneVersions(versions, now) {
    const timestamp = this.#timestamp(now);
    return versions.map((record) => {
      if (this.#isAvailable(record, now)) return record;
      if (record.invalidatedAt && (!Array.isArray(record.secrets) || record.secrets.length === 0)) return record;
      return this.#invalidatedRecord(record, timestamp, this.#invalidationReason(record));
    });
  }

  #boundHistory(versions, highWatermarks) {
    const byCredential = new Map();
    for (const record of versions) {
      const bucket = byCredential.get(record.credentialId) ?? [];
      bucket.push(record);
      byCredential.set(record.credentialId, bucket);
    }

    const bounded = [];
    for (const [credentialId, records] of byCredential) {
      const newest = [...records].sort((left, right) => {
        if (right.version !== left.version) return right.version - left.version;
        return String(right.versionId ?? '').localeCompare(String(left.versionId ?? ''));
      }).slice(0, MAX_VERSIONS_PER_CREDENTIAL);
      const selected = [];
      for (const record of newest) {
        const candidate = [...selected, record];
        if (this.#historyBytes(candidate) > MAX_HISTORY_BYTES_PER_CREDENTIAL) {
          if (selected.length === 0) throw this.#historyLimitError();
          continue;
        }
        selected.push(record);
      }
      const observed = records.reduce((highest, record) => Math.max(highest, record.version), 0);
      highWatermarks.set(credentialId, Math.max(highWatermarks.get(credentialId) ?? 0, observed));
      bounded.push(...selected);
    }

    return bounded.sort((left, right) => {
      if (left.credentialId !== right.credentialId) return left.credentialId.localeCompare(right.credentialId);
      return left.version - right.version;
    });
  }

  #historyBytes(records) {
    return Buffer.byteLength(canonicalJson(records), 'utf8');
  }

  #isAvailable(record, now) {
    if (record.invalidatedAt) return false;
    const createdAt = new Date(record.createdAt);
    if (Number.isNaN(createdAt.getTime())) return false;
    return now.getTime() < createdAt.getTime() + SECRET_VERSION_RETENTION_MS;
  }

  #invalidatedRecord(record, invalidatedAt, reason) {
    return {
      ...record,
      secrets: [],
      invalidatedAt,
      invalidationReason: reason
    };
  }

  #invalidationReason(record) {
    const createdAt = new Date(record.createdAt);
    return Number.isNaN(createdAt.getTime()) ? 'invalid-created-at' : 'retention-expired';
  }

  async #saveState(versions, highWatermarks) {
    const records = versions.map((record) => ({ ...record, secrets: record.secrets.map((secret) => ({ ...secret })) }));
    const persistedHighWatermarks = Object.fromEntries([...highWatermarks.entries()].sort(([left], [right]) => left.localeCompare(right)));

    if (!this.store?.save) {
      this.records = records;
      this.highWatermarks = new Map(highWatermarks);
      return;
    }

    await this.store.save({ versions: records, secretVersionHighWatermarks: persistedHighWatermarks });
    this.highWatermarks = new Map(highWatermarks);
  }

  #nextVersion(highWatermarks, versions, credentialId) {
    const observed = versions
      .filter((record) => record.credentialId === credentialId)
      .reduce((highest, record) => Math.max(highest, record.version ?? 0), 0);
    const current = Math.max(highWatermarks.get(credentialId) ?? 0, observed);
    if (current >= Number.MAX_SAFE_INTEGER) throw this.#stateError();
    return current + 1;
  }

  #now() {
    const value = this.clock();
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) throw new Error('CredentialSecretVersionService clock must return a valid date');
    return date;
  }

  #isTerminalCredential(credential) {
    return credential.lifecycleState === 'revoked' || credential.lifecycleState === 'deleted';
  }

  #assertSecretRollbackAdmission(result) {
    if (result?.conflicts?.some((item) => item.code === 'RESTORE_TERMINAL_CONFLICT')) {
      throw this.#unavailableVersionError();
    }
    this.restoreAdmissionService.assertCommitAllowed(result);
  }

  #unavailableVersionError() {
    const error = new Error('Requested Secret version is not available');
    error.code = 'SECRET_VERSION_UNAVAILABLE';
    return error;
  }

  async #recordAudit(action, credentialId, result, details) {
    if (!this.auditLogService?.record) return;

    await this.auditLogService.record({
      action,
      targetType: 'credential',
      targetId: credentialId,
      result,
      details
    });
  }

  #assertCredentialId(credentialId, operation) {
    if (!credentialId) {
      throw new Error(`CredentialSecretVersionService.${operation}() requires credentialId`);
    }
  }

  #normalizeVersion(version) {
    const normalized = Number(version);
    if (!Number.isInteger(normalized) || normalized < 1) {
      throw new Error('Secret version must be a positive integer');
    }
    return normalized;
  }

  #timestamp(value) {
    const date = value instanceof Date ? value : new Date(value);
    return date.toISOString();
  }
}
