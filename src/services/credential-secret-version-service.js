import { Credential } from '../models/credential.js';
import { CredentialSecretVersion } from '../models/credential-secret-version.js';
import { SerializedMutationQueue } from '../storage/serialized-mutation-queue.js';

export const SECRET_VERSION_RETENTION_MS = 24 * 60 * 60 * 1000;

export class CredentialSecretVersionService {
  constructor({
    store = null,
    credentialManager = null,
    credentialManagerRef = null,
    auditLogService = null,
    clock = () => new Date()
  } = {}) {
    this.store = store;
    this.credentialManager = credentialManager;
    this.credentialManagerRef = credentialManagerRef;
    this.auditLogService = auditLogService;
    this.clock = clock;
    this.records = [];
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
      const versions = await this.#loadVersions();
      const retainedVersions = this.#pruneVersions(versions, this.#now());
      const records = [];

      for (const entry of entries) {
        const credential = Credential.from(entry.credential);
        const now = this.#now();
        const record = new CredentialSecretVersion({
          credentialId: credential.credentialId,
          version: this.#nextVersion(retainedVersions, credential.credentialId),
          secrets: credential.secrets.map((secret) => secret.toJSON()),
          reason: entry.reason ?? 'credential-import',
          createdAt: now,
          createdBy: entry.createdBy ?? 'system',
          metadata: {
            providerKey: credential.providerKey,
            credentialVersion: credential.version,
            ...(entry.metadata ?? {})
          }
        });
        retainedVersions.push(record.toJSON());
        records.push(record);
      }

      if (records.length > 0) await this.#saveVersions(retainedVersions);

      try {
        const callbackResult = await onCommitted?.({ records: [...records] });
        return { records, callbackResult };
      } catch (error) {
        if (records.length > 0) await this.#saveVersions(versions);
        throw error;
      }
    });
  }

  async #recordCredentialVersion(credentialInput, { reason = 'manual-update', createdBy = 'system', metadata = {} } = {}) {
    const credential = Credential.from(credentialInput);
    const now = this.#now();
    const versions = await this.#loadVersions();
    const retainedVersions = this.#pruneVersions(versions, now);
    const nextVersion = this.#nextVersion(retainedVersions, credential.credentialId);
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
        ...metadata
      }
    });

    retainedVersions.push(record.toJSON());
    await this.#saveVersions(retainedVersions);
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
    const rolledBackCredential = await credentialManager.updateCredential(credentialId, {
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
      skipSecretVersionRecord: true
    });

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
      const versions = await this.#loadVersions();
      const now = this.#timestamp(this.#now());
      let invalidated = 0;
      let changed = false;
      const updated = versions.map((record) => {
        if (record.credentialId !== credentialId) return record;
        if (record.invalidatedAt && (!Array.isArray(record.secrets) || record.secrets.length === 0)) return record;
        invalidated += 1;
        changed = true;
        return this.#invalidatedRecord(record, now, reason);
      });

      if (changed) await this.#saveVersions(updated);
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

  async #loadVersions() {
    if (!this.store?.load) {
      return this.records.map((record) => ({ ...record, secrets: record.secrets.map((secret) => ({ ...secret })) }));
    }

    try {
      const data = await this.store.load();
      return Array.isArray(data?.versions) ? data.versions.map((record) => ({
        ...record,
        secrets: Array.isArray(record?.secrets) ? record.secrets.map((secret) => ({ ...secret })) : []
      })) : [];
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw error;
    }
  }

  async #loadRetainedVersions() {
    const versions = await this.#loadVersions();
    const now = this.#now();
    const retainedVersions = this.#pruneVersions(versions, now);
    if (JSON.stringify(retainedVersions) !== JSON.stringify(versions)) {
      await this.#saveVersions(retainedVersions);
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

  async #saveVersions(versions) {
    const records = versions.map((record) => ({ ...record, secrets: record.secrets.map((secret) => ({ ...secret })) }));

    if (!this.store?.save) {
      this.records = records;
      return;
    }

    await this.store.save({ versions: records });
  }

  #nextVersion(versions, credentialId) {
    const current = versions
      .filter((record) => record.credentialId === credentialId)
      .reduce((highest, record) => Math.max(highest, record.version ?? 0), 0);
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
