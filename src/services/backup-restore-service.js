import { safeError } from '../utils/safe-diagnostics.js';
import { RestoreAdmissionService } from './restore-admission-service.js';
import { RestoreCommitCoordinator } from '../storage/restore-commit-coordinator.js';

const BACKUP_SCHEMA_VERSION = 1;

export class BackupRestoreService {
  constructor({ accessManagementService, auditLogService, managementService, store = null, clock = () => new Date(), restoreAdmissionService = null, restoreCommitCoordinator = null } = {}) {
    if (!accessManagementService) {
      throw new Error('BackupRestoreService requires AccessManagementService');
    }
    if (!auditLogService) {
      throw new Error('BackupRestoreService requires AuditLogService');
    }

    this.accessManagementService = accessManagementService;
    this.auditLogService = auditLogService;
    this.managementService = managementService;
    this.store = store;
    this.clock = clock;
    this.restoreAdmissionService = restoreAdmissionService ?? new RestoreAdmissionService({
      accessManagementService,
      auditLogService,
      clock
    });
    this.restoreCommitCoordinator = restoreCommitCoordinator ?? new RestoreCommitCoordinator();
    this.backups = [];
  }

  async createBackup(options = {}) {
    const generatedAt = this.#timestamp();
    const accessState = this.accessManagementService.getRestoreState
      ? await this.accessManagementService.getRestoreState()
      : { users: await this.accessManagementService.listUsers(), roles: await this.accessManagementService.listRoles() };
    const backup = {
      backupId: options.backupId ?? this.#createBackupId(generatedAt),
      schemaVersion: BACKUP_SCHEMA_VERSION,
      generatedAt,
      source: 'credential-hub-management',
      contents: ['users', 'roles', 'audit-log', 'management-status'],
      data: {
        users: accessState.users,
        roles: accessState.roles,
        auditLog: await this.auditLogService.list(),
        status: this.managementService?.getStatus ? await this.managementService.getStatus() : null
      }
    };

    await this.#saveBackup(backup);
    await this.#audit({
      action: 'backup.created',
      targetId: backup.backupId,
      result: 'success',
      actorUserId: options.actorUserId,
      details: { contents: backup.contents, schemaVersion: backup.schemaVersion }
    });

    return this.#backupItem(backup);
  }

  async listBackups() {
    const backups = await this.#loadBackups();
    return backups
      .map((backup) => this.#backupItem(backup))
      .sort((left, right) => right.generatedAt.localeCompare(left.generatedAt));
  }

  async getBackup(backupId) {
    const backup = await this.#loadBackup(this.#normalizeBackupId(backupId));
    return this.#clone(backup);
  }

  async previewRestore(backupId, options = {}) {
    const normalizedBackupId = this.#normalizeBackupId(backupId);
    const backup = await this.#loadBackup(normalizedBackupId);
    this.#assertRestorableBackup(backup);
    return this.restoreAdmissionService.preflightManagementBackup({
      backup,
      actorUserId: options.actorUserId ?? null
    });
  }

  async restoreBackup(backupId, options = {}) {
    const normalizedBackupId = this.#normalizeBackupId(backupId);

    try {
      const backup = await this.#loadBackup(normalizedBackupId);
      this.#assertRestorableBackup(backup);

      if (typeof this.accessManagementService.replaceUsers !== 'function') {
        throw new Error('BackupRestoreService requires AccessManagementService.replaceUsers()');
      }
      if (typeof this.auditLogService.replaceEntries !== 'function') {
        throw new Error('BackupRestoreService requires AuditLogService.replaceEntries()');
      }

      const preflight = await this.restoreAdmissionService.preflightManagementBackup({
        backup,
        actorUserId: options.actorUserId ?? null
      });
      const allowExplicitAdminResolution = options.allowNonTerminalResolution !== false;
      this.restoreAdmissionService.assertCommitAllowed(preflight, { allowExplicitAdminResolution });

      if (typeof this.accessManagementService.getRestoreSnapshot !== 'function'
        || typeof this.accessManagementService.restoreSnapshot !== 'function'
        || typeof this.auditLogService.getRestoreSnapshot !== 'function'
        || typeof this.auditLogService.restoreSnapshot !== 'function') {
        throw this.#atomicityError('RESTORE_ATOMICITY_UNSUPPORTED', 'Management restore requires snapshot-capable authority stores', 501);
      }

      const [accessSnapshot, auditSnapshot] = await Promise.all([
        this.accessManagementService.getRestoreSnapshot(),
        this.auditLogService.getRestoreSnapshot()
      ]);

      return await this.restoreCommitCoordinator.run(async () => {
        let auditPublished = false;
        let accessPublished = false;
        try {
          const finalAdmission = await this.restoreAdmissionService.revalidateManagementBackup({
            backup,
            preflight,
            actorUserId: options.actorUserId ?? null
          });
          this.restoreAdmissionService.assertCommitAllowed(finalAdmission, { allowExplicitAdminResolution });

          const restoredAuditEntries = await this.auditLogService.replaceEntries(backup.data.auditLog);
          auditPublished = true;
          await this.accessManagementService.replaceUsers(backup.data.users, {
            skipAudit: true,
            skipTokenRevocation: true,
            actorUserId: options.actorUserId
          });
          accessPublished = true;
          await this.#audit({
            action: 'backup.restored',
            targetId: normalizedBackupId,
            result: 'success',
            actorUserId: options.actorUserId,
            details: {
              schemaVersion: backup.schemaVersion,
              candidateDigest: finalAdmission.candidateDigest,
              stateDigest: finalAdmission.stateDigest
            }
          });
          auditPublished = true;

          return {
            backupId: normalizedBackupId,
            restoredAt: this.#timestamp(),
            decision: finalAdmission.decision,
            candidateDigest: finalAdmission.candidateDigest,
            stateDigest: finalAdmission.stateDigest,
            restored: {
              users: backup.data.users.length,
              auditLog: restoredAuditEntries.length
            }
          };
        } catch (error) {
          if (auditPublished || accessPublished) {
            try {
              if (accessPublished) await this.accessManagementService.restoreSnapshot(accessSnapshot);
              if (auditPublished) await this.auditLogService.restoreSnapshot(auditSnapshot);
            } catch (rollbackError) {
              throw this.#atomicityError('RESTORE_ATOMICITY_FAILED', 'Management restore could not safely retain the previous authority state', 500, {
                causeCode: rollbackError?.code ?? 'RESTORE_ROLLBACK_FAILED'
              });
            }
          }
          throw error;
        }
      });
    } catch (error) {
      try {
        await this.#audit({
          action: 'backup.restored',
          targetId: normalizedBackupId,
          result: 'failure',
          actorUserId: options.actorUserId,
          details: { error: safeError(error) }
        });
      } catch {
        // The original restore failure remains authoritative when audit storage
        // is unavailable; a failure record must never mask it.
      }
      throw error;
    }
  }

  async #loadBackups() {
    if (!this.store?.list || !this.store?.load) {
      return this.backups.map((backup) => this.#clone(backup));
    }

    const backupIds = await this.store.list();
    const backups = [];
    for (const backupId of backupIds) {
      backups.push(await this.store.load(backupId));
    }
    return backups;
  }

  async #loadBackup(backupId) {
    if (!this.store?.load) {
      const backup = this.backups.find((item) => item.backupId === backupId);
      if (!backup) {
        throw this.#notFound(`Backup '${backupId}' not found`);
      }
      return this.#clone(backup);
    }

    try {
      return await this.store.load(backupId);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        throw this.#notFound(`Backup '${backupId}' not found`);
      }
      throw error;
    }
  }

  async #saveBackup(backup) {
    if (!this.store?.save) {
      this.backups = this.backups.filter((item) => item.backupId !== backup.backupId);
      this.backups.push(this.#clone(backup));
      return;
    }

    await this.store.save(backup);
  }

  #assertRestorableBackup(backup) {
    if (backup?.schemaVersion !== BACKUP_SCHEMA_VERSION) {
      throw this.#badRequest(`Unsupported backup schema version '${backup?.schemaVersion}'`);
    }
    if (!Array.isArray(backup?.data?.users) || !Array.isArray(backup?.data?.auditLog)) {
      throw this.#badRequest('Backup is missing restorable management data');
    }
  }

  async #audit({ action, targetId, result, actorUserId = null, details = null }) {
    if (!this.auditLogService?.record) {
      return;
    }

    await this.auditLogService.record({
      userId: actorUserId ?? null,
      action,
      targetType: 'backup',
      targetId,
      result,
      details
    });
  }

  #backupItem(backup) {
    return {
      backupId: backup.backupId,
      schemaVersion: backup.schemaVersion,
      generatedAt: backup.generatedAt,
      source: backup.source,
      contents: [...backup.contents],
      counts: {
        users: backup.data?.users?.length ?? 0,
        roles: backup.data?.roles?.length ?? 0,
        auditLog: backup.data?.auditLog?.length ?? 0
      }
    };
  }

  #timestamp() {
    const value = this.clock();
    const date = value instanceof Date ? value : new Date(value);
    return date.toISOString();
  }

  #createBackupId(generatedAt) {
    return `management-${generatedAt.replaceAll(':', '-').replaceAll('.', '-')}`;
  }

  #normalizeBackupId(value) {
    if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
      throw this.#badRequest('backupId must be a non-empty string');
    }
    return value;
  }

  #clone(value) {
    return JSON.parse(JSON.stringify(value));
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

  #atomicityError(code, message, statusCode, details = {}) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    error.classification = 'HARD_SECURITY_BLOCK';
    error.details = details;
    return error;
  }
}
