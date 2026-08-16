import test from 'node:test';
import assert from 'node:assert/strict';

import { BackupRestoreService } from '../../src/services/backup-restore-service.js';
import { AccessManagementService } from '../../src/services/access-management-service.js';
import { AuditLogService } from '../../src/services/audit-log-service.js';

test('BackupRestoreService creates management backup with users roles audit log and status', async () => {
  const auditLogService = new AuditLogService({ clock: () => new Date('2026-07-08T10:00:00.000Z') });
  const accessManagementService = new AccessManagementService({ auditLogService });
  await accessManagementService.createUser({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' });

  const service = new BackupRestoreService({
    accessManagementService,
    auditLogService,
    managementService: { async getStatus() { return { status: 'ok' }; } },
    clock: () => new Date('2026-07-08T11:00:00.000Z')
  });

  const backup = await service.createBackup({ actorUserId: 'admin-1' });
  const full = await service.getBackup(backup.backupId);

  assert.equal(backup.schemaVersion, 1);
  assert.equal(backup.counts.users, 1);
  assert.ok(backup.contents.includes('audit-log'));
  assert.equal(full.data.users[0].userId, 'admin-1');
  assert.equal(full.data.status.status, 'ok');
});

test('BackupRestoreService restores users and audit log from a backup', async () => {
  const auditLogService = new AuditLogService();
  const accessManagementService = new AccessManagementService({ auditLogService });
  await accessManagementService.createUser({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' });

  const service = new BackupRestoreService({
    accessManagementService,
    auditLogService,
    managementService: { async getStatus() { return {}; } }
  });

  const backup = await service.createBackup({ actorUserId: 'admin-1' });
  await accessManagementService.createUser({ userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer', actorUserId: 'admin-1' });

  const restored = await service.restoreBackup(backup.backupId, { actorUserId: 'admin-1' });
  const users = await accessManagementService.listUsers();
  const auditEntries = await auditLogService.list({ action: 'backup.restored' });

  assert.equal(restored.restored.users, 1);
  assert.deepEqual(users.map((user) => user.userId), ['admin-1']);
  assert.equal(auditEntries[0].result, 'success');
});

test('BackupRestoreService rejects unsupported backup schema versions', async () => {
  const service = new BackupRestoreService({
    accessManagementService: new AccessManagementService(),
    auditLogService: new AuditLogService(),
    store: {
      async save() {},
      async list() { return ['backup-1']; },
      async load() { return { backupId: 'backup-1', schemaVersion: 999, data: { users: [], auditLog: [] } }; }
    }
  });

  await assert.rejects(() => service.restoreBackup('backup-1'), /Unsupported backup schema version/);
});
