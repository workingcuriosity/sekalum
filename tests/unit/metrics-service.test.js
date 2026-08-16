import test from 'node:test';
import assert from 'node:assert/strict';

import { MetricsService } from '../../src/services/metrics-service.js';

test('MetricsService aggregates management, access, audit, export and backup metrics', async () => {
  const service = new MetricsService({
    managementService: {
      async getStatus() {
        return {
          status: 'ok',
          credentials: {
            total: 3,
            byLifecycleState: { active: 2, expired: 1 },
            byProvider: { twitch: 2, google: 1 },
            items: [
              { credentialId: 'cred-1', expiresAt: '2026-07-10T00:00:00.000Z' },
              { credentialId: 'cred-2', expiresAt: '2026-07-20T00:00:00.000Z' },
              { credentialId: 'cred-3', expiresAt: '2026-07-01T00:00:00.000Z' }
            ]
          },
          providers: {
            total: 2,
            byCapability: { oauth: 2, refresh: 1 },
            items: [
              { providerKey: 'twitch', capabilities: ['oauth', 'refresh'] },
              { providerKey: 'google', capabilities: ['oauth'] }
            ]
          },
          scheduler: {
            available: true,
            started: true,
            running: false,
            jobCount: 1,
            runCount: 10,
            failureCount: 2,
            lastRunAt: '2026-07-08T09:00:00.000Z'
          }
        };
      }
    },
    accessManagementService: {
      async listUsers() { return [{ userId: 'admin', roleKey: 'admin', status: 'active' }]; },
      async listRoles() { return [{ roleKey: 'admin', permissions: ['metrics:read', 'users:manage'] }]; }
    },
    auditLogService: {
      async list() {
        return [
          { entryId: 'a1', action: 'user.created', result: 'success', createdAt: '2026-07-08T08:00:00.000Z' },
          { entryId: 'a2', action: 'backup.restored', result: 'failure', createdAt: '2026-07-08T09:00:00.000Z' }
        ];
      }
    },
    exportService: { async listResources() { return [{ resource: 'audit-log' }, { resource: 'users' }]; } },
    backupRestoreService: { async listBackups() { return [{ backupId: 'b1', generatedAt: '2026-07-08T07:00:00.000Z', counts: { users: 1, auditLog: 2 } }]; } },
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const metrics = await service.getMetrics();

  assert.equal(metrics.generatedAt, '2026-07-08T10:00:00.000Z');
  assert.equal(metrics.summary.credentials, 3);
  assert.equal(metrics.summary.auditEntries, 2);
  assert.equal(metrics.scheduler.successCount, 8);
  assert.equal(metrics.scheduler.failureRate, 0.2);
  assert.equal(metrics.providers.averageCapabilitiesPerProvider, 1.5);
  assert.equal(metrics.credentials.expiringCredentials, 1);
  assert.equal(metrics.credentials.expiredCredentials, 1);
  assert.equal(metrics.accessManagement.users.byRole.admin, 1);
  assert.equal(metrics.auditLog.failure, 1);
  assert.equal(metrics.exports.resourceCount, 2);
  assert.equal(metrics.backups.totalUsersBackedUp, 1);
});

test('MetricsService returns zero rates when no scheduler or audit activity exists', async () => {
  const service = new MetricsService({
    managementService: {
      async getStatus() {
        return {
          status: 'empty',
          credentials: { total: 0, items: [] },
          providers: { total: 0, items: [] },
          scheduler: { available: true, runCount: 0, failureCount: 0, jobs: [] }
        };
      }
    },
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const metrics = await service.getMetrics();

  assert.equal(metrics.scheduler.successRate, 0);
  assert.equal(metrics.scheduler.failureRate, 0);
  assert.equal(metrics.auditLog.successRate, 0);
  assert.equal(metrics.providers.averageCapabilitiesPerProvider, 0);
});

test('MetricsService tolerates unavailable optional services', async () => {
  const service = new MetricsService({
    managementService: {
      async getStatus() {
        return {
          credentials: { total: 0, items: [] },
          providers: { total: 0, items: [] },
          scheduler: { available: false }
        };
      }
    }
  });

  const metrics = await service.getMetrics();

  assert.equal(metrics.summary.users, 0);
  assert.equal(metrics.summary.backups, 0);
  assert.equal(metrics.exports.available, true);
});

test('MetricsService requires ManagementService.getStatus', () => {
  assert.throws(() => new MetricsService({ managementService: {} }), /ManagementService.getStatus/);
});
