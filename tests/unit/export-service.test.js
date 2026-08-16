import test from 'node:test';
import assert from 'node:assert/strict';

import { ExportService } from '../../src/services/export-service.js';

test('ExportService exports audit log entries as JSON payload', async () => {
  const service = new ExportService({
    managementService: { async getStatus() { return {}; } },
    auditLogService: {
      async list(filters) {
        assert.equal(filters.action, 'user.created');
        return [{ entryId: 'entry-1', action: 'user.created', result: 'success' }];
      }
    },
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const result = await service.export('audit-log', { format: 'json', filters: { action: 'user.created' } });
  const content = JSON.parse(result.content);

  assert.equal(result.resource, 'audit-log');
  assert.equal(result.format, 'json');
  assert.equal(result.contentType, 'application/json; charset=utf-8');
  assert.equal(content.generatedAt, '2026-07-08T10:00:00.000Z');
  assert.equal(content.data[0].entryId, 'entry-1');
});

test('ExportService exports users and roles through AccessManagementService', async () => {
  const service = new ExportService({
    managementService: { async getStatus() { return {}; } },
    accessManagementService: {
      async listUsers() { return [{ userId: 'admin-1', roleKey: 'admin' }]; },
      async listRoles() { return [{ roleKey: 'admin', permissions: ['export:read'] }]; }
    }
  });

  const users = await service.export('users');
  const roles = await service.export('roles');

  assert.equal(users.data[0].userId, 'admin-1');
  assert.equal(roles.data[0].roleKey, 'admin');
});

test('ExportService exports provider status as CSV', async () => {
  const service = new ExportService({
    managementService: {
      async getProviders() {
        return {
          total: 1,
          items: [{ providerKey: 'threads', capabilities: ['oauth', 'refresh'] }]
        };
      }
    }
  });

  const result = await service.export('providers', { format: 'csv' });

  assert.equal(result.contentType, 'text/csv; charset=utf-8');
  assert.match(result.content, /providerKey,capabilities/);
  assert.match(result.content, /threads,oauth\|refresh/);
});

test('ExportService rejects unsupported resources and formats', async () => {
  const service = new ExportService({ managementService: {} });

  await assert.rejects(() => service.export('unknown'), /resource must be one of/);
  await assert.rejects(() => service.export('users', { format: 'xml' }), /format must be json or csv/);
});
