import test from 'node:test';
import assert from 'node:assert/strict';

import { AuditLogService } from '../../src/services/audit-log-service.js';

test('AuditLogService records audit entries with required fields', async () => {
  const service = new AuditLogService({ clock: () => new Date('2026-07-08T09:30:00.000Z') });

  const entry = await service.record({
    userId: 'admin-1',
    roleKey: 'admin',
    action: 'user.created',
    targetType: 'user',
    targetId: 'viewer-1',
    result: 'success',
    details: { roleKey: 'viewer' }
  });

  assert.equal(entry.timestamp, '2026-07-08T09:30:00.000Z');
  assert.equal(entry.userId, 'admin-1');
  assert.equal(entry.action, 'user.created');
  assert.equal(entry.targetType, 'user');
  assert.equal(entry.targetId, 'viewer-1');
  assert.equal(entry.result, 'success');
  assert.deepEqual(entry.details, { roleKey: 'viewer' });
});

test('AuditLogService filters entries by user, action and result', async () => {
  const service = new AuditLogService();

  await service.record({ userId: 'admin-1', action: 'user.created', targetType: 'user', targetId: 'user-1', result: 'success' });
  await service.record({ userId: 'operator-1', action: 'scheduler.started', targetType: 'scheduler', result: 'failure' });

  const adminEntries = await service.list({ userId: 'admin-1' });
  assert.equal(adminEntries.length, 1);
  assert.equal(adminEntries[0].action, 'user.created');

  const failedEntries = await service.list({ result: 'failure', action: 'scheduler.started' });
  assert.equal(failedEntries.length, 1);
  assert.equal(failedEntries[0].userId, 'operator-1');
});

test('AuditLogService persists entries through injected store', async () => {
  const saved = [];
  const service = new AuditLogService({
    store: {
      async load() { return saved.at(-1) ?? { entries: [] }; },
      async save(data) { saved.push(data); }
    }
  });

  await service.record({ action: 'user.deleted', targetType: 'user', targetId: 'user-1', result: 'success' });
  const entries = await service.list();

  assert.equal(saved.length, 1);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].userId, 'system');
});
