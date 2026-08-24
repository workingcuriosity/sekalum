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
  assert.equal(entry.actorType, 'user');
  assert.equal(entry.userId, 'admin-1');
  assert.equal(entry.consumerId, null);
  assert.equal(entry.apiTokenId, null);
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
  assert.equal(entries[0].actorType, 'service');
});

test('AuditLogService keeps consumer and API-token actors separate and filters each identity', async () => {
  const service = new AuditLogService();

  await service.record({
    actorType: 'consumer', consumerId: 'consumer-1', apiTokenId: 'token-1',
    action: 'consumer-credential.resolve', targetType: 'credential', targetId: 'credential-1'
  });
  await service.record({
    actorType: 'api-token', apiTokenId: 'token-1',
    action: 'api-token.used', targetType: 'api-token', targetId: 'token-1'
  });

  const consumer = await service.list({ consumerId: 'consumer-1', actorType: 'consumer' });
  assert.equal(consumer.length, 1);
  assert.equal(consumer[0].userId, null);
  assert.equal(consumer[0].apiTokenId, 'token-1');
  assert.equal((await service.list({ apiTokenId: 'token-1' })).length, 2);
});

test('AuditLogService makes legacy ambiguity explicit without inventing a user identity', async () => {
  const saved = [{ entries: [
    {
      entryId: 'legacy-consumer', timestamp: '2026-07-08T09:00:00.000Z', userId: 'consumer-1',
      action: 'consumer-credential.resolve', targetType: 'credential', targetId: 'credential-1',
      result: 'success', details: { consumerId: 'consumer-1' }
    },
    {
      entryId: 'legacy-unknown', timestamp: '2026-07-08T08:00:00.000Z', userId: 'operator-1',
      action: 'custom.action', targetType: 'system', targetId: null,
      result: 'success', details: null
    }
  ] }];
  const service = new AuditLogService({ store: {
    async load() { return saved[0]; },
    async save(data) { saved.push(data); }
  } });

  const entries = await service.list();
  assert.equal(entries[0].actorType, 'consumer');
  assert.equal(entries[0].userId, null);
  assert.equal(entries[0].consumerId, 'consumer-1');
  assert.equal(entries[0].legacyUserId, 'consumer-1');
  assert.equal(entries[1].actorType, 'legacy-ambiguous');
  assert.equal(entries[1].userId, null);
  assert.equal(entries[1].legacyUserId, 'operator-1');
  assert.equal((await service.list({ userId: 'operator-1' })).length, 1);
});
