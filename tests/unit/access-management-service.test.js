import test from 'node:test';
import assert from 'node:assert/strict';

import { AccessManagementService } from '../../src/services/access-management-service.js';

test('AccessManagementService exposes fixed MS12 roles', async () => {
  const service = new AccessManagementService();
  const roles = await service.listRoles();

  assert.deepEqual(roles.map((role) => role.roleKey), ['admin', 'operator', 'viewer']);
  assert.ok(roles.find((role) => role.roleKey === 'admin').permissions.includes('management:read'));
});

test('AccessManagementService creates and updates users with known roles', async () => {
  const service = new AccessManagementService();

  const created = await service.createUser({
    userId: 'user-1',
    displayName: 'Admin User',
    email: 'admin@example.test',
    roleKey: 'admin'
  });

  assert.equal(created.userId, 'user-1');
  assert.equal(created.status, 'active');

  const updated = await service.updateUser('user-1', {
    roleKey: 'viewer',
    status: 'disabled'
  });

  assert.equal(updated.roleKey, 'viewer');
  assert.equal(updated.status, 'disabled');

  const summary = await service.getSummary();
  assert.deepEqual(summary.users.byRole, { viewer: 1 });
  assert.deepEqual(summary.users.byStatus, { disabled: 1 });
});

test('AccessManagementService rejects unknown user roles', async () => {
  const service = new AccessManagementService();

  await assert.rejects(
    () => service.createUser({ userId: 'user-1', displayName: 'User', roleKey: 'owner' }),
    /Unknown role 'owner'/
  );
});

test('AccessManagementService persists users through injected store', async () => {
  const saved = [];
  const service = new AccessManagementService({
    store: {
      async load() { return saved.at(-1) ?? { users: [] }; },
      async save(data) { saved.push(data); }
    }
  });

  await service.createUser({ userId: 'operator-1', displayName: 'Operator', roleKey: 'operator' });
  const users = await service.listUsers();

  assert.equal(saved.length, 1);
  assert.equal(users.length, 1);
  assert.equal(users[0].roleKey, 'operator');
});

test('AccessManagementService resolves permissions for active users', async () => {
  const service = new AccessManagementService();

  await service.createUser({ userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer' });

  assert.equal(await service.hasPermission('viewer-1', 'management:read'), true);
  assert.equal(await service.hasPermission('viewer-1', 'users:manage'), false);

  await assert.rejects(
    () => service.authorize('viewer-1', 'users:manage'),
    /missing permission 'users:manage'/
  );
});

test('AccessManagementService rejects disabled users during authorization', async () => {
  const service = new AccessManagementService();

  await service.createUser({ userId: 'operator-1', displayName: 'Operator', roleKey: 'operator', status: 'disabled' });

  await assert.rejects(
    () => service.authorize('operator-1', 'management:read'),
    /disabled/
  );
});

test('AccessManagementService writes audit entries for user changes', async () => {
  const entries = [];
  const service = new AccessManagementService({
    auditLogService: {
      async record(entry) { entries.push(entry); }
    }
  });

  await service.createUser({ userId: 'user-1', displayName: 'User', roleKey: 'viewer', actorUserId: 'admin-1' });
  await service.updateUser('user-1', { status: 'disabled', actorUserId: 'admin-1' });
  await service.deleteUser('user-1', { actorUserId: 'admin-1' });

  assert.deepEqual(entries.map((entry) => entry.action), ['user.created', 'user.updated', 'user.deleted']);
  assert.deepEqual(entries.map((entry) => entry.targetId), ['user-1', 'user-1', 'user-1']);
  assert.equal(entries[0].userId, 'admin-1');
});
