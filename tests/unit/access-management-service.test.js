import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { AccessManagementService } from '../../src/services/access-management-service.js';

const VALID_BOOTSTRAP_SECRET = crypto.createHash('sha256')
  .update('access-management-bootstrap-test-fixture-v2')
  .digest('hex');

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

test('AccessManagementService serializes a current-principal operation with role revocation', async () => {
  const service = new AccessManagementService();
  await service.createUser({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' });
  const { principalGeneration } = await service.getUserIdentity('admin-1');
  let releaseCommit;
  let startedCommit;
  const commitStarted = new Promise((resolve) => { startedCommit = resolve; });
  let committed = false;

  const protectedCommit = service.withAuthorizedCurrentPrincipal(
    'admin-1',
    principalGeneration,
    'providers:manage',
    async () => {
      startedCommit();
      await new Promise((resolve) => { releaseCommit = resolve; });
      committed = true;
    }
  );
  await commitStarted;
  const revoke = service.updateUser('admin-1', { roleKey: 'viewer' });
  releaseCommit();
  await protectedCommit;
  await revoke;

  assert.equal(committed, true);
  await assert.rejects(
    () => service.authorizeCurrentPrincipal('admin-1', principalGeneration, 'providers:manage'),
    /missing permission 'providers:manage'/
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

test('AccessManagementService requires a strong bootstrap proof and creates an active administrator', async () => {
  const bootstrapSecret = VALID_BOOTSTRAP_SECRET;
  const entries = [];
  const service = new AccessManagementService({
    config: { get(key) { return key === 'ADMIN_BOOTSTRAP_TOKEN' ? bootstrapSecret : null; } },
    auditLogService: { async record(entry) { entries.push(entry); } }
  });

  await assert.rejects(
    () => service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin' }),
    { code: 'BOOTSTRAP_PROOF_INVALID' }
  );
  await assert.rejects(
    () => service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin', roleKey: 'operator' }, bootstrapSecret),
    { code: 'BAD_REQUEST' }
  );
  await assert.rejects(
    () => service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin', status: 'disabled' }, bootstrapSecret),
    { code: 'BAD_REQUEST' }
  );

  const created = await service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin' }, bootstrapSecret);
  assert.equal(created.roleKey, 'admin');
  assert.equal(created.status, 'active');
  assert.equal(entries[0].userId, null);
  assert.deepEqual(entries[0].details, { roleKey: 'admin', status: 'active', bootstrap: true });
  assert.doesNotMatch(JSON.stringify(entries), new RegExp(bootstrapSecret));

  await assert.rejects(
    () => service.bootstrapFirstAdministrator({ userId: 'admin-2', displayName: 'Second Admin' }, bootstrapSecret),
    { code: 'BOOTSTRAP_CLOSED' }
  );
});

test('AccessManagementService atomically permits exactly one concurrent bootstrap', async () => {
  const bootstrapSecret = VALID_BOOTSTRAP_SECRET;
  const service = new AccessManagementService({ bootstrapSecret });
  const results = await Promise.allSettled(Array.from({ length: 12 }, (_, index) => service.bootstrapFirstAdministrator({
    userId: `admin-${index}`,
    displayName: `Admin ${index}`
  }, bootstrapSecret)));

  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(results.filter((result) => result.status === 'rejected').length, 11);
  assert.deepEqual((await service.listUsers()).map((user) => user.roleKey), ['admin']);
});

test('AccessManagementService rejects missing or weak bootstrap configuration', async () => {
  for (const bootstrapSecret of [undefined, '', 'short', 'x'.repeat(31)]) {
    const service = new AccessManagementService({ bootstrapSecret });
    await assert.rejects(
      () => service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin' }, 'x'.repeat(32)),
      { code: 'BOOTSTRAP_UNAVAILABLE' }
    );
  }
});

test('AccessManagementService can retry bootstrap after a failed user write without opening a second path', async () => {
  const bootstrapSecret = VALID_BOOTSTRAP_SECRET;
  let saved = null;
  let saveAttempts = 0;
  const service = new AccessManagementService({
    bootstrapSecret,
    store: {
      async load() { return saved ?? { users: [] }; },
      async save(data) {
        saveAttempts += 1;
        if (saveAttempts === 1) throw new Error('simulated write failure');
        saved = data;
      }
    }
  });

  await assert.rejects(
    () => service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin' }, bootstrapSecret),
    /simulated write failure/
  );
  const created = await service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin' }, bootstrapSecret);
  assert.equal(created.roleKey, 'admin');
  assert.equal((await service.listUsers()).length, 1);
});

test('AccessManagementService does not reopen bootstrap when audit persistence fails after the user write', async () => {
  const bootstrapSecret = VALID_BOOTSTRAP_SECRET;
  let auditAttempts = 0;
  const service = new AccessManagementService({
    bootstrapSecret,
    auditLogService: {
      async record() {
        auditAttempts += 1;
        if (auditAttempts === 1) throw new Error('simulated audit failure');
      }
    }
  });

  await assert.rejects(
    () => service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin' }, bootstrapSecret),
    /simulated audit failure/
  );
  assert.equal((await service.listUsers()).length, 1);
  await assert.rejects(
    () => service.bootstrapFirstAdministrator({ userId: 'admin-2', displayName: 'Second Admin' }, bootstrapSecret),
    { code: 'BOOTSTRAP_CLOSED' }
  );
});

test('AccessManagementService persists terminal bootstrap state after deleting the last administrator', async () => {
  const bootstrapSecret = VALID_BOOTSTRAP_SECRET;
  let saved = { users: [] };
  const store = {
    async load() { return saved; },
    async save(data) { saved = structuredClone(data); }
  };
  const service = new AccessManagementService({ bootstrapSecret, store });
  await service.bootstrapFirstAdministrator({ userId: 'admin-1', displayName: 'Admin' }, bootstrapSecret);
  await service.deleteUser('admin-1');
  assert.deepEqual(saved, { users: [], bootstrapCompleted: true });

  const restarted = new AccessManagementService({ bootstrapSecret, store });
  await assert.rejects(
    () => restarted.bootstrapFirstAdministrator({ userId: 'admin-2', displayName: 'Second Admin' }, bootstrapSecret),
    { code: 'BOOTSTRAP_CLOSED' }
  );
});
test('BOOTSTRAP-ATTACK-001: known placeholder fails closed while a deployment-unique proof bootstraps once', async () => {
  const placeholder = 'REPLACE_WITH_A_UNIQUE_HIGH_ENTROPY_BOOTSTRAP_TOKEN';
  const blocked = new AccessManagementService({ bootstrapSecret: placeholder });
  await assert.rejects(() => blocked.bootstrapFirstAdministrator({ userId: 'attacker', displayName: 'Attacker' }, placeholder), { code: 'BOOTSTRAP_UNAVAILABLE' });
  assert.deepEqual(await blocked.listUsers(), []);
  const unique = new AccessManagementService({ bootstrapSecret: VALID_BOOTSTRAP_SECRET });
  const first = await unique.bootstrapFirstAdministrator({ userId: 'admin', displayName: 'Admin' }, VALID_BOOTSTRAP_SECRET);
  assert.equal(first.userId, 'admin');
});

test('AccessManagementService rejects predictable bootstrap secrets at the configuration boundary', async () => {
  for (const weakSecret of [
    'a'.repeat(32),
    '01234567890123456789012345678901',
    'abcdefghijklmnopqrstuvwxyzabcdef'
  ]) {
    const service = new AccessManagementService({ bootstrapSecret: weakSecret });
    await assert.rejects(
      () => service.bootstrapFirstAdministrator({ userId: 'admin-weak', displayName: 'Admin' }, weakSecret),
      { code: 'BOOTSTRAP_UNAVAILABLE' }
    );
  }
});
