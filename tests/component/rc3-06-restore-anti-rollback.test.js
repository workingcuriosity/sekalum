import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { CredentialManager } from '../../src/managers/credential-manager.js';
import { CredentialTransferService } from '../../src/services/credential-transfer-service.js';
import { RestoreAdmissionService } from '../../src/services/restore-admission-service.js';
import { BackupRestoreService } from '../../src/services/backup-restore-service.js';
import { CredentialSecretVersionService } from '../../src/services/credential-secret-version-service.js';
import { TokenLifecycleService } from '../../src/services/token-lifecycle-service.js';
import { CredentialCollectionStoreAdapter } from '../../src/storage/credential-collection-store-adapter.js';

class MemoryJsonStore {
  constructor() { this.files = new Map(); }
  async exists(filePath) { return this.files.has(filePath); }
  async load(filePath) { return structuredClone(this.files.get(filePath)); }
  async save(filePath, value) { this.files.set(filePath, structuredClone(value)); }
}

function credential(overrides = {}) {
  return Credential.from({
    credentialId: 'credential-1',
    credentialGeneration: 'generation-1',
    credentialKey: 'credential-key-1',
    providerKey: 'provider-1',
    credentialMethodKey: 'api-key',
    externalReference: 'account-1',
    lifecycleState: 'active',
    secrets: [{ name: 'apiKey', value: 'historical-secret' }],
    metadata: { displayName: 'Account 1' },
    ...overrides
  });
}

function transferManager(initialCredentials, { tombstones = [], isDeletedIdentity = null, onBatch = null } = {}) {
  const credentials = [...initialCredentials];
  return {
    credentials,
    tombstones,
    async listCredentials() { return [...credentials]; },
    async getCredential(credentialId) { return credentials.find((item) => item.credentialId === credentialId) ?? null; },
    async getRestoreState() { return { credentials: [...credentials], tombstones: [...tombstones] }; },
    async isDeletedIdentity(credentialId) { return isDeletedIdentity?.(credentialId) ?? tombstones.some((item) => item.credentialId === credentialId); },
    async importCredentialBatch(operations, { beforeCommit = null, onCommitted = null } = {}) {
      await beforeCommit?.({
        currentCredentials: [...credentials],
        currentTombstones: [...tombstones]
      });
      await onBatch?.(operations, credentials);
      return { credentials: [...credentials], operations };
    }
  };
}

function transferPayload(inputCredential) {
  return {
    format: 'credential-hub-credential-transfer',
    schemaVersion: 1,
    generatedAt: '2026-08-22T10:00:00.000Z',
    credentials: [inputCredential.toJSON()]
  };
}

function auditStore(initial = []) {
  let entries = structuredClone(initial);
  return {
    get entries() { return entries; },
    async list() { return structuredClone(entries); },
    async record(entry) { entries.push(structuredClone(entry)); return entry; },
    async replaceEntries(next) { entries = structuredClone(next); return structuredClone(entries); },
    async getRestoreSnapshot() { return structuredClone(entries); },
    async restoreSnapshot(snapshot) { entries = structuredClone(snapshot); }
  };
}

test('RESTORE-ATTACK-001: revoked Credential rejects an old active archive restore', async () => {
  const current = credential({ lifecycleState: 'revoked' });
  const manager = transferManager([current]);
  const service = new CredentialTransferService({ credentialManager: manager });

  await assert.rejects(
    () => service.importCredentials(transferPayload(credential()), { conflictStrategy: 'overwrite' }),
    { code: 'RESTORE_TERMINAL_CONFLICT', classification: 'HARD_SECURITY_BLOCK' }
  );
  assert.equal(manager.credentials[0].lifecycleState, 'revoked');
});

test('RESTORE-ATTACK-002: deleted Credential remains blocked after restart and tombstone reload', async () => {
  const jsonStore = new MemoryJsonStore();
  const createStore = () => new CredentialCollectionStoreAdapter({ jsonStore, basePath: '/rc3-06-attack-002' });
  const original = credential();
  await createStore().create(original);
  await createStore().delete(original.credentialId);
  const manager = new CredentialManager({ credentialStore: createStore() });
  const restartedManager = new CredentialManager({ credentialStore: createStore() });
  const service = new CredentialTransferService({ credentialManager: restartedManager });

  await assert.rejects(
    () => service.importCredentials(transferPayload(original), { conflictStrategy: 'rename' }),
    { code: 'RESTORE_DELETED_IDENTITY_BARRIER', classification: 'HARD_SECURITY_BLOCK' }
  );
  assert.equal((await manager.listCredentials()).length, 0);
  assert.equal((await restartedManager.listCredentials()).length, 0);
});

test('RESTORE-ATTACK-003: rename/recreate input cannot select a tombstoned identity', async () => {
  const manager = transferManager([credential({ credentialId: 'current-1', credentialKey: 'current-key-1', externalReference: 'account-1' })], {
    isDeletedIdentity: (credentialId) => credentialId === 'tombstoned-id'
  });
  const service = new CredentialTransferService({
    credentialManager: manager,
    idGenerator: () => 'tombstoned-id'
  });

  await assert.rejects(
    () => service.importCredentials(transferPayload(credential()), { conflictStrategy: 'rename' }),
    { code: 'RESTORE_DELETED_IDENTITY_BARRIER', classification: 'HARD_SECURITY_BLOCK' }
  );
  assert.equal(manager.credentials.length, 1);
});

test('RESTORE-ATTACK-004: revoked API token cannot be revived by a future historical restore hook', () => {
  const admission = new RestoreAdmissionService();
  const result = admission.preflightApiTokenRestore({
    restoredToken: { id: 'api-token-1', userId: 'user-1', principalGeneration: 'principal-1' },
    currentToken: { id: 'api-token-1', userId: 'user-1', principalGeneration: 'principal-1', revokedAt: '2026-08-22T10:00:00.000Z' },
    currentPrincipal: { userId: 'user-1', principalGeneration: 'principal-1' }
  });

  assert.equal(result.decision, 'BLOCKED');
  assert.throws(() => admission.assertCommitAllowed(result), { code: 'RESTORE_TOKEN_REVOKED' });
});

test('RESTORE-ATTACK-005: old principal generation cannot drive an authority-bearing restore', async () => {
  let users = [{
    userId: 'admin-1', displayName: 'Current Admin', email: null, roleKey: 'admin', status: 'active',
    principalGeneration: 'principal-current', createdAt: '2026-08-22T09:00:00.000Z', updatedAt: '2026-08-22T09:00:00.000Z'
  }];
  const access = {
    async getRestoreState() { return { users: structuredClone(users), roles: [{ roleKey: 'admin', permissions: ['backup:manage'] }], principalTombstones: [] }; },
    async getRestoreSnapshot() { return { users: structuredClone(users), principalTombstones: [], bootstrapCompleted: true }; },
    async replaceUsers(next) { users = structuredClone(next); },
    async restoreSnapshot(snapshot) { users = structuredClone(snapshot.users); },
    async listUsers() { return structuredClone(users); },
    async listRoles() { return [{ roleKey: 'admin', permissions: ['backup:manage'] }]; }
  };
  const audit = auditStore();
  const backups = new Map();
  const service = new BackupRestoreService({
    accessManagementService: access,
    auditLogService: audit,
    managementService: { async getStatus() { return { status: 'ready' }; } },
    store: {
      async save(backup) { backups.set(backup.backupId, structuredClone(backup)); },
      async load(id) { return structuredClone(backups.get(id)); },
      async list() { return [...backups.keys()]; }
    }
  });

  const created = await service.createBackup();
  const historical = await service.getBackup(created.backupId);
  historical.data.users[0].principalGeneration = 'principal-old';
  await backups.set(created.backupId, historical);

  await assert.rejects(() => service.restoreBackup(created.backupId), { code: 'RESTORE_GENERATION_CONFLICT' });
  assert.equal(users[0].principalGeneration, 'principal-current');
});

test('RESTORE-ATTACK-006: Preview PASS followed by concurrent revoke is blocked at final revalidation', async () => {
  const active = credential();
  const revoked = credential({ lifecycleState: 'revoked', version: 2 });
  let current = active;
  const manager = {
    async listCredentials() { return [current]; },
    async getRestoreState() { return { credentials: [current], tombstones: [] }; },
    async isDeletedIdentity() { return false; },
    async importCredentialBatch(_operations, { beforeCommit }) {
      await beforeCommit({ currentCredentials: [current], currentTombstones: [] });
    }
  };
  const coordinator = {
    async run(operation) {
      current = revoked;
      return operation();
    }
  };
  const service = new CredentialTransferService({
    credentialManager: manager,
    restoreCommitCoordinator: coordinator
  });

  await assert.rejects(
    () => service.importCredentials(transferPayload(active), { conflictStrategy: 'overwrite' }),
    { code: 'RESTORE_TERMINAL_CONFLICT', classification: 'HARD_SECURITY_BLOCK' }
  );
  assert.equal(current.lifecycleState, 'revoked');
});

test('RESTORE-ATTACK-007: historical Grant cannot cross a replacement Credential generation', () => {
  const admission = new RestoreAdmissionService();
  const result = admission.preflightGrantRestore({
    restoredGrant: {
      grantId: 'grant-1', consumerId: 'consumer-1', credentialId: 'credential-1',
      credentialGeneration: 'generation-old', providerKey: 'provider-1'
    },
    currentGrant: { grantId: 'grant-1', consumerId: 'consumer-1' },
    currentCredential: credential({ credentialGeneration: 'generation-new' })
  });

  assert.equal(result.decision, 'BLOCKED');
  assert.throws(() => admission.assertCommitAllowed(result), { code: 'RESTORE_GRANT_BINDING_CONFLICT' });
});

test('RESTORE-ATTACK-008: staged management restore failure restores the previous authority state', async () => {
  let users = [{ userId: 'admin-1', displayName: 'Admin', email: null, roleKey: 'admin', status: 'active', principalGeneration: 'principal-1' }];
  const access = {
    async getRestoreState() { return { users: structuredClone(users), roles: [{ roleKey: 'admin', permissions: [] }], principalTombstones: [] }; },
    async getRestoreSnapshot() { return { users: structuredClone(users), principalTombstones: [], bootstrapCompleted: true }; },
    async replaceUsers() { throw new Error('authority publish failed'); },
    async restoreSnapshot(snapshot) { users = structuredClone(snapshot.users); },
    async listUsers() { return structuredClone(users); },
    async listRoles() { return [{ roleKey: 'admin', permissions: [] }]; }
  };
  const audit = auditStore([{ action: 'before', targetId: 'authority', result: 'success' }]);
  const backups = new Map();
  const service = new BackupRestoreService({
    accessManagementService: access,
    auditLogService: audit,
    managementService: { async getStatus() { return { status: 'ready' }; } },
    store: {
      async save(backup) { backups.set(backup.backupId, structuredClone(backup)); },
      async load(id) { return structuredClone(backups.get(id)); },
      async list() { return [...backups.keys()]; }
    }
  });

  const created = await service.createBackup();
  const historical = await service.getBackup(created.backupId);
  historical.data.users = [{ userId: 'admin-2', displayName: 'Historical Admin', email: null, roleKey: 'admin', status: 'active', principalGeneration: 'principal-2' }];
  await backups.set(created.backupId, historical);

  await assert.rejects(() => service.restoreBackup(created.backupId), /authority publish failed/);
  assert.equal(users[0].userId, 'admin-1');
  assert.equal(audit.entries.some((entry) => entry.targetId === 'admin-2'), false);
  assert.equal(audit.entries.at(-1).result, 'failure');
});

test('Restore commit coordinator protects secret rollback from a terminal Credential', async () => {
  const current = credential({ lifecycleState: 'revoked' });
  const manager = {
    async getCredential() { return current; },
    async updateCredential() { throw new Error('must not update'); }
  };
  const versions = new CredentialSecretVersionService({
    credentialManager: manager,
    store: { async load() { return { versions: [{ credentialId: 'credential-1', version: 1, secrets: [{ name: 'apiKey', value: 'old' }], createdAt: new Date().toISOString() }] }; }, async save() {} }
  });
  await assert.rejects(() => versions.rollbackCredentialSecrets('credential-1', 1), { code: 'SECRET_VERSION_UNAVAILABLE' });
});

test('Legacy provider token restore remains separate and requires the current mapped Credential', async () => {
  const lifecycle = new TokenLifecycleService({
    tokenStore: { async load() { const error = new Error('missing'); error.code = 'NOT_FOUND'; throw error; }, async save() {} },
    backupStore: { async restore() { return { providerId: 'provider-1:account-1', credentialKey: 'missing-key' }; } },
    logger: { info() {} },
    credentialManager: { async getCredentialByKey() { return null; } }
  });
  await assert.rejects(() => lifecycle.restore('provider-1:account-1', 'historical'), { code: 'RESTORE_PRINCIPAL_CONFLICT' });
});
