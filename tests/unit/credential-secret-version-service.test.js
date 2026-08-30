import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { CredentialSecretVersionService, SECRET_VERSION_RETENTION_MS } from '../../src/services/credential-secret-version-service.js';

test('CredentialSecretVersionService records immutable secret versions per credential', async () => {
  const service = new CredentialSecretVersionService({
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const credential = Credential.from({
    credentialId: 'threads:main',
    providerKey: 'threads',
    secrets: [{ name: 'accessToken', value: 'access-1' }]
  });

  const first = await service.recordCredentialVersion(credential, { reason: 'initial-import' });
  const second = await service.recordCredentialVersion(Credential.from({
    ...credential.toJSON(),
    secrets: [{ name: 'accessToken', value: 'access-2' }],
    version: 2
  }), { reason: 'refresh' });

  assert.equal(first.version, 1);
  assert.equal(second.version, 2);
  assert.equal(first.secrets[0].value, 'access-1');
  assert.equal(second.secrets[0].value, 'access-2');

  const versions = await service.listCredentialVersions('threads:main');
  assert.deepEqual(versions.map((version) => version.version), [2, 1]);
});

test('CredentialSecretVersionService retrieves a specific version', async () => {
  const service = new CredentialSecretVersionService();
  const credential = Credential.from({
    credentialId: 'google:main',
    providerKey: 'google',
    secrets: [{ name: 'accessToken', value: 'access-1' }]
  });

  await service.recordCredentialVersion(credential, { reason: 'initial-import' });

  const version = await service.getCredentialVersion('google:main', 1);

  assert.equal(version.credentialId, 'google:main');
  assert.equal(version.secrets[0].name, 'accessToken');
  assert.equal(version.secrets[0].value, 'access-1');
});

test('CredentialSecretVersionService rolls back credential secrets through CredentialManager', async () => {
  const saved = [];
  const credential = Credential.from({
    credentialId: 'twitch:main',
    providerKey: 'twitch',
    secrets: [{ name: 'accessToken', value: 'access-new' }],
    metadata: { displayName: 'Main' },
    version: 2
  });

  const credentialManager = {
    async getCredential(credentialId) {
      assert.equal(credentialId, 'twitch:main');
      return credential;
    },
    async updateCredential(credentialId, updates, options) {
      assert.equal(credentialId, 'twitch:main');
      assert.equal(options.skipSecretVersionRecord, true);
      const updated = Credential.from({
        ...credential.toJSON(),
        secrets: updates.secrets,
        metadata: updates.metadata,
        version: credential.version + 1
      });
      saved.push(updated);
      return updated;
    }
  };

  const service = new CredentialSecretVersionService({ credentialManager });
  await service.recordCredentialVersion(Credential.from({
    ...credential.toJSON(),
    secrets: [{ name: 'accessToken', value: 'access-old' }],
    version: 1
  }), { reason: 'initial-import' });

  const rolledBack = await service.rollbackCredentialSecrets('twitch:main', 1, { userId: 'admin' });

  assert.equal(rolledBack.secrets[0].value, 'access-old');
  assert.equal(saved[0].metadata.toJSON().custom.lastSecretRollbackVersion, 1);

  const versions = await service.listCredentialVersions('twitch:main');
  assert.equal(versions[0].reason, 'rollback');
  assert.equal(versions[0].secrets[0].value, 'access-old');
});

test('CredentialSecretVersionService writes audit events when versions change', async () => {
  const auditEntries = [];
  const service = new CredentialSecretVersionService({
    auditLogService: {
      async record(entry) {
        auditEntries.push(entry);
      }
    }
  });

  await service.recordCredentialVersion({
    credentialId: 'openai:main',
    providerKey: 'openai',
    secrets: [{ name: 'apiKey', value: 'key-1' }]
  }, { reason: 'manual-update' });

  assert.equal(auditEntries.length, 1);
  assert.equal(auditEntries[0].action, 'credential-secret-version.created');
  assert.equal(auditEntries[0].targetId, 'openai:main');
  assert.equal(auditEntries[0].details.reason, 'manual-update');
});

test('CredentialSecretVersionService enforces the exact 24-hour retention boundary', async () => {
  let now = new Date('2026-08-27T00:00:00.000Z');
  const service = new CredentialSecretVersionService({ clock: () => now });
  await service.recordCredentialVersion({
    credentialId: 'boundary-credential',
    providerKey: 'test',
    secrets: [{ name: 'token', value: 'boundary-secret' }]
  });

  now = new Date(now.getTime() + SECRET_VERSION_RETENTION_MS - 1);
  assert.equal((await service.getCredentialVersion('boundary-credential', 1)).secrets[0].value, 'boundary-secret');

  now = new Date('2026-08-28T00:00:00.000Z');
  await assert.rejects(
    () => service.getCredentialVersion('boundary-credential', 1),
    (error) => error.code === 'SECRET_VERSION_UNAVAILABLE' && error.message === 'Requested Secret version is not available'
  );

  now = new Date(now.getTime() + 1);
  await assert.rejects(() => service.getCredentialVersion('boundary-credential', 1), { code: 'SECRET_VERSION_UNAVAILABLE' });
});

test('CredentialSecretVersionService invalidates malformed and expired records without regranting retention', async () => {
  const persisted = {
    versions: [
      {
        versionId: 'expired-version',
        credentialId: 'migration-credential',
        version: 1,
        secrets: [{ name: 'token', value: 'expired-secret' }],
        reason: 'initial-import',
        createdAt: '2026-08-25T00:00:00.000Z',
        createdBy: 'system',
        metadata: {}
      },
      {
        versionId: 'invalid-version',
        credentialId: 'migration-credential',
        version: 2,
        secrets: [{ name: 'token', value: 'invalid-secret' }],
        reason: 'refresh',
        createdAt: 'not-a-date',
        createdBy: 'system',
        metadata: {}
      }
    ]
  };
  const store = {
    async load() { return structuredClone(persisted); },
    async save(value) { persisted.versions = structuredClone(value.versions); }
  };
  const service = new CredentialSecretVersionService({
    store,
    clock: () => new Date('2026-08-27T00:00:00.000Z')
  });

  assert.deepEqual(await service.listCredentialVersions('migration-credential'), []);
  assert.equal(persisted.versions.every((version) => version.secrets.length === 0), true);
  assert.equal(persisted.versions.every((version) => version.invalidatedAt), true);

  await service.recordCredentialVersion({
    credentialId: 'migration-credential',
    providerKey: 'test',
    secrets: [{ name: 'token', value: 'fresh-secret' }]
  });
  assert.equal((await service.listCredentialVersions('migration-credential'))[0].version, 3);
});

test('CredentialSecretVersionService fails closed when expiry invalidation cannot persist', async () => {
  const store = {
    async load() {
      return {
        versions: [{
          versionId: 'unpersistable-expired',
          credentialId: 'unpersistable-credential',
          version: 1,
          secrets: [{ name: 'token', value: 'expired-secret' }],
          reason: 'refresh',
          createdAt: '2026-08-25T00:00:00.000Z',
          createdBy: 'system',
          metadata: {}
        }]
      };
    },
    async save() { throw new Error('expiry invalidation storage unavailable'); }
  };
  const service = new CredentialSecretVersionService({ store, clock: () => new Date('2026-08-27T00:00:00.000Z') });
  await assert.rejects(() => service.listCredentialVersions('unpersistable-credential'), /expiry invalidation storage unavailable/);
});

test('CredentialSecretVersionService invalidates history immediately and preserves invalidation after restart', async () => {
  const persisted = { versions: [] };
  const store = {
    async load() { return structuredClone(persisted); },
    async save(value) { persisted.versions = structuredClone(value.versions); }
  };
  const service = new CredentialSecretVersionService({ store, clock: () => new Date('2026-08-27T00:00:00.000Z') });
  await service.recordCredentialVersion({
    credentialId: 'terminal-credential',
    providerKey: 'test',
    secrets: [{ name: 'token', value: 'terminal-secret' }]
  });

  assert.deepEqual(await service.invalidateHistoryForCredential('terminal-credential', { reason: 'credential-revoked' }), {
    credentialId: 'terminal-credential',
    invalidated: 1
  });
  assert.deepEqual(await service.invalidateHistoryForCredential('terminal-credential', { reason: 'credential-revoked' }), {
    credentialId: 'terminal-credential',
    invalidated: 0
  });

  const restarted = new CredentialSecretVersionService({ store, clock: () => new Date('2026-08-27T00:00:00.000Z') });
  await assert.rejects(() => restarted.getCredentialVersion('terminal-credential', 1), { code: 'SECRET_VERSION_UNAVAILABLE' });
  assert.deepEqual(persisted.versions[0].secrets, []);
});

test('CredentialSecretVersionService rejects rollback after expiry and for terminal credentials', async () => {
  let now = new Date('2026-08-27T00:00:00.000Z');
  const credential = Credential.from({
    credentialId: 'rollback-boundary',
    providerKey: 'test',
    secrets: [{ name: 'token', value: 'current-secret' }]
  });
  let updates = 0;
  const credentialManager = {
    async getCredential() { return credential; },
    async updateCredential() { updates += 1; return credential; }
  };
  const service = new CredentialSecretVersionService({ credentialManager, clock: () => now });
  await service.recordCredentialVersion({ ...credential.toJSON(), secrets: [{ name: 'token', value: 'old-secret' }] });

  now = new Date(now.getTime() + SECRET_VERSION_RETENTION_MS);
  await assert.rejects(() => service.rollbackCredentialSecrets(credential.credentialId, 1), { code: 'SECRET_VERSION_UNAVAILABLE' });
  assert.equal(updates, 0);

  const terminalManager = {
    async getCredential() { return Credential.from({ ...credential.toJSON(), lifecycleState: 'revoked' }); },
    async updateCredential() { updates += 1; return credential; }
  };
  const terminalService = new CredentialSecretVersionService({ credentialManager: terminalManager, clock: () => new Date('2026-08-27T00:00:00.000Z') });
  await terminalService.recordCredentialVersion({ ...credential.toJSON(), secrets: [{ name: 'token', value: 'terminal-old-secret' }] });
  await assert.rejects(() => terminalService.rollbackCredentialSecrets(credential.credentialId, 1), { code: 'SECRET_VERSION_UNAVAILABLE' });
  assert.equal(updates, 0);
});
