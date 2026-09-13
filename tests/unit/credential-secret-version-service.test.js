import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import {
  CredentialSecretVersionService,
  MAX_HISTORY_BYTES_PER_CREDENTIAL,
  MAX_VERSIONS_PER_CREDENTIAL,
  SECRET_VERSION_RETENTION_MS
} from '../../src/services/credential-secret-version-service.js';

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
  assert.deepEqual(versions.map((version) => version.version), [2, 1]);
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

function persistedVersionStore(initial = { versions: [] }) {
  let state = structuredClone(initial);
  return {
    async load() { return structuredClone(state); },
    async save(value) { state = structuredClone(value); },
    snapshot() { return structuredClone(state); }
  };
}

function versionCredential(credentialId, value = 'secret') {
  return {
    credentialId,
    providerKey: 'test',
    secrets: [{ name: 'token', value }]
  };
}

test('Secret-version high-watermark is persistent and monotonic across restart', async () => {
  const store = persistedVersionStore();
  const service = new CredentialSecretVersionService({ store });
  assert.equal((await service.recordCredentialVersion(versionCredential('watermark'))).version, 1);
  assert.equal((await service.recordCredentialVersion(versionCredential('watermark', 'next'))).version, 2);
  assert.equal(store.snapshot().secretVersionHighWatermarks.watermark, 2);

  const restarted = new CredentialSecretVersionService({ store });
  assert.equal((await restarted.recordCredentialVersion(versionCredential('watermark', 'restart'))).version, 3);
  assert.equal(store.snapshot().secretVersionHighWatermarks.watermark, 3);
});

test('Secret-version count pruning preserves the high-watermark and never reuses expired or invalidated versions', async () => {
  let now = new Date('2026-08-27T00:00:00.000Z');
  const store = persistedVersionStore();
  const service = new CredentialSecretVersionService({ store, clock: () => now });
  for (let index = 0; index < MAX_VERSIONS_PER_CREDENTIAL + 2; index += 1) {
    await service.recordCredentialVersion(versionCredential('bounded', `secret-${index}`));
  }

  assert.equal(store.snapshot().versions.filter((record) => record.credentialId === 'bounded').length, MAX_VERSIONS_PER_CREDENTIAL);
  assert.equal(store.snapshot().secretVersionHighWatermarks.bounded, MAX_VERSIONS_PER_CREDENTIAL + 2);

  now = new Date(now.getTime() + SECRET_VERSION_RETENTION_MS);
  assert.deepEqual(await service.listCredentialVersions('bounded'), []);
  assert.equal(store.snapshot().secretVersionHighWatermarks.bounded, MAX_VERSIONS_PER_CREDENTIAL + 2);
  assert.equal((await service.recordCredentialVersion(versionCredential('bounded', 'after-expiry'))).version, MAX_VERSIONS_PER_CREDENTIAL + 3);

  await service.invalidateHistoryForCredential('bounded', { reason: 'credential-revoked' });
  assert.equal((await service.recordCredentialVersion(versionCredential('bounded', 'after-invalidation'))).version, MAX_VERSIONS_PER_CREDENTIAL + 4);
});

test('Secret-version history byte bound is deterministic and fails closed for one oversized record', async () => {
  const store = persistedVersionStore();
  const service = new CredentialSecretVersionService({ store });
  for (let index = 0; index < 20; index += 1) {
    await service.recordCredentialVersion(versionCredential('bytes', 'x'.repeat(220_000)));
  }

  const retained = store.snapshot().versions.filter((record) => record.credentialId === 'bytes');
  assert.ok(Buffer.byteLength(JSON.stringify(retained), 'utf8') <= MAX_HISTORY_BYTES_PER_CREDENTIAL);
  await assert.rejects(
    () => service.recordCredentialVersion(versionCredential('oversized', 'x'.repeat(MAX_HISTORY_BYTES_PER_CREDENTIAL))),
    (error) => error.code === 'SECRET_VERSION_HISTORY_LIMIT_EXCEEDED'
  );
  assert.equal(store.snapshot().versions.some((record) => record.credentialId === 'oversized'), false);
});

test('Secret-version legacy state converges and heals high-watermark without resetting identity', async () => {
  const old = '2026-08-25T00:00:00.000Z';
  const versions = Array.from({ length: MAX_VERSIONS_PER_CREDENTIAL + 12 }, (_, index) => ({
    versionId: `legacy-${index + 1}`,
    credentialId: 'legacy',
    version: index + 1,
    secrets: [{ name: 'token', value: 'expired' }],
    reason: 'legacy',
    createdAt: old,
    createdBy: 'system',
    metadata: {}
  }));
  const store = persistedVersionStore({ versions });
  const service = new CredentialSecretVersionService({ store, clock: () => new Date('2026-08-27T00:00:00.000Z') });
  assert.deepEqual(await service.listCredentialVersions('legacy'), []);
  assert.equal(store.snapshot().versions.length, MAX_VERSIONS_PER_CREDENTIAL);
  assert.equal(store.snapshot().secretVersionHighWatermarks.legacy, MAX_VERSIONS_PER_CREDENTIAL + 12);
  assert.equal((await service.recordCredentialVersion(versionCredential('legacy', 'new'))).version, MAX_VERSIONS_PER_CREDENTIAL + 13);

  const belowObserved = persistedVersionStore({
    versions: [{ ...versions[6], secrets: [] }],
    secretVersionHighWatermarks: { legacy: 2 }
  });
  const healing = new CredentialSecretVersionService({ store: belowObserved, clock: () => new Date('2026-08-27T00:00:00.000Z') });
  await healing.listCredentialVersions('legacy');
  assert.equal(belowObserved.snapshot().secretVersionHighWatermarks.legacy, 7);

  const ahead = persistedVersionStore({
    versions: [{ ...versions[0], secrets: [] }],
    secretVersionHighWatermarks: { legacy: 20 }
  });
  const aheadService = new CredentialSecretVersionService({ store: ahead });
  assert.equal((await aheadService.recordCredentialVersion(versionCredential('legacy', 'after-ahead'))).version, 21);
});

test('Secret-version malformed state fails closed without resetting version identity', async () => {
  const malformed = persistedVersionStore({
    versions: [{ credentialId: 'malformed', version: 0, secrets: [] }],
    secretVersionHighWatermarks: { malformed: 4 }
  });
  const service = new CredentialSecretVersionService({ store: malformed });
  await assert.rejects(() => service.recordCredentialVersion(versionCredential('malformed', 'new')), { code: 'SECRET_VERSION_STATE_INVALID' });
  assert.equal(malformed.snapshot().secretVersionHighWatermarks.malformed, 4);
});

test('Secret-version batch persistence rolls back history and high-watermark together', async () => {
  const store = persistedVersionStore();
  const service = new CredentialSecretVersionService({ store });
  await assert.rejects(
    () => service.recordCredentialVersionsAtomically([{ credential: versionCredential('atomic'), reason: 'import' }], {
      onCommitted: () => { throw new Error('callback failed'); }
    }),
    /callback failed/
  );
  assert.deepEqual(store.snapshot(), { versions: [], secretVersionHighWatermarks: {} });
});
