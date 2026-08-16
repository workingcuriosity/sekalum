import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { CredentialSecretVersionService } from '../../src/services/credential-secret-version-service.js';

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
