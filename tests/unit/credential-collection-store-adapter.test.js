import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { CredentialCollectionStoreAdapter } from '../../src/storage/credential-collection-store-adapter.js';
import { withBindingCommitLock } from '../../src/storage/binding-commit-coordinator.js';
import { CompositeCredentialStoreAdapter } from '../../src/storage/composite-credential-store-adapter.js';
import { EncryptedJsonStore } from '../../src/storage/encrypted-json-store.js';
import { JsonStore } from '../../src/storage/json-store.js';

function createJsonStore() {
  let data = null;
  return {
    async exists() { return data !== null; },
    async load() { return structuredClone(data); },
    async save(_path, value) { data = structuredClone(value); }
  };
}

const credentialInput = {
  credentialId: 'openai-main',
  providerKey: 'openai',
  externalReference: 'main',
  secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
  metadata: { displayName: 'OpenAI Main', type: 'api-key' }
};

test('generic credential collection saves and reloads non-OAuth credentials', async () => {
  const store = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });
  const saved = await store.save(credentialInput);

  assert.equal(saved.providerKey, 'openai');
  assert.equal((await store.load('openai-main')).secrets[0].value, 'sk-example-12345678901234567890');
  assert.equal((await store.list()).length, 1);
  assert.equal(await store.exists('openai-main'), true);
  assert.equal(await store.delete('openai-main'), true);
  assert.equal(await store.exists('openai-main'), false);
});

test('generic credential collection persists a generated key when migrating an existing credential', async () => {
  let data = {
    credentials: [{ credentialId: 'legacy-main', providerKey: 'openai', secrets: [] }]
  };
  const jsonStore = {
    async exists() { return true; },
    async load() { return structuredClone(data); },
    async save(_path, value) { data = structuredClone(value); }
  };
  const store = new CredentialCollectionStoreAdapter({ jsonStore, basePath: '/data' });

  const firstLoad = await store.load('legacy-main');
  const secondLoad = await store.load('legacy-main');

  assert.match(firstLoad.credentialKey, /^[0-9a-f-]{36}$/);
  assert.equal(secondLoad.credentialKey, firstLoad.credentialKey);
  assert.equal(data.credentials[0].credentialKey, firstLoad.credentialKey);

  await store.save({ ...firstLoad.toJSON(), metadata: { displayName: 'Updated' } });
  assert.equal((await store.load('legacy-main')).credentialKey, firstLoad.credentialKey);
});

test('metadata-first legacy migration persists one generated public key for later runtime resolution', async () => {
  let rawData = {
    credentials: [{ credentialId: 'legacy-main', providerKey: 'openai', externalReference: 'main', secrets: [] }]
  };
  let metadataData = null;
  const jsonStore = {
    async exists(filePath) { return filePath.endsWith('credentials.json') ? rawData !== null : metadataData !== null; },
    async load(filePath) { return structuredClone(filePath.endsWith('credentials.json') ? rawData : metadataData); },
    async save(filePath, value) {
      if (filePath.endsWith('credentials.json')) rawData = structuredClone(value);
      else metadataData = structuredClone(value);
    }
  };
  const store = new CredentialCollectionStoreAdapter({ jsonStore, metadataJsonStore: jsonStore, basePath: '/data' });

  const metadata = await store.listMetadata();
  const loaded = await store.load('legacy-main');

  assert.equal(loaded.credentialKey, metadata[0].credentialKey);
  assert.equal(rawData.credentials[0].credentialKey, metadata[0].credentialKey);
});

test('legacy migration re-enters the binding lock without a lock-order deadlock', async () => {
  let rawData = {
    credentials: [{ credentialId: 'legacy-main', providerKey: 'openai', externalReference: 'main', secrets: [] }]
  };
  const jsonStore = {
    async exists(filePath) { return filePath.endsWith('credentials.json'); },
    async load() { return structuredClone(rawData); },
    async save(filePath, value) { if (filePath.endsWith('credentials.json')) rawData = structuredClone(value); }
  };
  const store = new CredentialCollectionStoreAdapter({ jsonStore, metadataJsonStore: jsonStore, basePath: '/data' });
  const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('migration lock deadlock')), 100));
  const metadata = await Promise.race([withBindingCommitLock(() => store.listMetadata()), timeout]);
  assert.equal(metadata.length, 1);
  assert.ok(rawData.credentials[0].credentialKey);
});

test('credential collection reports orphaned metadata instead of silently falling back', async () => {
  const rawData = { credentials: [] };
  const metadataData = {
    schemaVersion: 1,
    credentials: [{ credentialId: 'missing-id', credentialKey: 'orphan-key', providerKey: 'openai', externalReference: 'main' }]
  };
  const jsonStore = {
    async exists(filePath) { return filePath.endsWith('credentials.json') ? true : true; },
    async load(filePath) { return structuredClone(filePath.endsWith('credentials.json') ? rawData : metadataData); },
    async save() {}
  };
  const store = new CredentialCollectionStoreAdapter({ jsonStore, metadataJsonStore: jsonStore, basePath: '/data' });

  await assert.rejects(
    () => store.loadByCredentialKey('orphan-key'),
    { code: 'CREDENTIAL_IDENTITY_ORPHANED' }
  );
});

test('credential collection resolves OAuth imports by exact provider and external reference', async () => {
  const store = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });
  await store.save({ ...credentialInput, credentialId: 'canonical-id' });

  const loaded = await store.loadByExternalReference('openai', 'main');

  assert.equal(loaded.credentialId, 'canonical-id');
  await assert.rejects(() => store.loadByExternalReference('openai', 'missing'), { code: 'NOT_FOUND' });
});

test('generic credential collection rejects duplicate public credential keys', async () => {
  const store = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });

  await store.save({ ...credentialInput, credentialId: 'credential-a', credentialKey: 'shared-key' });
  await assert.rejects(
    () => store.save({ ...credentialInput, credentialId: 'credential-b', credentialKey: 'shared-key' }),
    { code: 'CREDENTIAL_KEY_DUPLICATE' }
  );
});

test('generic credential collection rejects duplicate keys during migration', async () => {
  const jsonStore = {
    async exists() { return true; },
    async load() {
      return {
        credentials: [
          { credentialId: 'credential-a', credentialKey: 'shared-key', providerKey: 'openai', secrets: [] },
          { credentialId: 'credential-b', credentialKey: 'shared-key', providerKey: 'openai', secrets: [] }
        ]
      };
    },
    async save() { throw new Error('migration must not persist after collision'); }
  };
  const store = new CredentialCollectionStoreAdapter({ jsonStore, basePath: '/data' });

  await assert.rejects(() => store.list(), { code: 'CREDENTIAL_KEY_DUPLICATE' });
});

test('generic credential collection rejects explicit invalid or changed public keys', async () => {
  const store = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });
  const saved = await store.save({ ...credentialInput, credentialId: 'credential-a', credentialKey: 'stable-key' });

  await assert.rejects(
    () => store.save({ ...saved.toJSON(), credentialKey: null }),
    { code: 'CREDENTIAL_KEY_IMMUTABLE' }
  );
  await assert.rejects(
    () => store.save({ ...saved.toJSON(), credentialKey: 'replacement-key' }),
    { code: 'CREDENTIAL_KEY_IMMUTABLE' }
  );
  assert.equal((await store.load('credential-a')).credentialKey, 'stable-key');
  await assert.rejects(
    () => store.save({ ...credentialInput, credentialId: 'credential-b', credentialKey: null }),
    /Credential: 'credentialKey' is required/
  );
});

test('credential collection applies the shared immutable binding guard to direct existing-record saves', async () => {
  const store = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });
  const saved = await store.save({
    ...credentialInput,
    credentialId: 'guarded-credential',
    credentialMethodKey: 'api-key'
  });
  const immutableChanges = [
    { providerKey: 'other-provider' },
    { externalReference: 'other-account' },
    { credentialMethodKey: 'oauth2' },
    { credentialGeneration: 'generation-2' },
    { providerProfile: { providerKey: 'openai', version: '2.0.0', digest: 'profile-2' } },
    { providerConfigurationId: 'configuration-2' },
    {
      oauthCredentialBinding: {
        providerKey: 'openai',
        credentialMethodKey: 'api-key',
        clientBindingFingerprint: 'a'.repeat(64),
        accountId: 'other-account',
        grantedScopes: []
      }
    }
  ];

  for (const updates of immutableChanges) {
    await assert.rejects(
      () => store.save({ ...saved.toJSON(), metadata: { displayName: 'mutable-attempt' }, ...updates }),
      (error) => error.code === 'CREDENTIAL_LIFECYCLE_CONFLICT'
        && error.details.reason === 'IMMUTABLE_BINDING'
        && !error.message.includes('other-account')
    );
  }

  const persisted = await store.load(saved.credentialId);
  assert.equal(persisted.providerKey, 'openai');
  assert.equal(persisted.externalReference, 'main');
  assert.equal(persisted.credentialMethodKey, 'api-key');
  assert.equal(persisted.metadata.toJSON().displayName, 'OpenAI Main');
});

test('credential collection permits mutable-only partial saves while retaining binding fields', async () => {
  const store = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });
  const saved = await store.save({ ...credentialInput, credentialId: 'partial-guarded', credentialMethodKey: 'api-key' });

  const updated = await store.save({
    credentialId: saved.credentialId,
    metadata: { displayName: 'partial update' },
    version: saved.version + 1
  });

  assert.equal(updated.metadata.toJSON().displayName, 'partial update');
  assert.equal(updated.providerKey, saved.providerKey);
  assert.equal(updated.externalReference, saved.externalReference);
  assert.equal(updated.credentialMethodKey, saved.credentialMethodKey);
  assert.equal(updated.credentialGeneration, saved.credentialGeneration);
  assert.equal(updated.credentialKey, saved.credentialKey);
});

test('credential collection applies the shared immutable binding guard to batch updates', async () => {
  const store = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });
  const saved = await store.save({ ...credentialInput, credentialId: 'batch-guarded', credentialMethodKey: 'api-key' });
  const replacement = { ...saved.toJSON(), providerKey: 'other-provider', metadata: { displayName: 'must-not-persist' }, version: saved.version + 1 };

  await assert.rejects(
    () => store.applyBatch([{ mode: 'update', credential: replacement, expectedVersion: saved.version }]),
    (error) => error.code === 'CREDENTIAL_LIFECYCLE_CONFLICT' && error.details.reason === 'IMMUTABLE_BINDING'
  );
  const persisted = await store.load(saved.credentialId);
  assert.equal(persisted.providerKey, 'openai');
  assert.equal(persisted.metadata.toJSON().displayName, 'OpenAI Main');
});

test('credential collection requires an explicit trusted option for binding migrations', async () => {
  const store = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });
  const saved = await store.save({ ...credentialInput, credentialId: 'migration-guarded', credentialMethodKey: 'api-key' });

  await assert.rejects(
    () => store.saveConditional({ ...saved.toJSON(), credentialMethodKey: 'oauth2', version: saved.version + 1 }, { expectedVersion: saved.version }),
    (error) => error.code === 'CREDENTIAL_LIFECYCLE_CONFLICT' && error.details.reason === 'IMMUTABLE_BINDING'
  );
  const migrated = await store.saveConditional(
    { ...saved.toJSON(), credentialMethodKey: 'oauth2', version: saved.version + 1 },
    { expectedVersion: saved.version, allowBindingChange: true }
  );
  assert.equal(migrated.credentialMethodKey, 'oauth2');
});

test('composite adapter combines generic credentials with legacy OAuth credentials', async () => {
  const primary = new CredentialCollectionStoreAdapter({ jsonStore: createJsonStore(), basePath: '/data' });
  const legacyCredential = { credentialId: 'threads:main', providerKey: 'threads' };
  const legacy = {
    async list() { return [legacyCredential]; },
    async load(id) { if (id === legacyCredential.credentialId) return legacyCredential; const error = new Error('not found'); error.code = 'NOT_FOUND'; throw error; },
    async exists(id) { return id === legacyCredential.credentialId; },
    async delete() { return false; },
    async listLegacyTokens() { return ['legacy-token']; }
  };
  const store = new CompositeCredentialStoreAdapter({ primary, legacy });

  await store.save(credentialInput);
  assert.deepEqual((await store.list()).map((entry) => entry.credentialId), ['openai-main', 'threads:main']);
  assert.equal((await store.load('threads:main')).providerKey, 'threads');
  assert.deepEqual(await store.listLegacyTokens(), ['legacy-token']);
});

test('composite adapter rejects cross-store credentialKey collisions', async () => {
  const primary = {
    async list() { return [{ credentialId: 'credential-a', credentialKey: 'shared-key' }]; }
  };
  const legacy = {
    async list() { return [{ credentialId: 'credential-b', credentialKey: 'shared-key' }]; }
  };
  const store = new CompositeCredentialStoreAdapter({ primary, legacy });

  await assert.rejects(() => store.list(), { code: 'CREDENTIAL_KEY_DUPLICATE' });
});

test('credential collection is encrypted at rest with the secure JSON store', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-hub-create-'));
  const secureStore = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: {
      get(key) { if (key === 'TOKEN_ENCRYPTION_KEY_VERSION') return 1; return null; },
      require(key) { if (key === 'TOKEN_ENCRYPTION_KEY') return '0123456789abcdef0123456789abcdef'; throw new Error(`Missing ${key}`); }
    }
  });
  const store = new CredentialCollectionStoreAdapter({ jsonStore: secureStore, basePath: directory });

  await store.save(credentialInput);
  const raw = await fs.readFile(path.join(directory, 'credentials.json'), 'utf8');

  assert.match(raw, /credential-hub-encrypted-json/);
  assert.doesNotMatch(raw, /sk-example|OpenAI Main/);
  assert.equal((await store.load('openai-main')).providerKey, 'openai');
});

test('credential collection serializes concurrent writes without losing credentials', async () => {
  let data = null;
  const jsonStore = {
    async exists() { return data !== null; },
    async load() {
      const snapshot = structuredClone(data);
      await new Promise((resolve) => setTimeout(resolve, 5));
      return snapshot;
    },
    async save(_path, value) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      data = structuredClone(value);
    }
  };
  const store = new CredentialCollectionStoreAdapter({ jsonStore, basePath: '/data' });

  await Promise.all([
    store.save(credentialInput),
    store.save({ ...credentialInput, credentialId: 'ftp-main', providerKey: 'ftp', externalReference: 'ftp-main' }),
    store.save({ ...credentialInput, credentialId: 'sftp-main', providerKey: 'sftp', externalReference: 'sftp-main' })
  ]);

  assert.deepEqual(
    (await store.list()).map((credential) => credential.credentialId).sort(),
    ['ftp-main', 'openai-main', 'sftp-main']
  );
});

test('credential collection continues serializing after a failed mutation', async () => {
  let data = null;
  let failNextSave = true;
  const jsonStore = {
    async exists() { return data !== null; },
    async load() { return structuredClone(data); },
    async save(_path, value) {
      if (failNextSave) {
        failNextSave = false;
        throw new Error('simulated write failure');
      }
      data = structuredClone(value);
    }
  };
  const store = new CredentialCollectionStoreAdapter({ jsonStore, basePath: '/data' });

  await assert.rejects(() => store.save(credentialInput), /simulated write failure/);
  await store.save({ ...credentialInput, credentialId: 'ftp-main', providerKey: 'ftp' });

  assert.deepEqual((await store.list()).map((credential) => credential.credentialId), ['ftp-main']);
});

test('credential lifecycle conditional persistence recovers after a failed write', async () => {
  let data = null;
  let failNextSave = false;
  const jsonStore = {
    async exists() { return data !== null; },
    async load() { return structuredClone(data); },
    async save(_path, value) {
      if (failNextSave) {
        failNextSave = false;
        throw new Error('simulated conditional write failure');
      }
      data = structuredClone(value);
    }
  };
  const store = new CredentialCollectionStoreAdapter({ jsonStore, basePath: '/data' });
  await store.save(credentialInput);
  const active = await store.load(credentialInput.credentialId);
  const revoked = { ...active.toJSON(), lifecycleState: 'revoked', version: active.version + 1 };
  failNextSave = true;

  await assert.rejects(
    () => store.saveConditional(revoked, { expectedVersion: active.version }),
    /simulated conditional write failure/
  );
  await store.saveConditional(revoked, { expectedVersion: active.version });

  assert.equal((await store.load(credentialInput.credentialId)).lifecycleState, 'revoked');
});
