import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { Config } from '../../src/config/config.js';
import { JsonStore } from '../../src/storage/json-store.js';
import { EncryptedJsonStore } from '../../src/storage/encrypted-json-store.js';
import { TokenStore } from '../../src/storage/token-store.js';
import { BackupStore } from '../../src/storage/backup-store.js';
import { TokenRecord } from '../../src/models/token-record.js';
import { TokenLifecycleService } from '../../src/services/token-lifecycle-service.js';

const ENCRYPTION_KEY = '12345678901234567890123456789012';

async function createSecureStores() {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const secureJsonStore = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  return {
    basePath,
    tokenStore: new TokenStore({
      jsonStore: secureJsonStore,
      basePath,
      logger: console
    }),
    backupStore: new BackupStore({
      jsonStore: secureJsonStore,
      basePath
    })
  };
}

function createTokenRecord(overrides = {}) {
  return new TokenRecord({
    providerId: 'google:main',
    provider: 'google',
    accountId: 'main',
    accountName: 'Google Main',
    accessToken: 'google-access-token-secret',
    refreshToken: 'google-refresh-token-secret',
    expiresAt: '2026-07-05T12:00:00.000Z',
    scopes: ['openid', 'email', 'profile'],
    metadata: { email: 'credential@example.test' },
    ...overrides
  });
}

test('active TokenStore persists Credential secrets encrypted at rest', async () => {
  const { basePath, tokenStore } = await createSecureStores();
  const tokenRecord = createTokenRecord();

  await tokenStore.save(tokenRecord);

  const filePath = path.join(basePath, 'tokens', 'google', 'main.json');
  const raw = await fs.readFile(filePath, 'utf8');
  const payload = JSON.parse(raw);

  assert.equal(payload.type, 'credential-hub-encrypted-json');
  assert.equal(payload.algorithm, 'aes-256-gcm');
  assert.doesNotMatch(raw, /google-access-token-secret/);
  assert.doesNotMatch(raw, /google-refresh-token-secret/);
  assert.doesNotMatch(raw, /credential@example\.test/);

  const loaded = await tokenStore.load('google:main');

  assert.equal(loaded.accessToken, 'google-access-token-secret');
  assert.equal(loaded.refreshToken, 'google-refresh-token-secret');
  assert.equal(loaded.metadata.email, 'credential@example.test');
});

test('TokenStore migrates a legacy token key once and preserves it', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-legacy-key-'));
  const jsonStore = new JsonStore();
  const tokenStore = new TokenStore({ jsonStore, basePath, logger: console });
  const { credentialKey, ...legacyRecord } = createTokenRecord({ credentialKey: 'legacy-public-key' });
  await jsonStore.save(path.join(basePath, 'tokens', 'google', 'main.json'), legacyRecord);

  const first = await tokenStore.load('google:main');
  const second = await tokenStore.load('google:main');

  assert.match(first.credentialKey, /^[0-9a-f-]{36}$/);
  assert.equal(second.credentialKey, first.credentialKey);
  assert.equal((await jsonStore.load(path.join(basePath, 'tokens', 'google', 'main.json'))).credentialKey, first.credentialKey);
});

test('TokenStore rejects duplicate public keys in the legacy inventory', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-duplicate-key-'));
  const jsonStore = new JsonStore();
  const tokenStore = new TokenStore({ jsonStore, basePath, logger: console });
  const first = createTokenRecord({ providerId: 'google:main', credentialKey: 'shared-key' });
  const second = createTokenRecord({ providerId: 'threads:main', provider: 'threads', credentialKey: 'shared-key' });
  await jsonStore.save(path.join(basePath, 'tokens', 'google', 'main.json'), first);
  await jsonStore.save(path.join(basePath, 'tokens', 'threads', 'main.json'), second);

  await assert.rejects(() => tokenStore.list(), { code: 'CREDENTIAL_KEY_DUPLICATE' });
});

test('TokenStore does not replace an existing credentialKey on update', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-key-update-'));
  const jsonStore = new JsonStore();
  const tokenStore = new TokenStore({ jsonStore, basePath, logger: console });
  const tokenRecord = createTokenRecord({ credentialKey: 'stable-key' });
  await tokenStore.save(tokenRecord);

  await assert.rejects(
    () => tokenStore.save(createTokenRecord({ credentialKey: 'replacement-key' })),
    { code: 'CREDENTIAL_KEY_IMMUTABLE' }
  );
  assert.equal((await tokenStore.load('google:main')).credentialKey, 'stable-key');
});

test('active BackupStore persists backup secrets encrypted at rest', async () => {
  const { basePath, backupStore } = await createSecureStores();
  const tokenRecord = createTokenRecord();

  const backupId = await backupStore.createBackup(tokenRecord);

  const filePath = path.join(basePath, 'backups', 'google', 'main', `${backupId}.json`);
  const raw = await fs.readFile(filePath, 'utf8');
  const payload = JSON.parse(raw);

  assert.equal(payload.type, 'credential-hub-encrypted-json');
  assert.doesNotMatch(raw, /google-access-token-secret/);
  assert.doesNotMatch(raw, /google-refresh-token-secret/);

  const restored = await backupStore.restore('google:main', backupId);

  assert.equal(restored.accessToken, 'google-access-token-secret');
  assert.equal(restored.refreshToken, 'google-refresh-token-secret');
  assert.equal(restored.credentialKey, tokenRecord.credentialKey);
});

test('legacy backups without credentialKey remain migratable', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-legacy-backup-'));
  const jsonStore = new JsonStore();
  const backupStore = new BackupStore({ jsonStore, basePath });
  const tokenStore = new TokenStore({ jsonStore, basePath, logger: console });
  const tokenRecord = createTokenRecord({ credentialKey: 'legacy-backup-key' });
  const { credentialKey: _credentialKey, ...legacyBackup } = tokenRecord;
  await jsonStore.save(path.join(basePath, 'backups', 'google', 'main', 'legacy.json'), legacyBackup);

  const restored = await backupStore.restore('google:main', 'legacy');
  await tokenStore.save(restored);
  const loaded = await tokenStore.load('google:main');

  assert.match(restored.credentialKey, /^[0-9a-f-]{36}$/);
  assert.equal(loaded.credentialKey, restored.credentialKey);
  assert.equal(loaded.id, tokenRecord.id);
});

test('legacy backup restore over an existing token preserves the existing credentialKey', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-legacy-backup-existing-'));
  const jsonStore = new JsonStore();
  const backupStore = new BackupStore({ jsonStore, basePath });
  const tokenStore = new TokenStore({ jsonStore, basePath, logger: console });
  const existing = createTokenRecord({ credentialKey: 'existing-key' });
  const { credentialKey: _credentialKey, ...legacyBackup } = createTokenRecord({ id: existing.id });
  await tokenStore.save(existing);
  await jsonStore.save(path.join(basePath, 'backups', 'google', 'main', 'legacy.json'), legacyBackup);

  const restored = await (new TokenLifecycleService({
    tokenStore,
    backupStore,
    logger: console
  })).restore('google:main', 'legacy');

  assert.equal(restored.id, existing.id);
  assert.equal(restored.credentialKey, existing.credentialKey);
  assert.equal((await tokenStore.load('google:main')).credentialKey, existing.credentialKey);

  await jsonStore.save(path.join(basePath, 'backups', 'google', 'main', 'different.json'), {
    ...legacyBackup,
    credentialKey: 'different-key'
  });
  await assert.rejects(
    () => (new TokenLifecycleService({ tokenStore, backupStore, logger: console })).restore('google:main', 'different'),
    { code: 'CREDENTIAL_KEY_IMMUTABLE' }
  );
});

test('BackupStore rejects an explicitly invalid credentialKey', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-invalid-backup-'));
  const jsonStore = new JsonStore();
  const backupStore = new BackupStore({ jsonStore, basePath });
  const tokenRecord = createTokenRecord({ credentialKey: 'stable-key' });
  await jsonStore.save(path.join(basePath, 'backups', 'google', 'main', 'invalid.json'), {
    ...tokenRecord,
    credentialKey: null
  });

  await assert.rejects(
    () => backupStore.restore('google:main', 'invalid'),
    /TokenRecord: 'credentialKey' is required/
  );
});

test('BackupStore rejects an explicitly undefined credentialKey', async () => {
  const backupStore = new BackupStore({
    jsonStore: { async load() { return { providerId: 'google:main', provider: 'google', accountId: 'main', accessToken: 'secret', credentialKey: undefined }; } },
    basePath: '/data'
  });

  await assert.rejects(
    () => backupStore.restore('google:main', 'invalid-undefined'),
    /TokenRecord: 'credentialKey' is required/
  );
});

test('TokenStore rolls back a failed multi-file legacy key migration', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-migration-rollback-'));
  const jsonStore = new JsonStore();
  const firstPath = path.join(basePath, 'tokens', 'google', 'main.json');
  const secondPath = path.join(basePath, 'tokens', 'threads', 'main.json');
  const first = createTokenRecord({ providerId: 'google:main' });
  const second = createTokenRecord({ providerId: 'threads:main', provider: 'threads' });
  const { credentialKey: _firstKey, ...legacyFirst } = first;
  const { credentialKey: _secondKey, ...legacySecond } = second;
  await jsonStore.save(firstPath, legacyFirst);
  await jsonStore.save(secondPath, legacySecond);

  let migrationWrites = 0;
  let failed = false;
  const originalSave = jsonStore.save.bind(jsonStore);
  jsonStore.save = async (filePath, value) => {
    if (filePath.includes(`${path.sep}tokens${path.sep}`) && Object.hasOwn(value, 'credentialKey')) {
      migrationWrites += 1;
      if (migrationWrites === 2 && !failed) {
        failed = true;
        throw new Error('simulated migration write failure');
      }
    }
    return originalSave(filePath, value);
  };

  const tokenStore = new TokenStore({ jsonStore, basePath, logger: console });

  await assert.rejects(() => tokenStore.list(), /simulated migration write failure/);
  assert.equal(Object.hasOwn(await jsonStore.load(firstPath), 'credentialKey'), false);
  assert.equal(Object.hasOwn(await jsonStore.load(secondPath), 'credentialKey'), false);

  const migrated = await tokenStore.list();
  assert.equal(migrated.length, 2);
  assert.equal(Object.hasOwn(await jsonStore.load(firstPath), 'credentialKey'), true);
  assert.equal(Object.hasOwn(await jsonStore.load(secondPath), 'credentialKey'), true);
});

test('EncryptedJsonStore rejects invalid encryption key length', async () => {
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: 'too-short' })
  });

  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));

  await assert.rejects(
    () => store.save(path.join(basePath, 'secret.json'), { accessToken: 'secret' }),
    /TOKEN_ENCRYPTION_KEY for version 1 must contain exactly 32 characters/
  );
});

test('EncryptedJsonStore can read existing plaintext JSON and rewrites encrypted on save', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'legacy.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await fs.writeFile(filePath, JSON.stringify({ accessToken: 'legacy-secret' }), 'utf8');

  assert.deepEqual(await store.load(filePath), { accessToken: 'legacy-secret' });

  await store.save(filePath, { accessToken: 'new-secret' });

  const raw = await fs.readFile(filePath, 'utf8');
  assert.doesNotMatch(raw, /new-secret/);
  assert.deepEqual(await store.load(filePath), { accessToken: 'new-secret' });
});

test('EncryptedJsonStore writes keyVersion metadata for new encrypted payloads', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'secret.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'versioned-secret' });

  const raw = await fs.readFile(filePath, 'utf8');
  const payload = JSON.parse(raw);

  assert.equal(payload.keyVersion, 1);

  const metadata = await store.getEncryptionMetadata(filePath);
  assert.deepEqual(metadata, {
    encrypted: true,
    keyVersion: 1,
    algorithm: 'aes-256-gcm',
    version: 1,
    currentKeyVersion: 1,
    needsReEncryption: false
  });
  assert.equal(await store.needsReEncryption(filePath), false);
});

test('EncryptedJsonStore can read encrypted legacy payloads without keyVersion as version 1', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'legacy-encrypted.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'legacy-encrypted-secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  delete payload.keyVersion;
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  assert.deepEqual(await store.load(filePath), { accessToken: 'legacy-encrypted-secret' });

  const metadata = await store.getEncryptionMetadata(filePath);
  assert.equal(metadata.keyVersion, 1);
  assert.equal(metadata.needsReEncryption, false);
});

test('EncryptedJsonStore rejects encrypted payloads with unsupported algorithm', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'unsupported-algorithm.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  payload.algorithm = 'aes-128-cbc';
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    /Unsupported encrypted JSON algorithm: aes-128-cbc/
  );
});

test('EncryptedJsonStore rejects encrypted payloads without configured historical key version', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'future-key-version.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  payload.keyVersion = 2;
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    /Missing TOKEN_ENCRYPTION_KEY for encrypted JSON key version: 2/
  );
});

test('EncryptedJsonStore rejects encrypted payloads with invalid iv structure', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'invalid-iv.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  payload.iv = Buffer.from('too-short').toString('base64');
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    /Invalid encrypted JSON payload: iv must decode to 12 bytes/
  );
});

test('EncryptedJsonStore rejects tampered encrypted payload data', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'tampered-data.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  const data = Buffer.from(payload.data, 'base64');
  data[0] = data[0] ^ 1;
  payload.data = data.toString('base64');
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    /Encrypted JSON payload could not be decrypted/
  );
});

test('EncryptedJsonStore rejects valid payload encrypted with a different key', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'wrong-key.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });
  const wrongKeyStore = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: 'abcdefghijklmnopqrstuvwxyz123456' })
  });

  await store.save(filePath, { accessToken: 'secret' });

  await assert.rejects(
    () => wrongKeyStore.load(filePath),
    /Encrypted JSON payload could not be decrypted/
  );
});

const ROTATION_KEY_V1 = '11111111111111111111111111111111';
const ROTATION_KEY_V2 = '22222222222222222222222222222222';

function createRotatingStore(currentVersion = 2) {
  return new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({
      TOKEN_ENCRYPTION_KEYS: JSON.stringify({
        1: ROTATION_KEY_V1,
        2: ROTATION_KEY_V2
      }),
      TOKEN_ENCRYPTION_KEY_VERSION: String(currentVersion)
    })
  });
}

test('EncryptedJsonStore writes new payloads with configured current key version', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'current-key-version.json');
  const store = createRotatingStore(2);

  await store.save(filePath, { accessToken: 'current-version-secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  assert.equal(payload.keyVersion, 2);
  assert.deepEqual(await store.load(filePath), { accessToken: 'current-version-secret' });

  const metadata = await store.getEncryptionMetadata(filePath);
  assert.equal(metadata.keyVersion, 2);
  assert.equal(metadata.currentKeyVersion, 2);
  assert.equal(metadata.needsReEncryption, false);
});

test('EncryptedJsonStore can decrypt old key versions when rotation keys are configured', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'old-key-version.json');
  const oldStore = createRotatingStore(1);
  const currentStore = createRotatingStore(2);

  await oldStore.save(filePath, { accessToken: 'old-version-secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  assert.equal(payload.keyVersion, 1);

  assert.deepEqual(await currentStore.load(filePath), { accessToken: 'old-version-secret' });
  assert.equal(await currentStore.needsReEncryption(filePath), true);

  const metadata = await currentStore.getEncryptionMetadata(filePath);
  assert.equal(metadata.keyVersion, 1);
  assert.equal(metadata.currentKeyVersion, 2);
  assert.equal(metadata.needsReEncryption, true);
});

test('EncryptedJsonStore re-encrypts old payloads with the current key version', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'reencrypt-old-key-version.json');
  const oldStore = createRotatingStore(1);
  const currentStore = createRotatingStore(2);

  await oldStore.save(filePath, { accessToken: 'rotated-secret' });

  const result = await currentStore.reEncrypt(filePath);
  assert.equal(result.reEncrypted, true);
  assert.equal(result.before.keyVersion, 1);
  assert.equal(result.after.keyVersion, 2);
  assert.equal(result.after.needsReEncryption, false);
  assert.deepEqual(await currentStore.load(filePath), { accessToken: 'rotated-secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  assert.equal(payload.keyVersion, 2);
});

test('EncryptedJsonStore re-encrypts plaintext legacy files with the current key version', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'reencrypt-plaintext.json');
  const store = createRotatingStore(2);

  await fs.writeFile(filePath, JSON.stringify({ accessToken: 'plaintext-secret' }), 'utf8');

  assert.equal(await store.needsReEncryption(filePath), true);

  const result = await store.reEncrypt(filePath);
  assert.equal(result.reEncrypted, true);
  assert.equal(result.before.encrypted, false);
  assert.equal(result.after.keyVersion, 2);
  assert.equal(result.after.needsReEncryption, false);

  const raw = await fs.readFile(filePath, 'utf8');
  assert.doesNotMatch(raw, /plaintext-secret/);
  assert.deepEqual(await store.load(filePath), { accessToken: 'plaintext-secret' });
});

test('EncryptedJsonStore rejects encrypted payloads when required historical key is missing', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'missing-historical-key.json');
  const oldStore = createRotatingStore(1);
  const currentStoreWithoutOldKey = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({
      TOKEN_ENCRYPTION_KEYS: JSON.stringify({ 2: ROTATION_KEY_V2 }),
      TOKEN_ENCRYPTION_KEY_VERSION: '2'
    })
  });

  await oldStore.save(filePath, { accessToken: 'requires-old-key' });

  await assert.rejects(
    () => currentStoreWithoutOldKey.load(filePath),
    /Missing TOKEN_ENCRYPTION_KEY for encrypted JSON key version: 1/
  );
});

test('EncryptedJsonStore returns diagnostics for encrypted payloads', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'diagnostics-encrypted.json');
  const store = createRotatingStore(2);

  await store.save(filePath, { accessToken: 'diagnostic-secret' });

  assert.deepEqual(await store.getEncryptionDiagnostics(filePath), {
    encrypted: true,
    legacyPlaintext: false,
    algorithm: 'aes-256-gcm',
    keyVersion: 2,
    currentKeyVersion: 2,
    payloadVersion: 1,
    needsReEncryption: false
  });
});

test('EncryptedJsonStore returns diagnostics for plaintext legacy files', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'diagnostics-plaintext.json');
  const store = createRotatingStore(2);

  await fs.writeFile(filePath, JSON.stringify({ accessToken: 'legacy-plaintext-secret' }), 'utf8');

  assert.deepEqual(await store.getEncryptionDiagnostics(filePath), {
    encrypted: false,
    legacyPlaintext: true,
    algorithm: null,
    keyVersion: null,
    currentKeyVersion: 2,
    payloadVersion: null,
    needsReEncryption: true
  });
});

test('EncryptedJsonStore diagnostics mark old key versions for re-encryption', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'diagnostics-old-key-version.json');
  const oldStore = createRotatingStore(1);
  const currentStore = createRotatingStore(2);

  await oldStore.save(filePath, { accessToken: 'old-diagnostic-secret' });

  const diagnostics = await currentStore.getEncryptionDiagnostics(filePath);

  assert.equal(diagnostics.encrypted, true);
  assert.equal(diagnostics.legacyPlaintext, false);
  assert.equal(diagnostics.keyVersion, 1);
  assert.equal(diagnostics.currentKeyVersion, 2);
  assert.equal(diagnostics.needsReEncryption, true);
});

test('EncryptedJsonStore exposes structured error code for unsupported algorithm', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'structured-unsupported-algorithm.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  payload.algorithm = 'aes-128-cbc';
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    (error) => {
      assert.equal(error.name, 'EncryptedJsonStoreError');
      assert.equal(error.code, 'ENCRYPTED_JSON_UNSUPPORTED_ALGORITHM');
      assert.deepEqual(error.details, { algorithm: 'aes-128-cbc' });
      return true;
    }
  );
});

test('EncryptedJsonStore exposes structured error code for invalid payload field length', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'structured-invalid-iv.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  payload.iv = Buffer.from('too-short').toString('base64');
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    (error) => {
      assert.equal(error.name, 'EncryptedJsonStoreError');
      assert.equal(error.code, 'ENCRYPTED_JSON_INVALID_FIELD_LENGTH');
      assert.equal(error.details.field, 'iv');
      assert.equal(error.details.expectedLength, 12);
      return true;
    }
  );
});

test('EncryptedJsonStore exposes structured error code for decrypt integrity failure', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'structured-tampered-data.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  const data = Buffer.from(payload.data, 'base64');
  data[0] = data[0] ^ 1;
  payload.data = data.toString('base64');
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    (error) => {
      assert.equal(error.name, 'EncryptedJsonStoreError');
      assert.equal(error.code, 'ENCRYPTED_JSON_DECRYPT_FAILED');
      assert.equal(error.details.keyVersion, 1);
      assert.equal(error.details.algorithm, 'aes-256-gcm');
      return true;
    }
  );
});

test('EncryptedJsonStore exposes structured error code for invalid payload type', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'structured-invalid-type.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  payload.type = 'unexpected-encrypted-json';
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  // A different type is treated as legacy/plain JSON and returned unchanged.
  // This protects backward compatibility for non-Credential-HUB JSON files.
  assert.deepEqual(await store.load(filePath), payload);
});

test('EncryptedJsonStore exposes structured error code for unsupported payload version', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'structured-unsupported-version.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  payload.version = 999;
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    (error) => {
      assert.equal(error.name, 'EncryptedJsonStoreError');
      assert.equal(error.code, 'ENCRYPTED_JSON_UNSUPPORTED_VERSION');
      assert.deepEqual(error.details, { version: 999 });
      return true;
    }
  );
});

test('EncryptedJsonStore exposes structured error code for invalid base64 data field', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'structured-invalid-base64.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  payload.data = 'not-valid-base64!';
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    (error) => {
      assert.equal(error.name, 'EncryptedJsonStoreError');
      assert.equal(error.code, 'ENCRYPTED_JSON_INVALID_BASE64');
      assert.deepEqual(error.details, { field: 'data' });
      return true;
    }
  );
});

test('EncryptedJsonStore exposes structured error code for tampered auth tag', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));
  const filePath = path.join(basePath, 'structured-tampered-tag.json');
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY })
  });

  await store.save(filePath, { accessToken: 'secret' });

  const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
  const tag = Buffer.from(payload.tag, 'base64');
  tag[0] = tag[0] ^ 1;
  payload.tag = tag.toString('base64');
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');

  await assert.rejects(
    () => store.load(filePath),
    (error) => {
      assert.equal(error.name, 'EncryptedJsonStoreError');
      assert.equal(error.code, 'ENCRYPTED_JSON_DECRYPT_FAILED');
      assert.equal(error.details.keyVersion, 1);
      assert.equal(error.details.algorithm, 'aes-256-gcm');
      return true;
    }
  );
});

test('EncryptedJsonStore exposes structured error code for invalid TOKEN_ENCRYPTION_KEYS JSON', async () => {
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEYS: '{invalid-json' })
  });
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));

  await assert.rejects(
    () => store.save(path.join(basePath, 'secret.json'), { accessToken: 'secret' }),
    (error) => {
      assert.equal(error.name, 'EncryptedJsonStoreError');
      assert.equal(error.code, 'ENCRYPTED_JSON_KEYS_INVALID_JSON');
      return true;
    }
  );
});

test('EncryptedJsonStore exposes structured error code for invalid current key version config', async () => {
  const store = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({
      TOKEN_ENCRYPTION_KEYS: JSON.stringify({ 1: ENCRYPTION_KEY }),
      TOKEN_ENCRYPTION_KEY_VERSION: 'latest'
    })
  });
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-secure-store-'));

  await assert.rejects(
    () => store.save(path.join(basePath, 'secret.json'), { accessToken: 'secret' }),
    (error) => {
      assert.equal(error.name, 'EncryptedJsonStoreError');
      assert.equal(error.code, 'ENCRYPTED_JSON_INVALID_KEY_VERSION');
      assert.equal(error.details.label, 'TOKEN_ENCRYPTION_KEY_VERSION');
      assert.equal(error.details.value, 'latest');
      return true;
    }
  );
});
