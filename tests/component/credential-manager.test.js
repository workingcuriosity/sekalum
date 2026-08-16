import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialManager } from '../../src/managers/credential-manager.js';
import { TokenManager } from '../../src/managers/token-manager.js';
import { Credential } from '../../src/models/credential.js';
import { LifecycleState } from '../../src/models/lifecycle-state.js';
import { ProviderResult } from '../../src/models/provider-result.js';
import { OAuthResult } from '../../src/models/oauth-result.js';
import { CredentialCollectionStoreAdapter } from '../../src/storage/credential-collection-store-adapter.js';
import { ConsumerCredentialService } from '../../src/services/consumer-credential-service.js';

function createMemoryStore() {
  const map = new Map();
  return {
    async save(credential) {
      map.set(credential.credentialId, credential);
    },
    async load(credentialId) {
      return map.get(credentialId);
    },
    async list() {
      return Array.from(map.values());
    },
    async delete(credentialId) {
      return map.delete(credentialId);
    }
  };
}

function createProviderManager(fields, providerKey = 'openai') {
  return {
    getProvider(key) {
      if (key !== providerKey) {
        const error = new Error('not found');
        error.code = 'NOT_FOUND';
        throw error;
      }
      return { key, credentialFields: fields };
    }
  };
}

const openAiFields = [
  { key: 'displayName', required: true, secret: false, type: 'text' },
  { key: 'apiKey', required: true, secret: true, type: 'api-key', validation: { minLength: 20 } }
];

test('CredentialManager validates and stores an OpenAI API-key credential', async () => {
  const store = createMemoryStore();
  const providerFields = [
    ...openAiFields,
    { key: 'redirectUri', secret: false, section: 'providerConfiguration' }
  ];
  const manager = new CredentialManager({ credentialStore: store, providerManager: createProviderManager(providerFields) });
  const credential = await manager.register({
    providerKey: 'openai',
    externalReference: 'main',
    secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
    metadata: { displayName: 'OpenAI Main' }
  });

  assert.equal((await store.load(credential.credentialId)).providerKey, 'openai');
});

test('CredentialManager returns stable creation failures before persistence', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store, providerManager: createProviderManager(openAiFields) });

  await assert.rejects(
    () => manager.register({ providerKey: 'openai', externalReference: 'main', metadata: { displayName: 'OpenAI Main' } }),
    (error) => error.code === 'CREDENTIAL_SECRET_MISSING' && error.messageKey === 'credential.create.secretMissing'
  );
  await assert.rejects(
    () => manager.register({ providerKey: 'openai', externalReference: 'main', secrets: [{ name: 'apiKey', value: 'invalid' }], metadata: { displayName: 'OpenAI Main' } }),
    (error) => error.code === 'CREDENTIAL_FIELD_INVALID'
  );
  await assert.rejects(
    () => manager.register({ providerKey: 'missing', externalReference: 'main', secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }] }),
    (error) => error.code === 'CREDENTIAL_PROVIDER_UNKNOWN'
  );
});

test('CredentialManager maps encryption and persistence failures to safe creation errors', async () => {
  const input = { providerKey: 'openai', externalReference: 'main', secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }], metadata: { displayName: 'OpenAI Main' } };
  const encryptionStore = { async save() { const error = new Error('raw key failure'); error.code = 'ENCRYPTED_JSON_KEY_INVALID'; throw error; } };
  const persistenceStore = { async save() { throw new Error('raw database failure'); } };

  await assert.rejects(
    () => new CredentialManager({ credentialStore: encryptionStore, providerManager: createProviderManager(openAiFields) }).register(input),
    (error) => error.code === 'CREDENTIAL_ENCRYPTION_FAILED' && !error.message.includes('key')
  );
  await assert.rejects(
    () => new CredentialManager({ credentialStore: persistenceStore, providerManager: createProviderManager(openAiFields) }).register(input),
    (error) => error.code === 'CREDENTIAL_PERSISTENCE_FAILED' && !error.message.includes('database')
  );
});

test('CredentialManager registers credentials without provider type knowledge', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store });

  const credential = await manager.register({
    providerKey: 'threads',
    externalReference: 'account-1',
    secrets: [{ name: 'accessToken', value: 'access' }]
  });

  assert.equal(credential instanceof Credential, true);
  assert.equal(credential.lifecycleState, LifecycleState.REGISTERED);
  assert.equal(await store.load(credential.credentialId), credential);
});


test('CredentialManager reads a credential through the CredentialStore', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store });

  const credential = await manager.register({
    providerKey: 'threads',
    externalReference: 'account-1',
    secrets: [{ name: 'accessToken', value: 'access' }]
  });

  assert.equal(await manager.getCredential(credential.credentialId), credential);
  assert.equal(await manager.load(credential.credentialId), credential);
});

test('CredentialManager validates selected methods and migrates legacy credentials only through an explicit method key', async () => {
  const store = createMemoryStore();
  const provider = {
    key: 'example',
    credentialMethods: [
      { key: 'api-key', credentialFields: [{ key: 'apiKey', required: true, secret: true, type: 'api-key' }] },
      { key: 'webhook', credentialFields: [{ key: 'signingSecret', required: true, secret: true, type: 'password' }] }
    ],
    providerMethodBindings: [{ methodKey: 'api-key' }, { methodKey: 'webhook' }]
  };
  const manager = new CredentialManager({ credentialStore: store, providerManager: { getProvider() { return provider; } } });

  await assert.rejects(
    () => manager.register({ providerKey: 'example', secrets: [{ name: 'apiKey', value: 'key' }] }),
    (error) => error.code === 'CREDENTIAL_METHOD_REQUIRED'
  );
  await assert.rejects(
    () => manager.register({ providerKey: 'example', credentialMethodKey: 'missing', secrets: [{ name: 'apiKey', value: 'key' }] }),
    (error) => error.code === 'CREDENTIAL_METHOD_UNAVAILABLE'
  );

  const legacy = new Credential({ credentialId: 'legacy-1', providerKey: 'example', secrets: [{ name: 'apiKey', value: 'key' }] });
  await store.save(legacy);
  const migrated = await manager.migrateCredentialMethod('legacy-1', 'api-key');
  assert.equal(migrated.credentialMethodKey, 'api-key');
  assert.equal(migrated.version, 2);
});

test('CredentialManager startup migration assigns oauth2 to legacy Discord token records', async () => {
  const store = createMemoryStore();
  const provider = {
    credentialMethods: [
      { key: 'oauth2', credentialFields: [] },
      { key: 'webhook', credentialFields: [] }
    ],
    providerMethodBindings: [{ methodKey: 'oauth2' }, { methodKey: 'webhook' }]
  };
  const manager = new CredentialManager({ credentialStore: store, providerManager: { getProvider() { return provider; } } });
  await store.save(new Credential({
    credentialId: 'legacy-discord-oauth',
    providerKey: 'discord',
    secrets: [{ name: 'accessToken', value: 'legacy-access-token' }, { name: 'refreshToken', value: 'legacy-refresh-token' }]
  }));

  assert.deepEqual(await manager.migrateLegacyCredentialMethods(), ['legacy-discord-oauth']);
  assert.equal((await store.load('legacy-discord-oauth')).credentialMethodKey, 'oauth2');
});

test('CredentialManager lists credentials through the CredentialStore', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store });

  const first = await manager.register({
    providerKey: 'threads',
    externalReference: 'account-1',
    secrets: [{ name: 'accessToken', value: 'access-1' }]
  });
  const second = await manager.register({
    providerKey: 'discord',
    externalReference: 'account-2',
    secrets: [{ name: 'accessToken', value: 'access-2' }]
  });

  assert.deepEqual(await manager.listCredentials(), [first, second]);
});


test('CredentialManager updates a credential through the CredentialStore', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store });

  const credential = await manager.register({
    providerKey: 'threads',
    externalReference: 'account-1',
    secrets: [{ name: 'accessToken', value: 'access-1' }],
    metadata: { displayName: 'old-name', scopes: ['read'] }
  });

  const updatedCredential = await manager.updateCredential(credential.credentialId, {
    externalReference: 'account-2',
    metadata: { displayName: 'new-name' },
    secrets: [{ name: 'accessToken', value: 'access-2' }]
  });

  assert.equal(updatedCredential.credentialId, credential.credentialId);
  assert.equal(updatedCredential.externalReference, 'account-2');
  assert.equal(updatedCredential.metadata.toJSON().displayName, 'new-name');
  assert.deepEqual(updatedCredential.metadata.toJSON().scopes, ['read']);
  assert.equal(updatedCredential.secrets[0].value, 'access-2');
  assert.equal(updatedCredential.version, credential.version + 1);
  assert.equal(await store.load(credential.credentialId), updatedCredential);
});

test('CredentialManager applies public Credential patches without exposing or clearing unchanged secrets', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store, providerManager: createProviderManager(openAiFields) });
  const credential = await manager.register({
    providerKey: 'openai',
    externalReference: 'main',
    secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
    metadata: { displayName: 'Old name', description: 'Old description' }
  });

  const publicUpdate = await manager.updateCredential(credential.credentialId, {
    metadata: { displayName: 'New name' },
    secrets: [{ name: 'apiKey', value: '' }]
  }, { userUpdate: true });

  assert.equal(publicUpdate.providerKey, 'openai');
  assert.equal(publicUpdate.metadata.toJSON().displayName, 'New name');
  assert.equal(publicUpdate.secrets[0].value, 'sk-example-12345678901234567890');

  const replacement = await manager.updateCredential(credential.credentialId, {
    secrets: [{ name: 'apiKey', value: 'sk-replacement-12345678901234567890' }]
  }, { userUpdate: true });
  assert.equal(replacement.secrets[0].value, 'sk-replacement-12345678901234567890');

  await assert.rejects(
    () => manager.updateCredential(credential.credentialId, { providerKey: 'other' }, { userUpdate: true }),
    (error) => error.code === 'CREDENTIAL_FIELD_INVALID'
  );

  await assert.rejects(
    () => manager.updateCredential(credential.credentialId, {
      metadata: { custom: { redirectUri: 'https://credential-hub.example.com/callback' } }
    }, { userUpdate: true }),
    (error) => error.code === 'CREDENTIAL_FIELD_INVALID'
  );
});

test('CredentialManager rejects public updates that clear required provider fields', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store, providerManager: createProviderManager(openAiFields) });
  const credential = await manager.register({
    providerKey: 'openai',
    externalReference: 'main',
    secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
    metadata: { displayName: 'OpenAI Main' }
  });

  await assert.rejects(
    () => manager.updateCredential(credential.credentialId, {
      metadata: { displayName: '' }
    }, { userUpdate: true }),
    (error) => error.code === 'CREDENTIAL_FIELD_MISSING'
      && error.messageKey === 'credential.create.fieldMissing'
  );

  assert.equal((await store.load(credential.credentialId)).metadata.toJSON().displayName, 'OpenAI Main');
});

test('CredentialManager rolls back a secret update when secret versioning fails', async () => {
  const store = createMemoryStore();
  let failVersioning = false;
  const manager = new CredentialManager({
    credentialStore: store,
    providerManager: createProviderManager(openAiFields),
    secretVersioningService: {
      async recordCredentialVersion() {
        if (failVersioning) throw new Error('version store unavailable');
      }
    }
  });
  const credential = await manager.register({
    providerKey: 'openai',
    externalReference: 'main',
    secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
    metadata: { displayName: 'OpenAI Main' }
  });

  failVersioning = true;
  await assert.rejects(
    () => manager.updateCredential(credential.credentialId, {
      secrets: [{ name: 'apiKey', value: 'sk-replacement-12345678901234567890' }]
    }, { userUpdate: true }),
    (error) => error.code === 'CREDENTIAL_SECRET_VERSIONING_FAILED'
      && error.messageKey === 'credential.update.secretVersioningFailed'
  );

  const persisted = await store.load(credential.credentialId);
  assert.equal(persisted.version, credential.version);
  assert.equal(persisted.secrets[0].value, 'sk-example-12345678901234567890');
});

test('CredentialManager keeps an update available when secret-version rollback fails', async () => {
  const stored = new Map();
  const errors = [];
  let rollbackFails = false;
  const manager = new CredentialManager({
    credentialStore: {
      async save(credential) {
        if (rollbackFails && credential.version === 1) throw new Error('rollback unavailable');
        stored.set(credential.credentialId, credential);
      },
      async load(credentialId) { return stored.get(credentialId); }
    },
    providerManager: createProviderManager(openAiFields),
    secretVersioningService: {
      async recordCredentialVersion(credential) {
        if (credential.version > 1) throw new Error('version store unavailable');
      }
    },
    logger: { error(message, details) { errors.push({ message, details }); } }
  });
  const credential = await manager.register({
    providerKey: 'openai',
    externalReference: 'main',
    secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
    metadata: { displayName: 'OpenAI Main' }
  });

  rollbackFails = true;
  const updated = await manager.updateCredential(credential.credentialId, {
    secrets: [{ name: 'apiKey', value: 'sk-replacement-12345678901234567890' }]
  }, { userUpdate: true });

  assert.equal(updated.version, credential.version + 1);
  assert.equal((await stored.get(credential.credentialId)).secrets[0].value, 'sk-replacement-12345678901234567890');
  assert.equal(errors[0].details.rollbackCode, 'CREDENTIAL_ROLLBACK_FAILED');
});

test('CredentialManager rejects update for unknown credentials', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store });

  await assert.rejects(
    () => manager.updateCredential('missing', { metadata: { displayName: 'new-name' } }),
    /could not find credential 'missing'/
  );
});

test('CredentialManager deletes a credential through the CredentialStore', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store });

  const credential = await manager.register({
    providerKey: 'threads',
    externalReference: 'account-1',
    secrets: [{ name: 'accessToken', value: 'access' }]
  });

  const deletedCredential = await manager.deleteCredential(credential.credentialId);

  assert.equal(deletedCredential.credentialId, credential.credentialId);
  assert.equal(deletedCredential.lifecycleState, LifecycleState.DELETED);
  assert.equal(await store.load(credential.credentialId), undefined);
});

test('CredentialManager rejects delete for unknown credentials', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({ credentialStore: store });

  await assert.rejects(
    () => manager.deleteCredential('missing'),
    /could not find credential 'missing'/
  );
});

test('CredentialManager executes lifecycle actions and owns state transitions', async () => {
  const store = createMemoryStore();
  const providerManager = {
    async validateCredential(credential) {
      assert.equal(credential.providerKey, 'threads');
      return ProviderResult.success({ ok: true });
    }
  };
  const manager = new CredentialManager({ credentialStore: store, providerManager });
  const credential = await manager.register({
    providerKey: 'threads',
    secrets: [{ name: 'accessToken', value: 'access' }]
  });

  const result = await manager.validate(credential);

  assert.equal(result.success, true);
  assert.equal(result.data.credential.lifecycleState, LifecycleState.ACTIVE);
  assert.equal((await store.load(credential.credentialId)).lifecycleState, LifecycleState.ACTIVE);
});

test('TokenManager remains as compatibility facade for CredentialManager', async () => {
  const store = createMemoryStore();
  const credentialManager = new CredentialManager({ credentialStore: store });
  const tokenManager = new TokenManager({ credentialManager });

  const credential = await tokenManager.register({
    provider: 'threads',
    accountId: 'account-1',
    accessToken: 'access',
    refreshToken: 'refresh'
  });

  assert.equal(credential.providerKey, 'threads');
  assert.equal(credential.externalReference, 'account-1');
  assert.equal(credential.secrets.length, 2);
});


test('CredentialManager refreshes expired OAuth credentials through the canonical store', async () => {
  const refreshCalls = [];
  const saved = [];
  const credential = new Credential({
    credentialId: 'twitch-main', providerKey: 'twitch', credentialMethodKey: 'oauth2', lifecycleState: LifecycleState.ACTIVE,
    externalReference: 'main',
    secrets: [{ name: 'accessToken', value: 'old-access-token' }, { name: 'refreshToken', value: 'old-refresh-token' }],
    metadata: { expiresAt: new Date(Date.now() - 1_000).toISOString() }
  });
  const oauthResult = new OAuthResult({
    providerId: 'twitch:main',
    provider: 'twitch',
    accountId: 'main',
    accessToken: 'new-access-token',
    refreshToken: 'new-refresh-token',
    expiresAt: new Date(Date.now() + 3600_000).toISOString()
  });

  const manager = new CredentialManager({
    credentialStore: {
      async list() {
        return [credential];
      },
      async save(value) {
        saved.push(value);
      }
    },
    providerManager: {
      async refreshCredential(value) {
        refreshCalls.push(value);
        assert.equal(value.accessToken, 'old-access-token');
        assert.equal(value.refreshToken, 'old-refresh-token');
        return ProviderResult.success(oauthResult);
      }
    },
    config: {
      get() {
        return 14;
      }
    },
    logger: {
      info() {}
    }
  });

  const candidates = await manager.refreshExpiredCredentials();

  assert.deepEqual(candidates, [credential]);
  assert.equal(refreshCalls.length, 1);
  assert.equal(refreshCalls[0].credentialId, credential.credentialId);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].secrets.find((secret) => secret.name === 'accessToken').value, 'new-access-token');
  assert.equal(saved[0].secrets.find((secret) => secret.name === 'refreshToken').value, 'new-refresh-token');
});

test('CredentialManager refreshIfDue refreshes an active OAuth credential and returns the updated credential', async () => {
  const saved = [];
  const credential = new Credential({
    credentialId: 'resolve-refresh', credentialKey: 'resolve-refresh-key', providerKey: 'twitch', credentialMethodKey: 'oauth2', lifecycleState: LifecycleState.ACTIVE,
    secrets: [{ name: 'accessToken', value: 'old-access' }, { name: 'refreshToken', value: 'old-refresh' }],
    metadata: { expiresAt: new Date(Date.now() - 1_000).toISOString() }
  });
  const manager = new CredentialManager({
    credentialStore: { async load() { return credential; }, async save(value) { saved.push(value); } },
    providerManager: {
      async refreshCredential() {
        return ProviderResult.success(new OAuthResult({
          providerId: 'twitch:main', provider: 'twitch', accountId: 'main',
          accessToken: 'new-access', refreshToken: 'new-refresh',
          expiresAt: new Date(Date.now() + 3600_000).toISOString()
        }));
      }
    },
    config: { get() { return 14; } },
    logger: { info() {} }
  });

  const refreshed = await manager.refreshIfDue(credential);

  assert.equal(refreshed.secrets.find((secret) => secret.name === 'accessToken').value, 'new-access');
  assert.equal(refreshed.secrets.find((secret) => secret.name === 'refreshToken').value, 'new-refresh');
  assert.equal(saved.length, 1);
});

test('CredentialManager persists a rotated refresh token atomically with the access token', async () => {
  const saved = [];
  const credential = new Credential({
    credentialId: 'kick-main', providerKey: 'kick', credentialMethodKey: 'oauth2', lifecycleState: LifecycleState.ACTIVE,
    secrets: [{ name: 'accessToken', value: 'kick-old-access' }, { name: 'refreshToken', value: 'kick-old-refresh' }],
    metadata: { expiresAt: new Date(Date.now() - 1_000).toISOString() }
  });
  const manager = new CredentialManager({
    credentialStore: { async list() { return [credential]; }, async save(value) { saved.push(value); } },
    providerManager: { async refreshCredential() { return ProviderResult.success(new OAuthResult({
      providerId: 'kick:main', provider: 'kick', accountId: 'main', accessToken: 'kick-new-access', refreshToken: 'kick-new-refresh'
    })); } },
    config: { get() { return 14; } },
    logger: { info() {} }
  });

  await manager.refreshExpiredCredentials();
  assert.equal(saved.length, 1);
  assert.deepEqual(saved[0].secrets.map((secret) => [secret.name, secret.value]), [
    ['accessToken', 'kick-new-access'],
    ['refreshToken', 'kick-new-refresh']
  ]);
});

test('a successful refresh is returned by Consumer Resolve from the canonical store', async () => {
  const store = createMemoryStore();
  const credential = new Credential({
    credentialId: 'twitch-resolve', credentialKey: 'twitch-public-key', providerKey: 'twitch', credentialMethodKey: 'oauth2', lifecycleState: LifecycleState.ACTIVE,
    secrets: [{ name: 'accessToken', value: 'stale-access' }, { name: 'refreshToken', value: 'refresh' }],
    metadata: { expiresAt: new Date(Date.now() - 1_000).toISOString() }
  });
  await store.save(credential);
  const manager = new CredentialManager({
    credentialStore: store,
    providerManager: { async refreshCredential() { return ProviderResult.success(new OAuthResult({
      providerId: 'twitch:main', provider: 'twitch', accountId: 'main', accessToken: 'current-access', refreshToken: 'current-refresh'
    })); } },
    config: { get() { return 14; } },
    logger: { info() {} }
  });

  await manager.refreshExpiredCredentials();
  const consumer = new ConsumerCredentialService({
    credentialStore: store,
    consumerGrantService: { async findGrant() { return { secretNames: ['accessToken'] }; } },
    providerRegistry: { get() { return {
      getCredentialMethod() { return { credentialFields: [{ key: 'accessToken', secret: true }] }; },
      getProviderMethodBinding() { return { methodKey: 'oauth2' }; }
    }; } }
  });

  const resolved = await consumer.resolve({ consumerId: 'consumer-1', credentialKey: credential.credentialKey, secretNames: ['accessToken'] });
  assert.deepEqual(resolved.secrets, { accessToken: 'current-access' });
});

test('CredentialManager does not partially persist when the provider refresh fails', async () => {
  let saveCount = 0;
  const credential = new Credential({
    credentialId: 'twitch-failure', providerKey: 'twitch', credentialMethodKey: 'oauth2', lifecycleState: LifecycleState.ACTIVE,
    secrets: [{ name: 'accessToken', value: 'unchanged-access' }, { name: 'refreshToken', value: 'unchanged-refresh' }],
    metadata: { expiresAt: new Date(Date.now() - 1_000).toISOString() }
  });
  const manager = new CredentialManager({
    credentialStore: { async list() { return [credential]; }, async save() { saveCount += 1; } },
    providerManager: { async refreshCredential() { return ProviderResult.failure(new Error('provider unavailable')); } },
    config: { get() { return 14; } },
    logger: { info() {} }
  });

  await assert.rejects(() => manager.refreshExpiredCredentials(), /provider unavailable/);
  assert.equal(saveCount, 0);
});

test('canonical credential persistence survives a manager/store restart', async () => {
  let data = null;
  const jsonStore = {
    async exists() { return data !== null; },
    async load() { return structuredClone(data); },
    async save(_path, value) { data = structuredClone(value); }
  };
  const firstStore = new CredentialCollectionStoreAdapter({ jsonStore, basePath: '/data' });
  const credential = await firstStore.save({
    credentialId: 'twitch-restart', providerKey: 'twitch', credentialMethodKey: 'oauth2',
    secrets: [{ name: 'accessToken', value: 'persisted-access' }, { name: 'refreshToken', value: 'persisted-refresh' }]
  });
  const restartedStore = new CredentialCollectionStoreAdapter({ jsonStore, basePath: '/data' });
  const loaded = await restartedStore.load(credential.credentialId);
  assert.equal(loaded.secrets.find((secret) => secret.name === 'accessToken').value, 'persisted-access');
  assert.equal(loaded.secrets.find((secret) => secret.name === 'refreshToken').value, 'persisted-refresh');
});

test('CredentialManager owns OAuth import orchestration during MS7 migration', async () => {
  const oauthResult = new OAuthResult({
    providerId: 'threads:main',
    provider: 'threads',
    accountId: 'main',
    accessToken: 'access-token'
  });

  const manager = new CredentialManager({
    credentialStore: {
      async load() { const error = new Error('missing'); error.code = 'NOT_FOUND'; throw error; },
      async save(credential) { this.saved = credential; }
    },
    providerManager: {},
  });

  const result = await manager.importCredential(oauthResult);

  assert.equal(result.credentialId, 'threads:main');
  assert.equal(result.secrets.find((secret) => secret.name === 'accessToken').value, 'access-token');
});

test('CredentialManager refresh workflow logs public Credential terminology', async () => {
  const infoEntries = [];
  const manager = new CredentialManager({
    credentialStore: {
      async list() {
        return [];
      }
    },
    providerManager: {},
    tokenLifecycleService: {},
    config: {
      get() {
        return 14;
      }
    },
    logger: {
      info(message) {
        infoEntries.push(message);
      }
    }
  });

  await manager.refreshExpiredCredentials();

  assert.deepEqual(infoEntries, [
    'Checking 0 credential(s) for refresh',
    'Refresh candidates processed: 0'
  ]);
  assert.equal(infoEntries.some((message) => /token/i.test(message)), false);
});

test('CredentialManager records secret versions when secrets are registered and updated', async () => {
  const store = createMemoryStore();
  const recorded = [];
  const manager = new CredentialManager({
    credentialStore: store,
    secretVersioningService: {
      async recordCredentialVersion(credential, options) {
        recorded.push({ credential, options });
      }
    }
  });

  const credential = await manager.register({
    providerKey: 'threads',
    externalReference: 'account-1',
    secrets: [{ name: 'accessToken', value: 'access-1' }]
  });

  await manager.updateCredential(credential.credentialId, {
    secrets: [{ name: 'accessToken', value: 'access-2' }]
  }, { versionReason: 'manual-update', createdBy: 'admin' });

  assert.equal(recorded.length, 2);
  assert.equal(recorded[0].options.reason, 'initial-import');
  assert.equal(recorded[1].options.reason, 'manual-update');
  assert.equal(recorded[1].options.createdBy, 'admin');
  assert.equal(recorded[1].credential.secrets[0].value, 'access-2');
});

test('CredentialManager removes a newly saved credential when initial secret versioning fails', async () => {
  const store = createMemoryStore();
  const manager = new CredentialManager({
    credentialStore: store,
    providerManager: createProviderManager(openAiFields),
    secretVersioningService: {
      async recordCredentialVersion() {
        throw new Error('version store unavailable');
      }
    }
  });

  await assert.rejects(
    () => manager.register({
      credentialId: 'openai-version-failure',
      providerKey: 'openai',
      externalReference: 'main',
      secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
      metadata: { displayName: 'OpenAI Main' }
    }),
    (error) => error.code === 'CREDENTIAL_SECRET_VERSIONING_FAILED'
      && error.messageKey === 'credential.create.secretVersioningFailed'
  );

  assert.equal(await store.load('openai-version-failure'), undefined);
  assert.deepEqual(await store.list(), []);
});

test('CredentialManager returns the persisted credential when versioning and compensation both fail', async () => {
  const stored = new Map();
  const errors = [];
  const manager = new CredentialManager({
    credentialStore: {
      async save(credential) { stored.set(credential.credentialId, credential); },
      async delete() { throw new Error('rollback unavailable'); }
    },
    providerManager: createProviderManager(openAiFields),
    secretVersioningService: {
      async recordCredentialVersion() { throw new Error('version store unavailable'); }
    },
    logger: { error(message, details) { errors.push({ message, details }); } }
  });

  const credential = await manager.register({
    credentialId: 'openai-degraded-versioning',
    providerKey: 'openai',
    externalReference: 'main',
    secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
    metadata: { displayName: 'OpenAI Main' }
  });

  assert.equal(credential.credentialId, 'openai-degraded-versioning');
  assert.equal(stored.has(credential.credentialId), true);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].details.credentialId, credential.credentialId);
});

test('CredentialManager returns the persisted credential when compensation deletes nothing', async () => {
  const stored = new Map();
  const errors = [];
  const manager = new CredentialManager({
    credentialStore: {
      async save(credential) { stored.set(credential.credentialId, credential); },
      async delete() { return false; }
    },
    providerManager: createProviderManager(openAiFields),
    secretVersioningService: {
      async recordCredentialVersion() { throw new Error('version store unavailable'); }
    },
    logger: { error(message, details) { errors.push({ message, details }); } }
  });

  const credential = await manager.register({
    credentialId: 'openai-unconfirmed-rollback',
    providerKey: 'openai',
    externalReference: 'main',
    secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }],
    metadata: { displayName: 'OpenAI Main' }
  });

  assert.equal(credential.credentialId, 'openai-unconfirmed-rollback');
  assert.equal(stored.has(credential.credentialId), true);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].details.credentialId, credential.credentialId);
  assert.equal(errors[0].details.rollbackCode, 'CREDENTIAL_ROLLBACK_NOT_CONFIRMED');
});
