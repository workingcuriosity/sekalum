import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialStore } from '../../src/storage/credential-store.js';
import { LegacyTokenCredentialStoreAdapter } from '../../src/storage/legacy-token-credential-store-adapter.js';
import { Credential } from '../../src/models/credential.js';
import { TokenRecord } from '../../src/models/token-record.js';

function createTokenRecord(overrides = {}) {
  return new TokenRecord({
    providerId: 'threads:main',
    provider: 'threads',
    accountId: 'main',
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    ...overrides
  });
}

test('CredentialStore loads legacy TokenRecord as Credential', async () => {
  const tokenRecord = createTokenRecord();
  const store = new CredentialStore({
    tokenStore: {
      async load(providerId) {
        assert.equal(providerId, 'threads:main');
        return tokenRecord;
      }
    }
  });

  const credential = await store.load('threads:main');

  assert.equal(credential instanceof Credential, true);
  assert.equal(credential.credentialId, 'threads:main');
  assert.equal(credential.credentialKey, tokenRecord.credentialKey);
  assert.equal(credential.providerKey, 'threads');
  assert.equal(credential.externalReference, 'main');
  assert.equal(credential.secrets.length, 2);
});

test('CredentialStore saves Credential through legacy TokenStore', async () => {
  const saved = [];
  const store = new CredentialStore({
    tokenStore: {
      async save(tokenRecord) {
        saved.push(tokenRecord);
      }
    }
  });

  await store.save({
    credentialId: 'threads:main',
    providerKey: 'threads',
    externalReference: 'main',
    secrets: [
      { name: 'accessToken', value: 'access-token' },
      { name: 'refreshToken', value: 'refresh-token' }
    ],
    metadata: {
      expiresAt: '2026-07-03T00:00:00.000Z',
      scopes: ['threads_basic']
    }
  });

  assert.equal(saved.length, 1);
  assert.equal(saved[0] instanceof TokenRecord, true);
  assert.equal(saved[0].providerId, 'threads:main');
  assert.equal(typeof saved[0].credentialKey, 'string');
  assert.equal(saved[0].provider, 'threads');
  assert.equal(saved[0].accountId, 'main');
  assert.equal(saved[0].accessToken, 'access-token');
});

test('TokenRecord rejects invalid public credentialKey values', () => {
  for (const credentialKey of [undefined, null, '', '   ', 42, {}, []]) {
    assert.throws(
      () => createTokenRecord({ credentialKey }),
      /TokenRecord: 'credentialKey' is required/
    );
  }
});

test('CredentialStore exposes legacy tokens only for MS7 migration workflows', async () => {
  const tokens = [createTokenRecord()];
  const store = new CredentialStore({
    tokenStore: {
      async list() {
        return tokens;
      }
    }
  });

  assert.deepEqual(await store.listLegacyTokens(), tokens);
});


test('CredentialStore delegates to a generic storage adapter without legacy token knowledge', async () => {
  const calls = [];
  const credential = Credential.from({
    credentialId: 'credential-1',
    providerKey: 'threads',
    secrets: [{ name: 'accessToken', value: 'access-token' }]
  });
  const store = new CredentialStore({
    storageAdapter: {
      async load(credentialId) {
        calls.push(['load', credentialId]);
        return credential;
      },
      async save(input) {
        calls.push(['save', input.credentialId]);
      },
      async delete(credentialId) {
        calls.push(['delete', credentialId]);
        return true;
      },
      async exists(credentialId) {
        calls.push(['exists', credentialId]);
        return true;
      },
      async list() {
        calls.push(['list']);
        return [credential];
      }
    }
  });

  assert.equal(await store.load('credential-1'), credential);
  await store.save(credential);
  assert.equal(await store.delete('credential-1'), true);
  assert.equal(await store.exists('credential-1'), true);
  assert.deepEqual(await store.list(), [credential]);
  assert.deepEqual(calls, [
    ['load', 'credential-1'],
    ['save', 'credential-1'],
    ['delete', 'credential-1'],
    ['exists', 'credential-1'],
    ['list']
  ]);
});

test('CredentialStore rejects legacy token listing without a legacy adapter', async () => {
  const store = new CredentialStore({
    storageAdapter: {
      async load() {},
      async save() {},
      async delete() {},
      async exists() {},
      async list() { return []; }
    }
  });

  await assert.rejects(
    () => store.listLegacyTokens(),
    /requires a legacy token storage adapter/
  );
});

test('LegacyTokenCredentialStoreAdapter converts missing legacy token files to credential NOT_FOUND', async () => {
  const store = new CredentialStore({
    storageAdapter: new LegacyTokenCredentialStoreAdapter({
      tokenStore: {
        async load() {
          const error = new Error('missing token file');
          error.code = 'ENOENT';
          throw error;
        }
      }
    })
  });

  await assert.rejects(
    () => store.load('threads:missing'),
    (error) => error.code === 'NOT_FOUND' && error.message.includes("Credential 'threads:missing' not found")
  );
});
