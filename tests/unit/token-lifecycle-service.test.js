import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthResult } from '../../src/models/oauth-result.js';
import { TokenRecord } from '../../src/models/token-record.js';
import { TokenLifecycleService } from '../../src/services/token-lifecycle-service.js';

function createTokenRecord(overrides = {}) {
  return new TokenRecord({
    id: 'token-id',
    credentialKey: 'public-key',
    providerId: 'google:main',
    provider: 'google',
    accountId: 'main',
    accessToken: 'old-access-token',
    refreshToken: 'old-refresh-token',
    ...overrides
  });
}

function createOAuthResult(overrides = {}) {
  return new OAuthResult({
    providerId: 'google:main',
    provider: 'google',
    accountId: 'main',
    accessToken: 'new-access-token',
    refreshToken: 'new-refresh-token',
    ...overrides
  });
}

function createService({ existingToken = null } = {}) {
  const saved = [];
  const backups = [];
  const tokenStore = {
    async exists() { return existingToken !== null; },
    async load() { return existingToken; },
    async save(token) { saved.push(token); }
  };
  const service = new TokenLifecycleService({
    tokenStore,
    backupStore: { async createBackup(token) { backups.push(token); } },
    logger: { info() {} }
  });
  return { service, saved, backups };
}

test('TokenLifecycleService refresh preserves credential identity while updating tokens', async () => {
  const existingToken = createTokenRecord();
  const { service, saved } = createService({ existingToken });

  const refreshed = await service.refresh(existingToken, createOAuthResult());
  const refreshedAgain = await service.refresh(refreshed, createOAuthResult({ accessToken: 'second-access-token' }));

  assert.equal(refreshed.id, existingToken.id);
  assert.equal(refreshed.credentialKey, existingToken.credentialKey);
  assert.equal(refreshed.accessToken, 'new-access-token');
  assert.equal(saved[0].credentialKey, existingToken.credentialKey);
  assert.equal(refreshedAgain.id, existingToken.id);
  assert.equal(refreshedAgain.credentialKey, existingToken.credentialKey);
  assert.equal(refreshedAgain.accessToken, 'second-access-token');
});

test('TokenLifecycleService re-import preserves an existing credential identity', async () => {
  const existingToken = createTokenRecord();
  const { service, saved, backups } = createService({ existingToken });

  const imported = await service.import(createOAuthResult());

  assert.equal(imported.id, existingToken.id);
  assert.equal(imported.credentialKey, existingToken.credentialKey);
  assert.equal(saved[0].credentialKey, existingToken.credentialKey);
  assert.equal(backups[0], existingToken);
});

test('TokenLifecycleService first import generates a new credential identity', async () => {
  const { service, saved } = createService();

  const imported = await service.import(createOAuthResult());

  assert.match(imported.credentialKey, /^[0-9a-f-]{36}$/);
  assert.equal(saved[0].credentialKey, imported.credentialKey);
});
