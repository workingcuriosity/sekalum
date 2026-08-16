import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { ApiToken } from '../../src/models/api-token.js';
import { ApiTokenStore } from '../../src/storage/api-token-store.js';
import { JsonStore } from '../../src/storage/json-store.js';

async function createTempStore() {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-hub-api-token-store-'));
  return {
    basePath,
    store: new ApiTokenStore({ jsonStore: new JsonStore(), basePath })
  };
}

function createToken(overrides = {}) {
  return new ApiToken({
    id: 'api-token-1',
    name: 'CI token',
    tokenPrefix: 'cht_abcd1234',
    tokenHash: 'sha256:token-hash',
    userId: 'automation-user',
    scopes: ['credentials:read'],
    createdAt: '2026-07-09T08:00:00.000Z',
    expiresAt: '2026-08-09T08:00:00.000Z',
    createdBy: 'admin-user',
    ...overrides
  });
}

test('ApiTokenStore starts with an empty token list', async () => {
  const { store } = await createTempStore();

  assert.deepEqual(await store.list(), []);
  assert.equal(await store.exists('api-token-1'), false);
});

test('ApiTokenStore saves and loads API tokens with internal hash intact', async () => {
  const { store } = await createTempStore();
  const token = createToken();

  await store.save(token);
  const loaded = await store.load('api-token-1');

  assert.equal(loaded instanceof ApiToken, true);
  assert.equal(loaded.id, 'api-token-1');
  assert.equal(loaded.tokenHash, 'sha256:token-hash');
  assert.equal(loaded.toPublicJSON().tokenHash, undefined);
  assert.equal(await store.exists('api-token-1'), true);
});

test('ApiTokenStore upserts existing tokens immutably', async () => {
  const { store } = await createTempStore();
  const token = createToken();

  await store.save(token);
  await store.save(token.withLastUsedAt('2026-07-10T08:00:00.000Z'));

  const tokens = await store.list();
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].lastUsedAt.toISOString(), '2026-07-10T08:00:00.000Z');
  assert.equal(tokens[0].version, 2);
});

test('ApiTokenStore finds tokens by prefix for future bearer authentication', async () => {
  const { store } = await createTempStore();

  await store.save(createToken());
  await store.save(createToken({ id: 'api-token-2', tokenPrefix: 'cht_wxyz9876', tokenHash: 'sha256:other-hash' }));

  const matches = await store.findByPrefix('cht_abcd1234');

  assert.equal(matches.length, 1);
  assert.equal(matches[0].id, 'api-token-1');
});

test('ApiTokenStore deletes existing tokens and reports missing tokens', async () => {
  const { store } = await createTempStore();

  await store.save(createToken());

  assert.equal(await store.delete('api-token-1'), true);
  assert.equal(await store.delete('api-token-1'), false);
  await assert.rejects(
    () => store.load('api-token-1'),
    (error) => error.code === 'NOT_FOUND' && error.message.includes("API token 'api-token-1' not found")
  );
});

test('ApiTokenStore rejects malformed persisted token collections', async () => {
  const { basePath, store } = await createTempStore();
  await fs.writeFile(path.join(basePath, 'api-tokens.json'), JSON.stringify({ tokens: {} }), 'utf8');

  await assert.rejects(() => store.list(), /tokens must be an array/);
});
