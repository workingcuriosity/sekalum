import test from 'node:test';
import assert from 'node:assert/strict';

import { ApiTokenService, ApiTokenServiceConstants } from '../../src/services/api-token-service.js';

class InMemoryApiTokenStore {
  constructor() {
    this.tokens = new Map();
  }

  async list() {
    return [...this.tokens.values()];
  }

  async load(tokenId) {
    const token = this.tokens.get(tokenId);
    if (!token) {
      const error = new Error(`API token '${tokenId}' not found`);
      error.code = 'NOT_FOUND';
      throw error;
    }
    return token;
  }

  async save(token) {
    this.tokens.set(token.id, token);
    return token;
  }

  async findByPrefix(tokenPrefix) {
    return [...this.tokens.values()].filter((token) => token.tokenPrefix === tokenPrefix);
  }
}

function createService({ now = '2026-07-09T08:00:00.000Z', randomBytes } = {}) {
  const store = new InMemoryApiTokenStore();
  const service = new ApiTokenService({
    store,
    clock: () => new Date(now),
    randomBytes: randomBytes ?? (() => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, 7))
  });
  return { store, service };
}

test('ApiTokenService creates a plaintext token once and stores only the hash', async () => {
  const { store, service } = createService();

  const result = await service.createToken({
    name: 'CI token',
    userId: 'automation-user',
    scopes: ['credentials:read', 'credentials:read'],
    expiresAt: '2026-08-09T08:00:00.000Z',
    createdBy: 'admin-user'
  });

  assert.match(result.token, /^cht_/);
  assert.equal(result.apiToken.tokenHash.startsWith('sha256:'), true);
  assert.equal(result.apiToken.tokenHash.includes(result.token), false);
  assert.equal(result.apiToken.tokenPrefix, result.token.slice(0, 20));
  assert.deepEqual(result.publicToken.scopes, ['credentials:read']);
  assert.equal(Object.hasOwn(result.publicToken, 'tokenHash'), false);
  assert.equal(Object.hasOwn(result.publicToken, 'token'), false);
  assert.equal((await store.list()).length, 1);
});

test('ApiTokenService authenticates an active token and updates lastUsedAt', async () => {
  const { store, service } = createService({ now: '2026-07-09T08:00:00.000Z' });
  const created = await service.createToken({
    name: 'Integration token',
    userId: 'integration-user',
    scopes: ['credentials:read'],
    expiresAt: '2026-08-09T08:00:00.000Z',
    createdBy: 'admin-user'
  });

  const result = await service.authenticate(created.token);
  const stored = await store.load(created.apiToken.id);

  assert.equal(result.authenticated, true);
  assert.equal(result.userId, 'integration-user');
  assert.deepEqual(result.scopes, ['credentials:read']);
  assert.equal(result.apiToken.lastUsedAt, '2026-07-09T08:00:00.000Z');
  assert.equal(stored.lastUsedAt.toISOString(), '2026-07-09T08:00:00.000Z');
});

test('ApiTokenService rejects malformed or unknown bearer tokens', async () => {
  const { service } = createService();

  assert.deepEqual(await service.authenticate('not-a-token'), {
    authenticated: false,
    reason: 'invalid-format',
    apiToken: null
  });

  const missing = await service.authenticate('cht_unknown-token-value');
  assert.equal(missing.authenticated, false);
  assert.equal(missing.reason, 'not-found');
});

test('ApiTokenService rejects revoked tokens', async () => {
  const { service } = createService();
  const created = await service.createToken({
    name: 'Revoked token',
    userId: 'automation-user',
    scopes: ['credentials:read'],
    createdBy: 'admin-user'
  });

  await service.revokeToken(created.apiToken.id, { revokedAt: '2026-07-10T08:00:00.000Z' });
  const result = await service.authenticate(created.token);

  assert.equal(result.authenticated, false);
  assert.equal(result.reason, 'revoked');
  assert.equal(result.apiToken.status, 'revoked');
  assert.equal(result.apiToken.revokedAt, '2026-07-10T08:00:00.000Z');
});

test('ApiTokenService rejects expired tokens', async () => {
  const { service } = createService({ now: '2026-07-09T08:00:00.000Z' });
  const created = await service.createToken({
    name: 'Expired token',
    userId: 'automation-user',
    scopes: ['credentials:read'],
    expiresAt: '2026-07-01T08:00:00.000Z',
    createdBy: 'admin-user'
  });

  const result = await service.authenticate(created.token);

  assert.equal(result.authenticated, false);
  assert.equal(result.reason, 'expired');
  assert.equal(result.apiToken.status, 'expired');
});

test('ApiTokenService lists and loads public token metadata without hashes', async () => {
  const { service } = createService();
  const created = await service.createToken({
    name: 'Read-only token',
    userId: 'automation-user',
    scopes: ['credentials:read'],
    createdBy: 'admin-user'
  });

  const listed = await service.listTokens();
  const loaded = await service.getToken(created.apiToken.id);

  assert.equal(listed.length, 1);
  assert.equal(listed[0].name, 'Read-only token');
  assert.equal(loaded.id, created.apiToken.id);
  assert.equal(Object.hasOwn(listed[0], 'tokenHash'), false);
  assert.equal(Object.hasOwn(loaded, 'tokenHash'), false);
});

test('ApiTokenService validates createToken input', async () => {
  const { service } = createService();

  await assert.rejects(
    () => service.createToken({ name: '', userId: 'user', createdBy: 'admin' }),
    /name/
  );
  await assert.rejects(
    () => service.createToken({ name: 'Token', userId: 'user', createdBy: 'admin', scopes: 'credentials:read' }),
    /scopes/
  );
  await assert.rejects(
    () => service.createToken({ name: 'Token', userId: 'user', createdBy: 'admin', expiresAt: 'not-a-date' }),
    /expiresAt/
  );
});

test('ApiTokenService records audit events for create, use, and revoke', async () => {
  const auditEntries = [];
  const auditLogService = { record: async (entry) => auditEntries.push(entry) };
  const store = new InMemoryApiTokenStore();
  const service = new ApiTokenService({
    store,
    auditLogService,
    clock: () => new Date('2026-07-09T08:00:00.000Z'),
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, 8)
  });

  const created = await service.createToken({
    name: 'Audited token',
    userId: 'integration-user',
    scopes: ['credentials:read'],
    createdBy: 'admin-user'
  });

  await service.authenticate(created.token);
  await service.revokeToken(created.apiToken.id);

  assert.deepEqual(auditEntries.map((entry) => entry.action), [
    'api-token.created',
    'api-token.used',
    'api-token.revoked'
  ]);
  assert.equal(auditEntries[0].userId, 'admin-user');
  assert.equal(auditEntries[0].targetType, 'api-token');
  assert.equal(auditEntries[0].targetId, created.apiToken.id);
  assert.equal(auditEntries[0].details.tokenPrefix, created.apiToken.tokenPrefix);
  assert.equal(Object.hasOwn(auditEntries[0].details, 'token'), false);
  assert.equal(Object.hasOwn(auditEntries[0].details, 'tokenHash'), false);
  assert.equal(auditEntries[1].userId, 'integration-user');
  assert.equal(auditEntries[2].result, 'success');
});

test('ApiTokenService records audit failures for invalid, revoked, and expired tokens', async () => {
  const auditEntries = [];
  const auditLogService = { record: async (entry) => auditEntries.push(entry) };
  let seed = 10;
  const store = new InMemoryApiTokenStore();
  const service = new ApiTokenService({
    store,
    auditLogService,
    clock: () => new Date('2026-07-09T08:00:00.000Z'),
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, seed++)
  });

  await service.authenticate('invalid-token');

  const revoked = await service.createToken({
    name: 'Revoked audited token',
    userId: 'automation-user',
    scopes: ['credentials:read'],
    createdBy: 'admin-user'
  });
  await service.revokeToken(revoked.apiToken.id);
  await service.authenticate(revoked.token);

  const expired = await service.createToken({
    name: 'Expired audited token',
    userId: 'automation-user',
    scopes: ['credentials:read'],
    expiresAt: '2026-07-01T08:00:00.000Z',
    createdBy: 'admin-user'
  });
  await service.authenticate(expired.token);

  const failureEntries = auditEntries.filter((entry) => entry.result === 'failure');
  assert.deepEqual(failureEntries.map((entry) => entry.action), [
    'api-token.invalid',
    'api-token.invalid',
    'api-token.expired'
  ]);
  assert.equal(failureEntries[0].details.reason, 'invalid-format');
  assert.equal(failureEntries[1].details.reason, 'revoked');
  assert.equal(failureEntries[2].details.reason, 'expired');
  assert.equal(failureEntries.every((entry) => entry.targetType === 'api-token'), true);
});
