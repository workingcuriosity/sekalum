import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { ApiTokenService, ApiTokenServiceConstants } from '../../src/services/api-token-service.js';
import { ApiTokenStore } from '../../src/storage/api-token-store.js';
import { JsonStore } from '../../src/storage/json-store.js';

class InMemoryApiTokenStore {
  constructor() {
    this.tokens = new Map();
    this.failNextSave = false;
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
    if (this.failNextSave) {
      this.failNextSave = false;
      throw new Error('simulated token persistence failure');
    }
    this.tokens.set(token.id, token);
    return token;
  }

  async findByPrefix(tokenPrefix) {
    return [...this.tokens.values()].filter((token) => token.tokenPrefix === tokenPrefix);
  }
}

class SnapshotBlockingApiTokenStore extends InMemoryApiTokenStore {
  constructor() {
    super();
    this.blockNextLookup = false;
    this.lookupEntered = new Promise((resolve) => { this.resolveLookupEntered = resolve; });
    this.releaseLookup = new Promise((resolve) => { this.resolveLookup = resolve; });
  }

  async findByPrefix(tokenPrefix) {
    const snapshot = await super.findByPrefix(tokenPrefix);
    if (this.blockNextLookup) {
      this.blockNextLookup = false;
      this.resolveLookupEntered();
      await this.releaseLookup;
    }
    return snapshot;
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

test('ApiTokenService enforces issuer scope containment and same-principal delegation in the service layer', async () => {
  const { service } = createService();
  const issuer = { userId: 'issuer-user', scopes: ['api-tokens:manage'] };

  await assert.rejects(
    () => service.createToken({
      name: 'Escalated consumer', userId: 'issuer-user',
      scopes: ['api-tokens:manage', 'credentials:consume'],
      createdBy: 'issuer-user', issuer
    }),
    { code: 'API_TOKEN_DELEGATION_DENIED', statusCode: 403 }
  );

  await assert.rejects(
    () => service.createToken({
      name: 'Cross-principal token', userId: 'other-user',
      scopes: ['api-tokens:manage'], createdBy: 'issuer-user', issuer
    }),
    { code: 'API_TOKEN_DELEGATION_DENIED', statusCode: 403 }
  );

  const valid = await service.createToken({
    name: 'Same-principal subset', userId: 'issuer-user',
    scopes: ['api-tokens:manage'], createdBy: 'issuer-user', issuer
  });
  assert.deepEqual(valid.publicToken.scopes, ['api-tokens:manage']);
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
  assert.equal(auditEntries[0].actorType, 'user');
  assert.equal(auditEntries[0].targetType, 'api-token');
  assert.equal(auditEntries[0].targetId, created.apiToken.id);
  assert.equal(auditEntries[0].details.tokenPrefix, created.apiToken.tokenPrefix);
  assert.equal(Object.hasOwn(auditEntries[0].details, 'token'), false);
  assert.equal(Object.hasOwn(auditEntries[0].details, 'tokenHash'), false);
  assert.equal(auditEntries[1].actorType, 'api-token');
  assert.equal(auditEntries[1].userId, null);
  assert.equal(auditEntries[1].apiTokenId, created.apiToken.id);
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
  assert.equal(failureEntries[0].actorType, 'service');
  assert.equal(failureEntries[1].actorType, 'api-token');
  assert.equal(failureEntries[2].actorType, 'api-token');
  assert.equal(failureEntries.every((entry) => entry.targetType === 'api-token'), true);
});

test('ApiTokenService makes repeated revocation idempotent and records the administrator', async () => {
  const auditEntries = [];
  const store = new InMemoryApiTokenStore();
  const service = new ApiTokenService({
    store,
    auditLogService: { record: async (entry) => auditEntries.push(entry) },
    clock: () => new Date('2026-07-09T08:00:00.000Z'),
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, 9)
  });
  const created = await service.createToken({ name: 'Idempotent token', userId: 'owner', createdBy: 'creator' });

  const first = await service.revokeToken(created.apiToken.id, { revokedBy: 'admin-user' });
  const second = await service.revokeToken(created.apiToken.id, { revokedBy: 'admin-user' });

  assert.equal(first.status, 'revoked');
  assert.deepEqual(second, first);
  assert.equal(auditEntries.find((entry) => entry.action === 'api-token.revoked').userId, 'admin-user');
  assert.equal(auditEntries.some((entry) => entry.action === 'api-token.revoke.noop'), true);
  assert.equal(auditEntries.every((entry) => !JSON.stringify(entry).includes(created.token)), true);
});

test('ApiTokenService serializes authentication and revocation around a stale snapshot', async () => {
  const store = new SnapshotBlockingApiTokenStore();
  const service = new ApiTokenService({
    store,
    clock: () => new Date('2026-07-09T08:00:00.000Z'),
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, 11)
  });
  const created = await service.createToken({ name: 'Race token', userId: 'owner', createdBy: 'admin' });

  store.blockNextLookup = true;
  const authentication = service.authenticate(created.token);
  await store.lookupEntered;

  const revocation = service.revokeToken(created.apiToken.id, {
    revokedAt: '2026-07-10T08:00:00.000Z',
    revokedBy: 'admin'
  });

  store.resolveLookup();

  const authenticationResult = await authentication;
  const revocationResult = await revocation;
  const stored = await store.load(created.apiToken.id);

  assert.equal(authenticationResult.authenticated, false);
  assert.equal(authenticationResult.reason, 'revoked');
  assert.equal(revocationResult.status, 'revoked');
  assert.equal(stored.revokedAt.toISOString(), '2026-07-10T08:00:00.000Z');
  assert.equal((await service.authenticate(created.token)).authenticated, false);
});

test('ApiTokenService recovers its mutation queue after an authentication write failure', async () => {
  const { store, service } = createService();
  const created = await service.createToken({ name: 'Recovery token', userId: 'owner', createdBy: 'admin' });

  store.failNextSave = true;
  await assert.rejects(() => service.authenticate(created.token), /simulated token persistence failure/);

  const revoked = await service.revokeToken(created.apiToken.id, {
    revokedAt: '2026-07-10T08:00:00.000Z',
    revokedBy: 'admin'
  });

  assert.equal(revoked.status, 'revoked');
  assert.equal((await service.authenticate(created.token)).authenticated, false);
});

test('ApiTokenService keeps revocation terminal across concurrent token use', async () => {
  const { store, service } = createService();
  const created = await service.createToken({ name: 'Concurrent token', userId: 'owner', createdBy: 'admin' });

  const operations = [
    ...Array.from({ length: 10 }, () => service.authenticate(created.token)),
    service.revokeToken(created.apiToken.id, {
      revokedAt: '2026-07-10T08:00:00.000Z',
      revokedBy: 'admin'
    })
  ];
  await Promise.all(operations);

  const stored = await store.load(created.apiToken.id);
  assert.equal(stored.revokedAt.toISOString(), '2026-07-10T08:00:00.000Z');
  assert.equal((await service.authenticate(created.token)).authenticated, false);
});

test('ApiTokenService preserves terminal revocation through the real file-backed store', async () => {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-hub-api-token-service-'));
  try {
    const store = new ApiTokenStore({ jsonStore: new JsonStore(), basePath });
    const service = new ApiTokenService({
      store,
      clock: () => new Date('2026-07-09T08:00:00.000Z'),
      randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, 12)
    });
    const created = await service.createToken({ name: 'File token', userId: 'owner', createdBy: 'admin' });

    await Promise.all([
      service.authenticate(created.token),
      service.revokeToken(created.apiToken.id, {
        revokedAt: '2026-07-10T08:00:00.000Z',
        revokedBy: 'admin'
      })
    ]);

    const persisted = await store.load(created.apiToken.id);
    assert.equal(persisted.revokedAt.toISOString(), '2026-07-10T08:00:00.000Z');
    assert.equal((await service.authenticate(created.token)).authenticated, false);
  } finally {
    await fs.rm(basePath, { recursive: true, force: true });
  }
});
