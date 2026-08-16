import test from 'node:test';
import assert from 'node:assert/strict';

import { ApiToken } from '../../src/models/api-token.js';
import { ApiTokenStatus, isApiTokenStatus } from '../../src/models/api-token-status.js';

const futureExpiry = () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

const baseTokenData = {
  id: 'api-token-1',
  name: 'CI deploy',
  tokenPrefix: 'cht_abcd1234',
  tokenHash: 'sha256:hash-value',
  userId: 'automation-user',
  scopes: ['credentials:read', 'credentials:write', 'credentials:read'],
  createdAt: '2026-07-09T08:00:00.000Z',
  expiresAt: futureExpiry(),
  createdBy: 'admin-user'
};

test('ApiToken stores metadata without plaintext token', () => {
  const token = new ApiToken(baseTokenData);

  assert.equal(token.id, 'api-token-1');
  assert.equal(token.name, 'CI deploy');
  assert.equal(token.tokenPrefix, 'cht_abcd1234');
  assert.equal(token.tokenHash, 'sha256:hash-value');
  assert.equal(token.userId, 'automation-user');
  assert.deepEqual(token.scopes, ['credentials:read', 'credentials:write']);
  assert.equal(token.status, ApiTokenStatus.ACTIVE);
  assert.equal(Object.isFrozen(token), true);
  assert.equal(Object.hasOwn(token, 'token'), false);
  assert.equal(Object.hasOwn(token.toPublicJSON(), 'tokenHash'), false);
  assert.equal(Object.hasOwn(token.toPublicJSON(), 'token'), false);
});

test('ApiTokenStatus exposes only supported API token lifecycle states', () => {
  assert.equal(isApiTokenStatus(ApiTokenStatus.ACTIVE), true);
  assert.equal(isApiTokenStatus(ApiTokenStatus.EXPIRED), true);
  assert.equal(isApiTokenStatus(ApiTokenStatus.REVOKED), true);
  assert.equal(isApiTokenStatus('deleted'), false);
});

test('ApiToken rejects incomplete token records', () => {
  assert.throws(() => new ApiToken({ ...baseTokenData, tokenHash: '' }), /tokenHash/);
  assert.throws(() => new ApiToken({ ...baseTokenData, tokenPrefix: '' }), /tokenPrefix/);
  assert.throws(() => new ApiToken({ ...baseTokenData, userId: '' }), /userId/);
  assert.throws(() => new ApiToken({ ...baseTokenData, createdBy: '' }), /createdBy/);
});

test('ApiToken validates scopes and dates', () => {
  assert.throws(() => new ApiToken({ ...baseTokenData, scopes: 'credentials:read' }), /scopes/);
  assert.throws(() => new ApiToken({ ...baseTokenData, scopes: ['credentials:read', ''] }), /non-empty strings/);
  assert.throws(() => new ApiToken({ ...baseTokenData, expiresAt: 'not-a-date' }), /expiresAt/);
  assert.throws(() => new ApiToken(baseTokenData).isExpired('not-a-date'), /referenceDate/);
});

test('ApiToken exposes revocation and last-used state as immutable updates', () => {
  const token = new ApiToken(baseTokenData);
  const revoked = token.withRevokedAt('2026-07-10T08:00:00.000Z');
  const used = token.withLastUsedAt('2026-07-11T08:00:00.000Z');

  assert.equal(token.revokedAt, null);
  assert.equal(revoked.status, ApiTokenStatus.REVOKED);
  assert.equal(revoked.version, 2);
  assert.equal(used.lastUsedAt.toISOString(), '2026-07-11T08:00:00.000Z');
  assert.equal(used.version, 2);
});

test('ApiToken detects expiration relative to a reference date', () => {
  const token = new ApiToken({ ...baseTokenData, expiresAt: '2026-08-09T08:00:00.000Z' });

  assert.equal(token.isExpired('2026-08-09T07:59:59.000Z'), false);
  assert.equal(token.isExpired('2026-08-09T08:00:00.000Z'), true);
  assert.equal(new ApiToken({ ...baseTokenData, expiresAt: '2026-07-01T08:00:00.000Z' }).status, ApiTokenStatus.EXPIRED);
});
