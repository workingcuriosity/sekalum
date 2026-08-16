import test from 'node:test';
import assert from 'node:assert/strict';

import { ApiToken } from '../../src/models/api-token.js';
import { ApiTokenStatus } from '../../src/models/api-token-status.js';

const baseTokenData = {
  id: 'api-token-component-1',
  name: 'External reporting job',
  tokenPrefix: 'cht_report',
  tokenHash: 'sha256:component-hash',
  userId: 'reporting-user',
  scopes: ['credentials:read', 'audit:read'],
  createdAt: '2026-07-09T08:00:00.000Z',
  expiresAt: null,
  createdBy: 'admin-user'
};

test('ApiToken round-trips stored JSON while preserving secret hash internally only', () => {
  const token = new ApiToken(baseTokenData);
  const restored = ApiToken.from(token.toJSON());

  assert.equal(restored.id, token.id);
  assert.equal(restored.tokenHash, 'sha256:component-hash');
  assert.deepEqual(restored.scopes, ['credentials:read', 'audit:read']);
  assert.equal(restored.toPublicJSON().tokenHash, undefined);
});

test('ApiToken status precedence treats revoked tokens as revoked even when expired', () => {
  const token = new ApiToken({
    ...baseTokenData,
    expiresAt: '2026-07-01T00:00:00.000Z',
    revokedAt: '2026-07-02T00:00:00.000Z'
  });

  assert.equal(token.status, ApiTokenStatus.REVOKED);
});
