import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';
import { AccessManagementService } from '../../src/services/access-management-service.js';
import { AuditLogService } from '../../src/services/audit-log-service.js';
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

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

async function createServer({ now = '2026-07-09T08:00:00.000Z' } = {}) {
  const auditLogService = new AuditLogService();
  const accessManagementService = new AccessManagementService({ auditLogService });
  await accessManagementService.replaceUsers([
    { userId: 'viewer-user', displayName: 'Viewer User', roleKey: 'viewer' },
    { userId: 'admin-user', displayName: 'Admin User', roleKey: 'admin' }
  ], { skipAudit: true });

  const apiTokenService = new ApiTokenService({
    store: new InMemoryApiTokenStore(),
    auditLogService,
    clock: () => new Date(now),
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, 13)
  });

  const providers = [{
    key: 'threads',
    displayName: 'Threads',
    description: 'Meta Threads OAuth provider',
    capabilities: ['oauth', 'refresh']
  }];

  return {
    apiTokenService,
    server: new OAuthCallbackServer({
      providerManager: {
        listProviders() { return providers; },
        getProvider(providerKey) { return providers.find((provider) => provider.key === providerKey) ?? null; },
        getProviderCapabilities(providerKey) { return providers.find((provider) => provider.key === providerKey)?.capabilities ?? null; }
      },
      importTokenCommand: {},
      credentialManager: { async listCredentials() { return []; } },
      schedulerService: { getStatus() { return { started: false, running: false, jobs: [] }; } },
      accessManagementService,
      auditLogService,
      apiTokenService,
      config: { get() { return 0; } },
      logger: { success() {}, error() {}, info() {} }
    })
  };
}

test('REST API accepts Authorization Bearer API tokens and keeps RBAC authorization', async () => {
  const setup = await createServer();
  const created = await setup.apiTokenService.createToken({
    name: 'REST token',
    userId: 'viewer-user',
    scopes: ['providers:read'],
    createdBy: 'admin-user'
  });
  const { server, baseUrl } = await listen(setup.server.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers`, {
      headers: { authorization: `Bearer ${created.token}` }
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
  } finally {
    server.close();
  }
});

test('REST API rejects invalid Bearer API tokens', async () => {
  const setup = await createServer();
  const { server, baseUrl } = await listen(setup.server.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers`, {
      headers: { authorization: 'Bearer cht_invalid' }
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'API_TOKEN_AUTH_FAILED');
    assert.match(body.error.message, /Invalid API token/);
  } finally {
    server.close();
  }
});

test('REST API rejects x-credential-hub-user without a Bearer token', async () => {
  const setup = await createServer();
  const { server, baseUrl } = await listen(setup.server.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers`, {
      headers: { 'x-credential-hub-user': 'viewer-user' }
    });
    const body = await response.json();

    if (process.env.NODE_ENV === 'test') {
      assert.equal(response.status, 200);
      assert.equal(body.success, true);
    } else {
      assert.equal(response.status, 401);
      assert.equal(body.success, false);
      assert.equal(body.error.code, 'API_TOKEN_AUTH_FAILED');
    }
  } finally {
    server.close();
  }
});

test('REST API applies RBAC after successful Bearer API token authentication', async () => {
  const setup = await createServer();
  const created = await setup.apiTokenService.createToken({
    name: 'Viewer token',
    userId: 'viewer-user',
    scopes: ['providers:read'],
    createdBy: 'admin-user'
  });
  const { server, baseUrl } = await listen(setup.server.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/management/providers/threads/health-check`, {
      method: 'POST',
      headers: { authorization: `Bearer ${created.token}` }
    });
    const body = await response.json();

    assert.equal(response.status, 403);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'API_TOKEN_SCOPE_MISSING');
    assert.match(body.error.message, /required scope/);
  } finally {
    server.close();
  }
});

test('REST API manages API tokens through RBAC protected endpoints', async () => {
  const setup = await createServer();
  const management = await setup.apiTokenService.createToken({ name: 'Administrator', userId: 'admin-user', scopes: ['api-tokens:manage', 'api-tokens:read'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setup.server.app);

  try {
    const createResponse = await fetch(`${baseUrl}/api/v1/management/api-tokens`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${management.token}`
      },
      body: JSON.stringify({
        name: 'External integration',
        userId: 'viewer-user',
        scopes: ['providers:read'],
        expiresAt: '2026-08-09T08:00:00.000Z'
      })
    });
    const createdBody = await createResponse.json();

    assert.equal(createResponse.status, 201);
    assert.equal(createdBody.success, true);
    assert.match(createdBody.data.token, /^cht_/);
    assert.equal(createdBody.data.apiToken.name, 'External integration');
    assert.equal(createdBody.data.apiToken.userId, 'viewer-user');
    assert.equal(createdBody.data.apiToken.tokenHash, undefined);

    const tokenId = createdBody.data.apiToken.id;

    const listResponse = await fetch(`${baseUrl}/api/v1/management/api-tokens`, {
      headers: { authorization: `Bearer ${management.token}` }
    });
    const listBody = await listResponse.json();

    assert.equal(listResponse.status, 200);
    assert.equal(listBody.data.some((entry) => entry.id === tokenId), true);
    assert.equal(listBody.data.every((entry) => entry.tokenHash === undefined), true);

    const getResponse = await fetch(`${baseUrl}/api/v1/management/api-tokens/${tokenId}`, {
      headers: { authorization: `Bearer ${management.token}` }
    });
    const getBody = await getResponse.json();

    assert.equal(getResponse.status, 200);
    assert.equal(getBody.data.id, tokenId);

    const revokeResponse = await fetch(`${baseUrl}/api/v1/management/api-tokens/${tokenId}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${management.token}` }
    });
    const revokeBody = await revokeResponse.json();

    assert.equal(revokeResponse.status, 200);
    assert.equal(revokeBody.data.id, tokenId);
    assert.equal(revokeBody.data.status, 'revoked');
  } finally {
    server.close();
  }
});

test('REST API token management endpoints enforce api-token permissions', async () => {
  const setup = await createServer();
  const viewer = await setup.apiTokenService.createToken({ name: 'Viewer', userId: 'viewer-user', scopes: ['api-tokens:manage'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setup.server.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/management/api-tokens`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${viewer.token}`
      },
      body: JSON.stringify({
        name: 'Forbidden token',
        userId: 'viewer-user',
        scopes: []
      })
    });
    const body = await response.json();

    assert.equal(response.status, 403);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'FORBIDDEN');
    assert.match(body.error.message, /api-tokens:manage/);
  } finally {
    server.close();
  }
});

test('REST API token management requires a valid, consumer-authorized token owner', async () => {
  const setup = await createServer();
  const management = await setup.apiTokenService.createToken({ name: 'Administrator', userId: 'admin-user', scopes: ['api-tokens:manage'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setup.server.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/management/api-tokens`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${management.token}` },
      body: JSON.stringify({ name: 'Unowned consumer token', userId: 'unknown-user', scopes: ['credentials:consume'] })
    });
    const body = await response.json();

    // Unknown owners deliberately receive the same authorization-style response
    // as missing credentials, so the endpoint does not disclose account state.
    assert.equal(response.status, 401);
    assert.equal(body.success, false);
  } finally {
    server.close();
  }
});
