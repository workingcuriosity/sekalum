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

function createServer() {
  const auditLogService = new AuditLogService();
  const accessManagementService = new AccessManagementService({ auditLogService });

  const server = new OAuthCallbackServer({
    providerManager: { listProviders() { return []; } },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    schedulerService: { getStatus() { return { started: false, running: false, jobs: [] }; } },
    accessManagementService,
    auditLogService,
    config: { get() { return 0; } },
    logger: { success() {}, error() {}, info() {} }
  });
  server.__testAccessManagementService = accessManagementService;
  return server;
}

function createBootstrapServer() {
  const auditLogService = new AuditLogService();
  const accessManagementService = new AccessManagementService({ auditLogService });
  const apiTokenService = new ApiTokenService({
    store: new InMemoryApiTokenStore(),
    auditLogService,
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, 13)
  });

  return {
    apiTokenService,
    server: new OAuthCallbackServer({
      providerManager: { listProviders() { return []; } },
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

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

test('HTTP management roles endpoint returns available roles', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/management/roles`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.deepEqual(body.data.map((role) => role.roleKey), ['admin', 'operator', 'viewer']);
  } finally {
    server.close();
  }
});

test('HTTP management users endpoint creates, updates and deletes users', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const createResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'user-1', displayName: 'User One', roleKey: 'admin' })
    });
    const created = await createResponse.json();

    assert.equal(createResponse.status, 201);
    assert.equal(created.data.roleKey, 'admin');

    const updateResponse = await fetch(`${baseUrl}/api/v1/management/users/user-1`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'user-1' },
      body: JSON.stringify({ roleKey: 'admin' })
    });
    const updated = await updateResponse.json();

    assert.equal(updateResponse.status, 200);
    assert.equal(updated.data.roleKey, 'admin');

    const list = await (await fetch(`${baseUrl}/api/v1/management/users`, { headers: { 'x-credential-hub-user': 'user-1' } })).json();
    assert.equal(list.data.length, 1);

    const deleteResponse = await fetch(`${baseUrl}/api/v1/management/users/user-1`, { method: 'DELETE', headers: { 'x-credential-hub-user': 'user-1' } });
    assert.equal(deleteResponse.status, 204);
  } finally {
    server.close();
  }
});

test('HTTP management users endpoint allows only the first administrator without a Bearer token', async () => {
  const setup = createBootstrapServer();
  const { server, baseUrl } = await listen(setup.server.app);

  try {
    const bootstrapResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });
    assert.equal(bootstrapResponse.status, 201);

    const unauthenticatedResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-2', displayName: 'Second Admin', roleKey: 'admin' })
    });
    const unauthenticated = await unauthenticatedResponse.json();
    assert.equal(unauthenticatedResponse.status, 401);
    assert.equal(unauthenticated.error.code, 'API_TOKEN_AUTH_FAILED');

    const managementToken = await setup.apiTokenService.createToken({
      name: 'Bootstrap validation token',
      userId: 'admin-1',
      scopes: ['users:manage'],
      createdBy: 'admin-1'
    });
    const authenticatedResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${managementToken.token}`
      },
      body: JSON.stringify({ userId: 'admin-2', displayName: 'Second Admin', roleKey: 'admin' })
    });
    assert.equal(authenticatedResponse.status, 201);
  } finally {
    server.close();
  }
});

test('HTTP management users endpoint enforces role permissions after bootstrap', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    const viewerCreateResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin-1' },
      body: JSON.stringify({ userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer' })
    });
    assert.equal(viewerCreateResponse.status, 201);

    const forbiddenResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'viewer-1' },
      body: JSON.stringify({ userId: 'user-2', displayName: 'User Two', roleKey: 'viewer' })
    });
    const forbidden = await forbiddenResponse.json();

    assert.equal(forbiddenResponse.status, 403);
    assert.equal(forbidden.error.code, 'FORBIDDEN');

    const unauthenticatedResponse = await fetch(`${baseUrl}/api/v1/management/users`);
    assert.equal(unauthenticatedResponse.status, 401);
  } finally {
    server.close();
  }
});

test('credential-sensitive route matrix denies unauthenticated and under-permissioned callers', async () => {
  const httpServer = createServer();
  await httpServer.__testAccessManagementService.replaceUsers([
    { userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' },
    { userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer' }
  ], { skipAudit: true });
  const { server, baseUrl } = await listen(httpServer.app);

  const matrix = [
    ['POST', '/api/v1/management/consumer-grants'],
    ['POST', '/api/v1/management/consumer-grants/diagnose'],
    ['GET', '/api/v1/management/consumer-grants'],
    ['PUT', '/api/v1/management/consumer-grants/grant-1'],
    ['POST', '/api/v1/management/scheduler/start'],
    ['POST', '/api/v1/management/scheduler/stop'],
    ['POST', '/api/v1/management/scheduler/run-once'],
    ['POST', '/api/v1/management/users'],
    ['PUT', '/api/v1/management/users/user-1'],
    ['DELETE', '/api/v1/management/users/user-1'],
    ['GET', '/api/v1/management/audit-log'],
    ['GET', '/api/v1/management/audit-log/entry-1'],
    ['POST', '/api/v1/management/api-tokens'],
    ['DELETE', '/api/v1/management/api-tokens/token-1'],
    ['GET', '/api/v1/management/exports'],
    ['GET', '/api/v1/management/exports/credentials'],
    ['GET', '/api/v1/management/backups'],
    ['POST', '/api/v1/management/backups'],
    ['GET', '/api/v1/management/backups/backup-1'],
    ['POST', '/api/v1/management/backups/backup-1/restore'],
    ['POST', '/api/v1/credentials'],
    ['POST', '/api/v1/credentials/bulk'],
    ['POST', '/api/v1/credentials/export'],
    ['POST', '/api/v1/credentials/import/preview'],
    ['POST', '/api/v1/credentials/import'],
    ['POST', '/api/v1/credentials/test-connection'],
    ['PUT', '/api/v1/credentials/credential-1'],
    ['DELETE', '/api/v1/credentials/credential-1'],
    ['POST', '/api/v1/credentials/credential-1/validate'],
    ['POST', '/api/v1/credentials/credential-1/refresh'],
    ['POST', '/api/v1/credentials/credential-1/revoke'],
    ['POST', '/api/v1/credentials/credential-1/health-check'],
    ['POST', '/api/v1/providers'],
    ['POST', '/api/v1/providers/example/disable'],
    ['POST', '/api/v1/providers/example/enable'],
    ['POST', '/api/v1/providers/example/oauth/start']
  ];

  const request = (method, pathname, headers = {}) => fetch(`${baseUrl}${pathname}`, {
    method,
    headers: {
      ...(method === 'POST' || method === 'PUT' ? { 'content-type': 'application/json' } : {}),
      ...headers
    },
    ...(method === 'POST' || method === 'PUT' ? { body: '{}' } : {})
  });

  try {
    for (const [method, pathname] of matrix) {
      const unauthenticated = await request(method, pathname);
      assert.equal(unauthenticated.status, 401, `${method} ${pathname} unauthenticated`);
      const unauthenticatedBody = await unauthenticated.json();
      assert.equal(unauthenticatedBody.error.code, 'API_TOKEN_AUTH_FAILED', `${method} ${pathname} unauthenticated code`);

      const underPermissioned = await request(method, pathname, { 'x-credential-hub-user': 'viewer-1' });
      assert.equal(underPermissioned.status, 403, `${method} ${pathname} viewer`);
      const underPermissionedBody = await underPermissioned.json();
      assert.equal(underPermissionedBody.error.code, 'FORBIDDEN', `${method} ${pathname} viewer code`);
    }
  } finally {
    server.close();
  }
});

test('HTTP management audit-log endpoint lists audited user changes for admins', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin-1' },
      body: JSON.stringify({ userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer' })
    });

    const response = await fetch(`${baseUrl}/api/v1/management/audit-log?action=user.created`, {
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.ok(body.data.length >= 2);
    assert.ok(body.data.some((entry) => entry.targetId === 'viewer-1'));

    const detailResponse = await fetch(`${baseUrl}/api/v1/management/audit-log/${body.data[0].entryId}`, {
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    assert.equal(detailResponse.status, 200);
  } finally {
    server.close();
  }
});

test('HTTP management audit-log endpoint rejects viewers', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin-1' },
      body: JSON.stringify({ userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer' })
    });

    const response = await fetch(`${baseUrl}/api/v1/management/audit-log`, {
      headers: { 'x-credential-hub-user': 'viewer-1' }
    });
    const body = await response.json();

    assert.equal(response.status, 403);
    assert.equal(body.error.code, 'FORBIDDEN');
  } finally {
    server.close();
  }
});

test('HTTP management export endpoints return JSON and CSV exports for admins', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    const resourcesResponse = await fetch(`${baseUrl}/api/v1/management/exports`, {
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    const resources = await resourcesResponse.json();

    assert.equal(resourcesResponse.status, 200);
    assert.ok(resources.data.some((item) => item.resource === 'audit-log'));

    const usersResponse = await fetch(`${baseUrl}/api/v1/management/exports/users?format=json`, {
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    const usersExport = await usersResponse.json();

    assert.equal(usersResponse.status, 200);
    assert.equal(usersExport.data[0].userId, 'admin-1');

    const auditResponse = await fetch(`${baseUrl}/api/v1/management/exports/audit-log?format=csv`, {
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    const auditCsv = await auditResponse.text();

    assert.equal(auditResponse.status, 200);
    assert.match(auditResponse.headers.get('content-type'), /text\/csv/);
    assert.match(auditCsv, /entryId,timestamp/);
  } finally {
    server.close();
  }
});

test('HTTP management export endpoints reject viewers', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin-1' },
      body: JSON.stringify({ userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer' })
    });

    const response = await fetch(`${baseUrl}/api/v1/management/exports/users`, {
      headers: { 'x-credential-hub-user': 'viewer-1' }
    });
    const body = await response.json();

    assert.equal(response.status, 403);
    assert.equal(body.error.code, 'FORBIDDEN');
  } finally {
    server.close();
  }
});


test('HTTP management backup endpoints create and restore management backups for admins', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    const createResponse = await fetch(`${baseUrl}/api/v1/management/backups`, {
      method: 'POST',
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    const created = await createResponse.json();

    assert.equal(createResponse.status, 201);
    assert.equal(created.success, true);
    assert.equal(created.data.counts.users, 1);

    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin-1' },
      body: JSON.stringify({ userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer' })
    });

    const listResponse = await fetch(`${baseUrl}/api/v1/management/backups`, {
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    const listed = await listResponse.json();
    assert.equal(listResponse.status, 200);
    assert.equal(listed.data.length, 1);

    const restoreResponse = await fetch(`${baseUrl}/api/v1/management/backups/${created.data.backupId}/restore`, {
      method: 'POST',
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    const restored = await restoreResponse.json();
    assert.equal(restoreResponse.status, 200);
    assert.equal(restored.data.restored.users, 1);

    const users = await (await fetch(`${baseUrl}/api/v1/management/users`, { headers: { 'x-credential-hub-user': 'admin-1' } })).json();
    assert.deepEqual(users.data.map((user) => user.userId), ['admin-1']);
  } finally {
    server.close();
  }
});

test('HTTP management backup endpoints reject viewers', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin-1' },
      body: JSON.stringify({ userId: 'viewer-1', displayName: 'Viewer', roleKey: 'viewer' })
    });

    const response = await fetch(`${baseUrl}/api/v1/management/backups`, {
      method: 'POST',
      headers: { 'x-credential-hub-user': 'viewer-1' }
    });
    const body = await response.json();

    assert.equal(response.status, 403);
    assert.equal(body.error.code, 'FORBIDDEN');
  } finally {
    server.close();
  }
});

test('HTTP management metrics endpoint returns extended operating metrics for admins', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    const response = await fetch(`${baseUrl}/api/v1/management/metrics`, {
      headers: { 'x-credential-hub-user': 'admin-1' }
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.summary.users, 1);
    assert.equal(body.data.accessManagement.users.byRole.admin, 1);
    assert.equal(body.data.scheduler.available, true);
    assert.ok(body.data.exports.resourceCount >= 1);
  } finally {
    server.close();
  }
});

test('HTTP management metrics endpoint rejects disabled users', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });

    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin-1' },
      body: JSON.stringify({ userId: 'operator-1', displayName: 'Operator', roleKey: 'operator', status: 'disabled' })
    });

    const response = await fetch(`${baseUrl}/api/v1/management/metrics`, {
      headers: { 'x-credential-hub-user': 'operator-1' }
    });
    const body = await response.json();

    assert.equal(response.status, 403);
    assert.equal(body.error.code, 'FORBIDDEN');
  } finally {
    server.close();
  }
});
