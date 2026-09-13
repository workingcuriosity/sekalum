import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';
import { AccessManagementService } from '../../src/services/access-management-service.js';
import { AuditLogService } from '../../src/services/audit-log-service.js';
import { ApiTokenService, ApiTokenServiceConstants } from '../../src/services/api-token-service.js';
import { AbuseAdmission, AbusePolicyClass } from '../../src/security/abuse-admission.js';
import { listenOAuthCallbackServer } from '../support/oauth-callback-test-server.js';

const BOOTSTRAP_TOKEN = crypto.createHash('sha256')
  .update('access-management-bootstrap-test-fixture-v2')
  .digest('hex');

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
  const accessManagementService = new AccessManagementService({ auditLogService, bootstrapSecret: BOOTSTRAP_TOKEN });

  const server = new OAuthCallbackServer({
    providerManager: { listProviders() { return []; } },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    schedulerService: { getStatus() { return { started: false, running: false, jobs: [] }; } },
    accessManagementService,
    auditLogService,
    abuseAdmission: new AbuseAdmission({
      policyOverrides: {
        [AbusePolicyClass.PRE_AUTH_FAILURE]: { capacity: 100 },
        [AbusePolicyClass.BOOTSTRAP]: { capacity: 10 },
        [AbusePolicyClass.MANAGEMENT_AUTHENTICATED]: { capacity: 100 },
        [AbusePolicyClass.MANAGEMENT_MUTATION]: { capacity: 100 }
      }
    }),
    config: { get() { return 0; } },
    logger: { success() {}, error() {}, info() {} }
  });
  server.__testAccessManagementService = accessManagementService;
  return server;
}

function createBootstrapServer({ nodeEnv = 'test', hostedMode = false, bindHost = null } = {}) {
  const auditLogService = new AuditLogService();
  const accessManagementService = new AccessManagementService({ auditLogService, bootstrapSecret: BOOTSTRAP_TOKEN });
  const apiTokenService = new ApiTokenService({
    store: new InMemoryApiTokenStore(),
    auditLogService,
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, 13)
  });
  const configValues = {
    NODE_ENV: nodeEnv,
    OAUTH_CALLBACK_PORT: 0,
    ...(hostedMode ? {
      HOSTED_MODE: 'true',
      APP_BIND_HOST: bindHost ?? '0.0.0.0',
      TRUSTED_PROXY: '127.0.0.1',
      PUBLIC_BASE_URL: 'https://sekalum.example.test'
    } : {
      ...(bindHost ? { APP_BIND_HOST: bindHost } : {}),
      ...(nodeEnv === 'production' ? { PUBLIC_BASE_URL: 'https://sekalum.example.test' } : {})
    })
  };

  return {
    accessManagementService,
    apiTokenService,
    server: new OAuthCallbackServer({
      providerManager: { listProviders() { return []; } },
      importTokenCommand: {},
      credentialManager: { async listCredentials() { return []; } },
      schedulerService: { getStatus() { return { started: false, running: false, jobs: [] }; } },
      accessManagementService,
      auditLogService,
      apiTokenService,
      abuseAdmission: new AbuseAdmission({
          policyOverrides: {
            [AbusePolicyClass.PRE_AUTH_FAILURE]: { capacity: 100 },
            [AbusePolicyClass.BOOTSTRAP]: { capacity: 10 },
            [AbusePolicyClass.MANAGEMENT_AUTHENTICATED]: { capacity: 100 },
            [AbusePolicyClass.MANAGEMENT_MUTATION]: { capacity: 100 }
        }
      }),
      config: { get(key, fallback = null) {
        return Object.hasOwn(configValues, key) ? configValues[key] : fallback;
      } },
      logger: { success() {}, error() {}, info() {} }
    })
  };
}

function listen(app, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const server = app.listen(0, host, () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

test('HTTP management roles endpoint returns available roles', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

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

test('TEST-AUTH-ATTACK-001: test header compatibility requires the canonical loopback listener and hosted mode requires Bearer authentication', async () => {
  const standalone = createBootstrapServer();
  const standaloneHttp = await listenOAuthCallbackServer(standalone.server);
  try {
    const response = await fetch(`${standaloneHttp.baseUrl}/api/v1/management/roles`, {
      headers: { 'x-credential-hub-user': 'local-test-user' }
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).success, true);
  } finally {
    standaloneHttp.server.close();
  }

  for (const bindHost of ['0.0.0.0', '::']) {
    const hosted = createBootstrapServer({ hostedMode: true, bindHost });
    await hosted.accessManagementService.replaceUsers([
      { userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' }
    ], { skipAudit: true });
    const managementToken = await hosted.apiTokenService.createToken({
      name: `Hosted test token ${bindHost}`,
      userId: 'admin-1',
      scopes: ['users:read'],
      createdBy: 'admin-1'
    });
    const hostedHttp = await listenOAuthCallbackServer(hosted.server);
    try {
      const headerResponse = await fetch(`${hostedHttp.baseUrl}/api/v1/management/roles`, {
        headers: { 'x-credential-hub-user': 'admin-1' }
      });
      assert.equal(headerResponse.status, 401, `${bindHost} hosted test header must be rejected`);
      assert.equal((await headerResponse.json()).error.code, 'API_TOKEN_AUTH_FAILED');

      const bearerResponse = await fetch(`${hostedHttp.baseUrl}/api/v1/management/roles`, {
        headers: { authorization: `Bearer ${managementToken.token}` }
      });
      assert.equal(bearerResponse.status, 200, `${bindHost} hosted Bearer authentication must remain available`);
      assert.equal((await bearerResponse.json()).success, true);
    } finally {
      hostedHttp.server.close();
    }
  }

  for (const nodeEnv of ['production', 'development']) {
    const server = createBootstrapServer({ nodeEnv });
    const http = await listenOAuthCallbackServer(server.server);
    try {
      const response = await fetch(`${http.baseUrl}/api/v1/management/roles`, {
        headers: { 'x-credential-hub-user': 'admin-1' }
      });
      assert.equal(response.status, 401, `${nodeEnv} test header must be rejected`);
      assert.equal((await response.json()).error.code, 'API_TOKEN_AUTH_FAILED');
    } finally {
      http.server.close();
    }
  }
});

test('TEST-AUTH-ATTACK-002: direct app listeners cannot activate compatibility header authentication', async () => {
  const canonical = createBootstrapServer();
  const canonicalHttp = await listenOAuthCallbackServer(canonical.server);
  const directLoopback = await listen(canonical.server.app);
  const directWildcard = await listen(canonical.server.app, '0.0.0.0');

  try {
    const canonicalResponse = await fetch(`${canonicalHttp.baseUrl}/api/v1/management/roles`, {
      headers: { 'x-credential-hub-user': 'local-test-user' }
    });
    assert.equal(canonicalResponse.status, 200);

    for (const http of [directLoopback, directWildcard]) {
      const response = await fetch(`${http.baseUrl}/api/v1/management/roles`, {
        headers: { 'x-credential-hub-user': 'local-test-user' }
      });
      assert.equal(response.status, 401);
      assert.equal((await response.json()).error.code, 'API_TOKEN_AUTH_FAILED');
    }
  } finally {
    canonicalHttp.server.close();
    directLoopback.server.close();
    directWildcard.server.close();
  }
});

test('HTTP management users endpoint creates, updates and deletes users', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    const createResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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

test('HTTP management users endpoint requires bootstrap proof and allows only the first administrator without a Bearer token', async () => {
  const setup = createBootstrapServer();
  const { server, baseUrl } = await listenOAuthCallbackServer(setup.server);

  try {
    const missingProofResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-missing', displayName: 'Admin', roleKey: 'admin' })
    });
    assert.equal(missingProofResponse.status, 403);

    const wrongProofResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': 'w'.repeat(32) },
      body: JSON.stringify({ userId: 'admin-wrong', displayName: 'Admin', roleKey: 'admin' })
    });
    assert.equal(wrongProofResponse.status, 403);

    const bootstrapResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
      body: JSON.stringify({ userId: 'admin-1', displayName: 'Admin', roleKey: 'admin' })
    });
    assert.equal(bootstrapResponse.status, 201);
    assert.doesNotMatch(await bootstrapResponse.clone().text(), new RegExp(BOOTSTRAP_TOKEN));

    const unauthenticatedResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'admin-2', displayName: 'Second Admin', roleKey: 'admin' })
    });
    const unauthenticated = await unauthenticatedResponse.json();
    assert.equal(unauthenticatedResponse.status, 403);
    assert.equal(unauthenticated.error.code, 'BOOTSTRAP_CLOSED');

    const reusedBootstrapResponse = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
      body: JSON.stringify({ userId: 'admin-3', displayName: 'Second Bootstrap', roleKey: 'admin' })
    });
    assert.equal(reusedBootstrapResponse.status, 403);

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

test('production management users endpoint does not trust loopback proxy headers as bootstrap proof', async () => {
  const setup = createBootstrapServer({ nodeEnv: 'production' });
  const { server, baseUrl } = await listenOAuthCallbackServer(setup.server);

  try {
    const response = await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-forwarded-for': '127.0.0.1'
      },
      body: JSON.stringify({ userId: 'proxy-admin', displayName: 'Proxy Admin', roleKey: 'admin' })
    });
    assert.equal(response.status, 403);
    assert.deepEqual(await setup.accessManagementService.listUsers(), []);
  } finally {
    server.close();
  }
});

test('HTTP management users endpoint enforces role permissions after bootstrap', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

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
      const expectedUnauthenticatedStatus = pathname === '/api/v1/management/users' && method === 'POST' ? 403 : 401;
      assert.equal(unauthenticated.status, expectedUnauthenticatedStatus, `${method} ${pathname} unauthenticated`);
      const unauthenticatedBody = await unauthenticated.json();
      const expectedUnauthenticatedCode = expectedUnauthenticatedStatus === 403 ? 'BOOTSTRAP_CLOSED' : 'API_TOKEN_AUTH_FAILED';
      assert.equal(unauthenticatedBody.error.code, expectedUnauthenticatedCode, `${method} ${pathname} unauthenticated code`);

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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    await fetch(`${baseUrl}/api/v1/management/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-bootstrap-token': BOOTSTRAP_TOKEN },
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
