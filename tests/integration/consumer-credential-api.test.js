import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';
import { Credential } from '../../src/models/credential.js';
import { AccessManagementService } from '../../src/services/access-management-service.js';
import { ApiTokenService, ApiTokenServiceConstants } from '../../src/services/api-token-service.js';
import { AuditLogService } from '../../src/services/audit-log-service.js';
import { ConsumerCredentialService } from '../../src/services/consumer-credential-service.js';
import { ConsumerGrantService } from '../../src/services/consumer-grant-service.js';
import { RuntimePublicProjectionService } from '../../src/services/runtime-public-projection-service.js';

class InMemoryApiTokenStore {
  constructor() { this.tokens = new Map(); }
  async list() { return [...this.tokens.values()]; }
  async load(tokenId) {
    const token = this.tokens.get(tokenId);
    if (!token) {
      const error = new Error('API token not found');
      error.code = 'NOT_FOUND';
      throw error;
    }
    return token;
  }
  async save(token) { this.tokens.set(token.id, token); return token; }
  async findByPrefix(tokenPrefix) { return [...this.tokens.values()].filter((token) => token.tokenPrefix === tokenPrefix); }
}

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

async function setup({ lifecycleState = 'active', runtimePublic = false, runtimePublicConfiguration = { clientId: 'twitch-client-id' } } = {}) {
  const auditLogService = new AuditLogService();
  const accessManagementService = new AccessManagementService({ auditLogService });
  await accessManagementService.replaceUsers([
    { userId: 'admin-user', displayName: 'Admin', roleKey: 'admin' },
    { userId: 'viewer-user', displayName: 'Viewer', roleKey: 'viewer' }
  ], { skipAudit: true });

  let entropy = 0;
  const apiTokenService = new ApiTokenService({
    store: new InMemoryApiTokenStore(),
    auditLogService,
    clock: () => new Date('2026-07-16T08:00:00.000Z'),
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, ++entropy)
  });
  const credentials = new Map([
    ['threads-credential', new Credential({
      credentialId: 'threads-credential', credentialKey: 'threads-public-key', providerKey: 'threads', credentialMethodKey: 'oauth2', lifecycleState,
      metadata: runtimePublic ? { custom: { providerConfigurationId: 'threads-configuration' } } : {},
      secrets: [{ name: 'accessToken', value: 'consumer-integration-secret' }, { name: 'refreshToken', value: 'consumer-refresh-secret' }]
    })],
    ['openai-credential', new Credential({
      credentialId: 'openai-credential', credentialKey: 'openai-public-key', providerKey: 'openai', credentialMethodKey: 'api-key', lifecycleState: 'active',
      secrets: [{ name: 'apiKey', value: 'consumer-openai-secret' }]
    })]
  ]);
  const consumerGrantService = new ConsumerGrantService();
  const providerRegistry = {
    get(providerKey) {
      const methods = {
        threads: {
          oauth2: { credentialFields: [
            { key: 'accessToken', label: 'Access Token', type: 'password', required: true, secret: true, visible: true, userConfigurable: true, systemManaged: false },
            { key: 'refreshToken', label: 'Refresh Token', type: 'password', required: false, secret: true, visible: true, userConfigurable: true, systemManaged: false },
            { key: 'clientId', label: 'Client ID', type: 'text', required: false, secret: false, visible: true, userConfigurable: true, systemManaged: false }
          ] },
          webhook: { credentialFields: [{ key: 'signingSecret', label: 'Signing Secret', type: 'password', secret: true }] }
        },
        openai: { 'api-key': { credentialFields: [{ key: 'apiKey', label: 'API Key', type: 'password', secret: true }, { key: 'organization', label: 'Organization', type: 'text', secret: false }] } }
      }[providerKey];
      if (!methods) throw new Error('unknown provider');
      return {
        credentialFields: runtimePublic ? [{ key: 'clientId', section: 'providerConfiguration', runtimePublic: true, secret: false }] : [],
        getCredentialMethod(methodKey) { return methods[methodKey] ?? null; },
        getProviderMethodBinding(methodKey) { return methods[methodKey] ? { methodKey } : null; }
      };
    }
  };
  const runtimePublicProjectionService = new RuntimePublicProjectionService({
    providerConfigurationService: {
      async load(configurationId, providerKey) {
        if (!runtimePublic || configurationId !== 'threads-configuration' || providerKey !== 'threads') return null;
        return { configurationId, providerKey, configuration: runtimePublicConfiguration };
      }
    },
    providerRegistry
  });
  const consumerCredentialService = new ConsumerCredentialService({
    credentialStore: {
      async load(credentialId) {
        const credential = credentials.get(credentialId);
        if (!credential) {
          const error = new Error('missing');
          error.code = 'NOT_FOUND';
          throw error;
        }
        return credential;
      },
      async list() { return [...credentials.values()]; }
    },
    consumerGrantService,
    providerRegistry,
    runtimePublicProjectionService,
    auditLogService
  });
  const server = new OAuthCallbackServer({
    providerManager: { listProviders() { return []; }, getProvider() { return null; }, getProviderCapabilities() { return null; } },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    schedulerService: { getStatus() { return { started: false, running: false, jobs: [] }; } },
    accessManagementService,
    auditLogService,
    apiTokenService,
    consumerCredentialService,
    config: { get() { return 0; } },
    logger: { success() {}, error() {}, info() {} }
  });
  const managementToken = await apiTokenService.createToken({ name: 'Grant administrator', userId: 'admin-user', scopes: ['consumer-grants:manage'], createdBy: 'admin-user' });
  return { apiTokenService, auditLogService, consumerGrantService, consumerCredentialService, credentials, providerRegistry, server, managementToken: managementToken.token };
}

async function resolve(baseUrl, credentialKey, headers, secretNames) {
  return fetch(`${baseUrl}/api/v1/consumer/credentials/${credentialKey}/resolve`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ secretNames })
  });
}

async function discover(baseUrl, headers) {
  return fetch(`${baseUrl}/api/v1/consumer/credentials`, { headers });
}

function assertSafeDiscoveryBody(body) {
  const serialized = JSON.stringify(body);
  assert.doesNotMatch(serialized, /credentialId|providerKey|credentialMethodKey|secretNames/);
  assert.doesNotMatch(serialized, /consumer-(integration|refresh|openai)-secret|signingSecret|apiKey/);
  assert.doesNotMatch(serialized, /Error:|stack|internal test detail/i);
}

test('Consumer REST API discovers only active granted public credential projections', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(body.data.credentials, [{
      credentialKey: 'threads-public-key',
      metadata: { displayName: 'threads-public-key' },
      fields: [
        { name: 'accessToken', label: 'Access Token', inputType: 'password', required: true, secret: true, visible: true, userConfigurable: true, systemManaged: false },
        { name: 'refreshToken', label: 'Refresh Token', inputType: 'password', required: false, secret: true, visible: true, userConfigurable: true, systemManaged: false },
        { name: 'clientId', label: 'Client ID', inputType: 'text', required: false, secret: false, visible: true, userConfigurable: true, systemManaged: false }
      ]
    }]);
    assertSafeDiscoveryBody(body);
  } finally {
    server.close();
  }
});

test('Consumer Discovery includes the optional Runtime-Public projection', async () => {
  const setupResult = await setup({ runtimePublic: true });
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.deepEqual(body.data.credentials[0].runtimePublic, { clientId: 'twitch-client-id' });
    assert.deepEqual(body.data.credentials[0].fields[0], {
      name: 'accessToken', label: 'Access Token', inputType: 'password', required: true,
      secret: true, visible: true, userConfigurable: true, systemManaged: false
    });
    assertSafeDiscoveryBody(body);
  } finally {
    server.close();
  }
});

test('Consumer Discovery omits an empty Runtime-Public projection', async () => {
  const setupResult = await setup({ runtimePublic: true, runtimePublicConfiguration: {} });
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(Object.hasOwn(body.data.credentials[0], 'runtimePublic'), false);
    assert.doesNotMatch(JSON.stringify(body), /runtimePublic: \{\}|runtimePublic.*null/);
    assertSafeDiscoveryBody(body);
  } finally {
    server.close();
  }
});

test('Consumer Discovery rejects missing and invalid authentication without exposing data', async () => {
  const setupResult = await setup();
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const missing = await discover(baseUrl, {});
    assert.equal(missing.status, 401);
    const missingBody = await missing.json();
    assert.equal(missingBody.error.code, 'API_TOKEN_AUTH_FAILED');
    assertSafeDiscoveryBody(missingBody);

    const invalid = await discover(baseUrl, { authorization: 'Bearer invalid-token' });
    assert.equal(invalid.status, 401);
    const invalidBody = await invalid.json();
    assert.equal(invalidBody.error.code, 'API_TOKEN_AUTH_FAILED');
    assertSafeDiscoveryBody(invalidBody);
  } finally {
    server.close();
  }
});

test('Consumer Discovery rejects tokens without the consume scope', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Unscoped', userId: 'admin-user', scopes: ['credentials:read'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    assert.equal(response.status, 403);
    const body = await response.json();
    assert.equal(body.error.code, 'CONSUMER_SCOPE_MISSING');
    assertSafeDiscoveryBody(body);
  } finally {
    server.close();
  }
});

test('Consumer Discovery returns a safe 500 response for internal service failures', async () => {
  const setupResult = await setup();
  setupResult.consumerGrantService.listGrants = async () => { throw new Error('internal test detail'); };
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    assert.equal(response.status, 500);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const body = await response.json();
    assert.equal(body.error.code, 'INTERNAL_ERROR');
    assert.equal(body.error.message, 'Credential discovery could not be completed');
    assertSafeDiscoveryBody(body);
  } finally {
    server.close();
  }
});

test('Consumer Discovery returns an empty list for a consumer without grants', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const body = await response.json();
    assert.deepEqual(body.data, { credentials: [] });
    assertSafeDiscoveryBody(body);
  } finally {
    server.close();
  }
});

test('Consumer Discovery deduplicates grants and filters inactive, missing and mismatched credentials', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  setupResult.consumerGrantService.listGrants = async () => [
    { credentialId: 'threads-credential', providerKey: 'threads' },
    { credentialId: 'threads-credential', providerKey: 'threads' },
    { credentialId: 'openai-credential', providerKey: 'wrong-provider' },
    { credentialId: 'missing-credential', providerKey: 'threads' }
  ];
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.credentials.length, 1);
    assert.equal(body.data.credentials[0].credentialKey, 'threads-public-key');
    assertSafeDiscoveryBody(body);
  } finally {
    server.close();
  }
});

test('Consumer Discovery rejects grant-reachable cross-store credentialKey collisions without returning data', async () => {
  const setupResult = await setup();
  const collidingCredential = new Credential({
    credentialId: 'legacy-threads-credential', credentialKey: 'threads-public-key', providerKey: 'threads', credentialMethodKey: 'oauth2', lifecycleState: 'active',
    secrets: [{ name: 'accessToken', value: 'legacy-secret' }]
  });
  setupResult.credentials.set(collidingCredential.credentialId, collidingCredential);
  const before = JSON.stringify([...setupResult.credentials].map(([id, credential]) => [id, credential.toJSON?.() ?? credential]));
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const grants = [
    { consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads' },
    { consumerId: token.apiToken.id, credentialId: 'legacy-threads-credential', providerKey: 'threads' }
  ];
  setupResult.consumerGrantService.listGrants = async () => [
    ...grants
  ];
  setupResult.consumerGrantService.findGrant = async ({ consumerId, credentialId, providerKey }) => grants.find((grant) =>
    grant.consumerId === consumerId && grant.credentialId === credentialId && grant.providerKey === providerKey
  ) ?? null;
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
      assert.equal(response.status, 500);
      const body = await response.json();
      assert.equal(body.error.code, 'INTERNAL_ERROR');
      assertSafeDiscoveryBody(body);
    }
    const after = JSON.stringify([...setupResult.credentials].map(([id, credential]) => [id, credential.toJSON?.() ?? credential]));
    assert.equal(after, before);
  } finally {
    server.close();
  }
});

test('Consumer Discovery ignores an ungrantable credentialKey collision', async () => {
  const setupResult = await setup();
  setupResult.credentials.set('ungrantable-threads-credential', new Credential({
    credentialId: 'ungrantable-threads-credential', credentialKey: 'threads-public-key', providerKey: 'threads', credentialMethodKey: 'oauth2', lifecycleState: 'active',
    secrets: [{ name: 'accessToken', value: 'ungrantable-secret' }]
  }));
  setupResult.consumerGrantService.listGrants = async () => [{ credentialId: 'threads-credential', providerKey: 'threads' }];
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.deepEqual(body.data.credentials.map(({ credentialKey }) => credentialKey), ['threads-public-key']);
    assertSafeDiscoveryBody(body);
  } finally {
    server.close();
  }
});

test('Consumer Discovery returns distinct public credentialKeys for distinct granted credentials', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const grants = [
    { consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads' },
    { consumerId: token.apiToken.id, credentialId: 'openai-credential', providerKey: 'openai' }
  ];
  setupResult.consumerGrantService.listGrants = async () => [
    ...grants
  ];
  setupResult.consumerGrantService.findGrant = async ({ consumerId, credentialId, providerKey }) => grants.find((grant) =>
    grant.consumerId === consumerId && grant.credentialId === credentialId && grant.providerKey === providerKey
  ) ?? null;
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.deepEqual(body.data.credentials.map(({ credentialKey }) => credentialKey), ['threads-public-key', 'openai-public-key']);
    assert.doesNotMatch(JSON.stringify(body), /credentialId|consumer-(integration|refresh|openai)-secret/);
  } finally {
    server.close();
  }
});

test('Consumer Discovery filters inactive credentials and invalid method or binding resolution', async () => {
  const inactiveSetup = await setup({ lifecycleState: 'revoked' });
  const inactiveToken = await inactiveSetup.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  inactiveSetup.consumerGrantService.listGrants = async () => [{ credentialId: 'threads-credential', providerKey: 'threads' }];
  const inactiveServer = await listen(inactiveSetup.server.app);

  try {
    const inactiveResponse = await discover(inactiveServer.baseUrl, { authorization: `Bearer ${inactiveToken.token}` });
    assert.equal(inactiveResponse.status, 200);
    assert.deepEqual((await inactiveResponse.json()).data, { credentials: [] });
  } finally {
    inactiveServer.server.close();
  }

  const invalidMethodSetup = await setup();
  const invalidMethodToken = await invalidMethodSetup.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  invalidMethodSetup.consumerGrantService.listGrants = async () => [{ credentialId: 'threads-credential', providerKey: 'threads' }];
  invalidMethodSetup.providerRegistry.get = () => ({ getCredentialMethod() { return null; }, getProviderMethodBinding() { return null; } });
  const invalidMethodServer = await listen(invalidMethodSetup.server.app);

  try {
    const invalidMethodResponse = await discover(invalidMethodServer.baseUrl, { authorization: `Bearer ${invalidMethodToken.token}` });
    assert.equal(invalidMethodResponse.status, 200);
    const body = await invalidMethodResponse.json();
    assert.deepEqual(body.data, { credentials: [] });
    assertSafeDiscoveryBody(body);
  } finally {
    invalidMethodServer.server.close();
  }
});

test('Consumer REST API resolves explicitly granted secret fields for multiple provider types', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const provisionThreads = await fetch(`${baseUrl}/api/v1/management/consumer-grants`, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${setupResult.managementToken}` },
      body: JSON.stringify({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] })
    });
    assert.equal(provisionThreads.status, 201);
    const provisionOpenAi = await fetch(`${baseUrl}/api/v1/management/consumer-grants`, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${setupResult.managementToken}` },
      body: JSON.stringify({ consumerId: token.apiToken.id, credentialId: 'openai-credential', providerKey: 'openai', secretNames: ['apiKey'] })
    });
    assert.equal(provisionOpenAi.status, 201);

    const threadsResponse = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${token.token}` }, ['accessToken']);
    const threadsBody = await threadsResponse.json();
    assert.equal(threadsResponse.status, 200);
    assert.equal(threadsResponse.headers.get('cache-control'), 'no-store');
    assert.equal(threadsBody.data.credentialKey, 'threads-credential');
    assert.equal(threadsBody.data.credentialId, undefined);
    assert.equal(threadsBody.data.providerKey, 'threads');
    assert.equal(threadsBody.data.credentialMethodKey, undefined);
    assert.equal(threadsBody.data.lifecycleState, 'active');
    assert.deepEqual(Object.keys(threadsBody.data).sort(), ['credentialKey', 'lifecycleState', 'providerKey', 'secrets']);
    assert.deepEqual(threadsBody.data.secrets, { accessToken: 'consumer-integration-secret' });

    const openAiResponse = await resolve(baseUrl, 'openai-credential', { authorization: `Bearer ${token.token}` }, ['apiKey']);
    assert.equal(openAiResponse.status, 200);
    assert.equal((await openAiResponse.json()).data.secrets.apiKey, 'consumer-openai-secret');

    const audit = await setupResult.auditLogService.list();
    assert.equal(audit.filter((entry) => entry.action === 'consumer-credential.resolve').length, 2);
    const serializedAudit = JSON.stringify(audit);
    assert.doesNotMatch(serializedAudit, /consumer-(integration|refresh|openai)-secret/);
    assert.doesNotMatch(serializedAudit, /accessToken|apiKey/);
  } finally {
    server.close();
  }
});

test('Consumer REST API resolves with the public credentialKey', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await resolve(baseUrl, 'threads-public-key', { authorization: `Bearer ${token.token}` }, ['accessToken']);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.data.credentialKey, 'threads-public-key');
    assert.equal(body.data.credentialId, undefined);
    assert.deepEqual(body.data.secrets, { accessToken: 'consumer-integration-secret' });
  } finally {
    server.close();
  }
});

test('Consumer REST API permits only secret fields of the credential selected method', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['clientId', 'accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);
  try {
    const nonSecret = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${token.token}` }, ['clientId']);
    assert.equal(nonSecret.status, 403);
    assert.equal((await nonSecret.json()).error.code, 'RESOLVE_NOT_AVAILABLE');

    const oauthSecret = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${token.token}` }, ['accessToken']);
    assert.equal(oauthSecret.status, 200);
    assert.equal((await oauthSecret.json()).data.credentialMethodKey, undefined);
  } finally {
    server.close();
  }
});

test('Consumer grant API preserves existing consumer bindings and updates only the selected binding', async () => {
  const setupResult = await setup();
  const consumerA = await setupResult.apiTokenService.createToken({ name: 'Consumer A', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const consumerB = await setupResult.apiTokenService.createToken({ name: 'Consumer B', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setupResult.server.app);
  const headers = { 'content-type': 'application/json', authorization: `Bearer ${setupResult.managementToken}` };

  try {
    const createA = await fetch(`${baseUrl}/api/v1/management/consumer-grants`, {
      method: 'POST', headers,
      body: JSON.stringify({ consumerId: consumerA.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] })
    });
    const grantA = (await createA.json()).data;
    assert.equal(createA.status, 201);

    const duplicate = await fetch(`${baseUrl}/api/v1/management/consumer-grants`, {
      method: 'POST', headers,
      body: JSON.stringify({ consumerId: consumerA.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['refreshToken'] })
    });
    assert.equal(duplicate.status, 400);
    assert.equal((await duplicate.json()).error.code, 'CONSUMER_GRANT_DUPLICATE');

    const updated = await fetch(`${baseUrl}/api/v1/management/consumer-grants/${grantA.grantId}`, {
      method: 'PUT', headers,
      body: JSON.stringify({ consumerId: consumerA.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['refreshToken', 'accessToken'] })
    });
    assert.equal(updated.status, 200);
    assert.deepEqual((await updated.json()).data.secretNames.sort(), ['accessToken', 'refreshToken']);

    const createB = await fetch(`${baseUrl}/api/v1/management/consumer-grants`, {
      method: 'POST', headers,
      body: JSON.stringify({ consumerId: consumerB.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] })
    });
    assert.equal(createB.status, 201);

    const grantsForA = await fetch(`${baseUrl}/api/v1/management/consumer-grants?consumerId=${encodeURIComponent(consumerA.apiToken.id)}&credentialId=threads-credential&providerKey=threads`, { headers: { authorization: `Bearer ${setupResult.managementToken}` } });
    assert.equal(grantsForA.status, 200);
    assert.deepEqual((await grantsForA.json()).data[0].secretNames.sort(), ['accessToken', 'refreshToken']);

    const resolveA = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${consumerA.token}` }, ['refreshToken', 'accessToken']);
    assert.equal(resolveA.status, 200);
    const resolveB = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${consumerB.token}` }, ['accessToken']);
    assert.equal(resolveB.status, 200);
  } finally {
    server.close();
  }
});

test('Consumer REST API denies header fallback, missing scope, missing grants, revoked tokens and non-active credentials', async () => {
  const setupResult = await setup({ lifecycleState: 'revoked' });
  const scoped = await setupResult.apiTokenService.createToken({ name: 'Scoped', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const unscoped = await setupResult.apiTokenService.createToken({ name: 'Unscoped', userId: 'admin-user', scopes: ['credentials:read'], createdBy: 'admin-user' });
  const unauthorizedOwner = await setupResult.apiTokenService.createToken({ name: 'Viewer', userId: 'viewer-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const expired = await setupResult.apiTokenService.createToken({ name: 'Expired', userId: 'admin-user', scopes: ['credentials:consume'], expiresAt: '2026-07-15T08:00:00.000Z', createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: scoped.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const headerFallback = await resolve(baseUrl, 'threads-credential', { 'x-credential-hub-user': 'admin-user' }, ['accessToken']);
    assert.equal(headerFallback.status, 401);
    assert.equal((await headerFallback.json()).error.code, 'API_TOKEN_AUTH_FAILED');

    const missingScope = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${unscoped.token}` }, ['accessToken']);
    assert.equal(missingScope.status, 403);
    assert.equal((await missingScope.json()).error.code, 'CONSUMER_SCOPE_MISSING');

    const missingOwnerPermission = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${unauthorizedOwner.token}` }, ['accessToken']);
    assert.equal(missingOwnerPermission.status, 403);
    assert.equal((await missingOwnerPermission.json()).error.code, 'CONSUMER_ACCESS_DENIED');

    const expiredResponse = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${expired.token}` }, ['accessToken']);
    assert.equal(expiredResponse.status, 401);
    assert.equal((await expiredResponse.json()).error.code, 'API_TOKEN_AUTH_FAILED');

    const inactive = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${scoped.token}` }, ['accessToken']);
    assert.equal(inactive.status, 409);
    assert.equal((await inactive.json()).error.code, 'CREDENTIAL_NOT_CONSUMABLE');

    const noGrant = await resolve(baseUrl, 'openai-credential', { authorization: `Bearer ${scoped.token}` }, ['apiKey']);
    assert.equal(noGrant.status, 403);
    assert.equal((await noGrant.json()).error.code, 'RESOLVE_NOT_AVAILABLE');

    const missingCredential = await resolve(baseUrl, 'missing-credential', { authorization: `Bearer ${scoped.token}` }, ['apiKey']);
    assert.equal(missingCredential.status, 404);
    assert.equal((await missingCredential.json()).error.code, 'CREDENTIAL_NOT_FOUND');

    await setupResult.apiTokenService.revokeToken(scoped.apiToken.id);
    const revoked = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${scoped.token}` }, ['accessToken']);
    assert.equal(revoked.status, 401);
    assert.equal((await revoked.json()).error.code, 'API_TOKEN_AUTH_FAILED');
  } finally {
    server.close();
  }
});
