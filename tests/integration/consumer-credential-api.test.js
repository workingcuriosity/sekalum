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
    randomBytes: () => Buffer.alloc(ApiTokenServiceConstants.TOKEN_BYTES, ++entropy),
    userIdentityProvider: (userId) => accessManagementService.getUserIdentity(userId),
    userAuthorizationProvider: (userId, permission) => accessManagementService.hasPermission(userId, permission)
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
  const credentialStore = {
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
  };
  const consumerGrantService = new ConsumerGrantService({ apiTokenService, credentialStore, providerRegistry });
  const consumerCredentialService = new ConsumerCredentialService({
    credentialStore,
    consumerGrantService,
    providerRegistry,
    runtimePublicProjectionService,
    auditLogService,
    apiTokenService
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
  const managementToken = await apiTokenService.createToken({ name: 'Grant administrator', userId: 'admin-user', scopes: ['consumer-grants:manage', 'credentials:read'], createdBy: 'admin-user' });
  return { accessManagementService, apiTokenService, auditLogService, consumerGrantService, consumerCredentialService, credentials, providerRegistry, server, managementToken: managementToken.token };
}

async function resolve(baseUrl, credentialKey, headers, secretNames) {
  return fetch(`${baseUrl}/api/v1/consumer/credentials/${credentialKey}/resolve`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ secretNames })
  });
}

async function batchResolve(baseUrl, headers, requests) {
  return fetch(`${baseUrl}/api/v1/consumer/credentials/resolve-batch`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ requests })
  });
}

async function discover(baseUrl, headers, query = '') {
  return fetch(`${baseUrl}/api/v1/consumer/credentials${query}`, { headers });
}

function assertSafeDiscoveryBody(body) {
  const serialized = JSON.stringify(body);
  assert.doesNotMatch(serialized, /credentialId|providerKey|credentialMethodKey|secretNames/);
  assert.doesNotMatch(serialized, /consumer-(integration|refresh|openai)-secret|signingSecret/);
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

test('Core Access Scope projection is authoritative, deduplicated and secret-free', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Scope consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  await setupResult.consumerGrantService.createGrant({ consumerId: consumer.apiToken.id, credentialId: 'openai-credential', providerKey: 'openai', secretNames: ['apiKey'] });
  const scope = await setupResult.consumerCredentialService.getAccessScope({ consumerId: consumer.apiToken.id });
  assert.deepEqual(scope.summary, { credentialCount: 2, secretFieldAssignmentCount: 2, providerCount: 2, activeGrantCount: 2 });
  assert.deepEqual(scope.credentials.map(({ credentialId, providerKey, permittedSecretFields }) => ({ credentialId, providerKey, permittedSecretFields })), [
    { credentialId: 'openai-credential', providerKey: 'openai', permittedSecretFields: ['apiKey'] },
    { credentialId: 'threads-credential', providerKey: 'threads', permittedSecretFields: ['accessToken'] }
  ]);
  assert.doesNotMatch(JSON.stringify(scope), /consumer-(integration|refresh|openai)-secret/);
  await assert.rejects(() => setupResult.consumerCredentialService.getAccessScope({ consumerId: 'unknown-consumer' }), { code: 'CONSUMER_NOT_FOUND' });
});

test('Access Scope includes only currently effective Consumer identities', async () => {
  const setupResult = await setup();
  const active = await setupResult.apiTokenService.createToken({ name: 'Active consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const revoked = await setupResult.apiTokenService.createToken({ name: 'Revoked consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const expired = await setupResult.apiTokenService.createToken({ name: 'Expired consumer', userId: 'admin-user', scopes: ['credentials:consume'], expiresAt: '2026-07-15T08:00:00.000Z', createdBy: 'admin-user' });
  const nonConsumer = await setupResult.apiTokenService.createToken({ name: 'Management token', userId: 'admin-user', scopes: ['credentials:read'], createdBy: 'admin-user' });
  const disabledOwner = await setupResult.apiTokenService.createToken({ name: 'Disabled owner consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.apiTokenService.revokeToken(revoked.apiToken.id);
  for (const token of [active, revoked, expired, nonConsumer]) {
    await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] }).catch((error) => {
      if (token !== active) assert.equal(error.code, 'CONSUMER_NOT_FOUND');
      else throw error;
    });
  }
  const scopes = await setupResult.consumerCredentialService.listAccessScopes();
  assert.deepEqual(scopes.map((scope) => scope.consumer.consumerId).sort(), [active.apiToken.id, disabledOwner.apiToken.id].sort());
  await setupResult.accessManagementService.updateUser('admin-user', { status: 'disabled' });
  assert.deepEqual(await setupResult.consumerCredentialService.listAccessScopes(), []);
  await assert.rejects(() => setupResult.consumerCredentialService.getAccessScope({ consumerId: revoked.apiToken.id }), { code: 'CONSUMER_NOT_FOUND' });
  await assert.rejects(() => setupResult.consumerCredentialService.getAccessScope({ consumerId: expired.apiToken.id }), { code: 'CONSUMER_NOT_FOUND' });
  await assert.rejects(() => setupResult.consumerCredentialService.getAccessScope({ consumerId: nonConsumer.apiToken.id }), { code: 'CONSUMER_NOT_FOUND' });
  await assert.rejects(() => setupResult.consumerCredentialService.getAccessScope({ consumerId: disabledOwner.apiToken.id }), { code: 'CONSUMER_NOT_FOUND' });
});

test('Core Access Scope uses the metadata-index secret inventory without loading values', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Metadata scope consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const metadataOnlyStore = {
    async load() { throw new Error('secret payload must not be loaded'); },
    async listMetadata() { return [...setupResult.credentials.values()].map((credential) => credential.toMetadataJSON()); }
  };
  const metadataService = new (setupResult.consumerCredentialService.constructor)({
    credentialStore: metadataOnlyStore,
    consumerGrantService: setupResult.consumerGrantService,
    providerRegistry: setupResult.providerRegistry,
    apiTokenService: setupResult.apiTokenService
  });
  const scope = await metadataService.getAccessScope({ consumerId: consumer.apiToken.id });
  assert.equal(scope.summary.credentialCount, 1);
  assert.deepEqual(scope.credentials[0].permittedSecretFields, ['accessToken']);
});

test('Production metadata-only CredentialStore validates Grant create/update/preview without loading Secret payloads', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Production metadata consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const credential = setupResult.credentials.get('threads-credential');
  let loadCalls = 0;
  let metadata = credential.toInternalMetadataJSON();
  const credentialStore = {
    async load() {
      loadCalls += 1;
      throw new Error('Secret payload must not be loaded');
    },
    async loadMetadata(credentialId) {
      if (credentialId !== credential.credentialId) {
        const error = new Error('missing');
        error.code = 'NOT_FOUND';
        throw error;
      }
      return metadata;
    },
    async listMetadata() { return [metadata]; }
  };
  const grantState = { revision: 0, grants: [] };
  const grantStore = {
    async load() { return grantState; },
    async save(next) {
      grantState.revision += 1;
      grantState.grants = next.grants;
    }
  };
  const grantService = new ConsumerGrantService({
    store: grantStore,
    credentialStore,
    providerRegistry: setupResult.providerRegistry,
    apiTokenService: setupResult.apiTokenService
  });
  const credentialService = new ConsumerCredentialService({
    credentialStore,
    consumerGrantService: grantService,
    providerRegistry: setupResult.providerRegistry,
    apiTokenService: setupResult.apiTokenService
  });
  const input = { consumerId: consumer.apiToken.id, credentialId: credential.credentialId, providerKey: 'threads', secretNames: ['accessToken'] };
  const prepared = await grantService.prepareGrant(input);
  const createPreview = await credentialService.previewGrant(input);
  assert.equal(createPreview.binding.decision, 'CAN_BE_SAVED');
  assert.equal(createPreview.referenceCheck.referenceOwner, 'Core');
  assert.equal(Object.hasOwn(createPreview.binding, 'secret'), false);
  const created = await grantService.createGrant(input);
  const updatePreview = await credentialService.previewGrant({ ...input, grantId: created.grantId, secretNames: ['refreshToken'] });
  const updated = await grantService.updateGrant(created.grantId, { secretNames: ['refreshToken'] });

  assert.deepEqual(
    { consumerId: created.consumerId, credentialId: created.credentialId, credentialGeneration: created.credentialGeneration, providerKey: created.providerKey, secretNames: created.secretNames },
    { consumerId: prepared.consumerId, credentialId: prepared.credentialId, credentialGeneration: prepared.credentialGeneration, providerKey: prepared.providerKey, secretNames: prepared.secretNames }
  );
  assert.deepEqual(createPreview.proposed.credentials[0].permittedSecretFields, ['accessToken']);
  assert.deepEqual(updatePreview.proposed.credentials[0].permittedSecretFields, ['refreshToken']);
  assert.deepEqual(updated.secretNames, ['refreshToken']);
  assert.equal(loadCalls, 0);
  assert.equal(grantState.grants.length, 1);
});

test('Production metadata-only Grant validation fails closed for missing or unavailable Secret values', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Metadata fail-closed consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const credential = setupResult.credentials.get('threads-credential');
  let loadCalls = 0;
  let metadata = { ...credential.toInternalMetadataJSON(), secretNames: ['accessToken'], secretInventory: [{ name: 'accessToken', hasValue: false }] };
  const credentialStore = {
    async load() {
      loadCalls += 1;
      throw new Error('Secret payload must not be loaded');
    },
    async loadMetadata() { return metadata; },
    async listMetadata() { return [metadata]; }
  };
  const grantService = new ConsumerGrantService({
    credentialStore,
    providerRegistry: setupResult.providerRegistry,
    apiTokenService: setupResult.apiTokenService
  });
  const credentialService = new ConsumerCredentialService({
    credentialStore,
    consumerGrantService: grantService,
    providerRegistry: setupResult.providerRegistry,
    apiTokenService: setupResult.apiTokenService
  });
  const input = { consumerId: consumer.apiToken.id, credentialId: credential.credentialId, providerKey: 'threads', secretNames: ['accessToken'] };
  await assert.rejects(() => grantService.createGrant(input), { code: 'CONSUMER_GRANT_SECRET_INVALID' });
  await assert.rejects(() => credentialService.previewGrant(input), { code: 'CONSUMER_GRANT_SECRET_INVALID' });

  metadata = { ...metadata, secretInventory: [] };
  await assert.rejects(() => grantService.createGrant(input), { code: 'CONSUMER_GRANT_SECRET_INVALID' });
  assert.equal(loadCalls, 0);
});

test('Access Scope preview is read-only and reports deterministic delta', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Preview consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const grant = await setupResult.consumerGrantService.createGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const preview = await setupResult.consumerCredentialService.previewGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken', 'refreshToken'], grantId: grant.grantId });
  assert.deepEqual(preview.delta, { added: ['threads-credential:refreshToken'], removed: [], status: 'increased' });
  assert.equal((await setupResult.consumerGrantService.listGrants({ consumerId: consumer.apiToken.id }))[0].secretNames.length, 1);
});

test('Create preview validates and projects a hypothetical Grant without persistence', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Create preview consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const preview = await setupResult.consumerCredentialService.previewGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  assert.equal(preview.current.summary.activeGrantCount, 0);
  assert.equal(preview.proposed.summary.activeGrantCount, 1);
  assert.deepEqual(preview.delta, { added: ['threads-credential:accessToken'], removed: [], status: 'increased' });
  assert.deepEqual(await setupResult.consumerGrantService.listGrants({ consumerId: consumer.apiToken.id }), []);
});

test('Generation/profile-bound Grant preview matches actual binding and rejects stale bindings', async () => {
  const setupResult = await setup();
  const profile = { providerKey: 'threads', version: '2.0.0', providerKind: 'oauth', digest: 'threads-profile-current' };
  const originalGet = setupResult.providerRegistry.get.bind(setupResult.providerRegistry);
  setupResult.providerRegistry.get = (providerKey) => {
    const provider = originalGet(providerKey);
    return providerKey === 'threads' ? { ...provider, providerProfile: profile } : provider;
  };
  setupResult.credentials.set('profile-credential', new Credential({
    credentialId: 'profile-credential', credentialKey: 'profile-public-key', providerKey: 'threads',
    credentialGeneration: 'generation-2', providerProfile: profile,
    providerProfileMigration: { migrationComplete: true, migrationVerified: true, profileDigest: profile.digest, source: 'test' },
    credentialMethodKey: 'oauth2', lifecycleState: 'active',
    secrets: [{ name: 'accessToken', value: 'profile-bound-secret' }, { name: 'refreshToken', value: 'profile-bound-refresh' }]
  }));
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Profile preview consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const input = { consumerId: consumer.apiToken.id, credentialId: 'profile-credential', providerKey: 'threads', secretNames: ['accessToken'] };
  const prepared = await setupResult.consumerGrantService.prepareGrant(input);
  const preview = await setupResult.consumerCredentialService.previewGrant(input);
  assert.deepEqual(preview.proposed.credentials[0].permittedSecretFields, ['accessToken']);
  assert.deepEqual(await setupResult.consumerGrantService.listGrants({ consumerId: consumer.apiToken.id }), []);
  const created = await setupResult.consumerGrantService.createGrant(input);
  assert.deepEqual(
    { consumerId: created.consumerId, credentialId: created.credentialId, credentialGeneration: created.credentialGeneration, providerKey: created.providerKey, profileDigest: created.providerProfile.digest, secretNames: created.secretNames },
    { consumerId: prepared.consumerId, credentialId: prepared.credentialId, credentialGeneration: prepared.credentialGeneration, providerKey: prepared.providerKey, profileDigest: prepared.providerProfile.digest, secretNames: prepared.secretNames }
  );
  const editPreview = await setupResult.consumerCredentialService.previewGrant({ ...input, secretNames: ['refreshToken'], grantId: created.grantId });
  assert.deepEqual(editPreview.proposed.credentials[0].permittedSecretFields, ['refreshToken']);
  const updated = await setupResult.consumerGrantService.updateGrant(created.grantId, { secretNames: ['refreshToken'] });
  assert.equal(updated.credentialGeneration, created.credentialGeneration);
  assert.equal(updated.providerProfile.digest, profile.digest);
  await assert.rejects(
    () => setupResult.consumerCredentialService.previewGrant({ ...input, credentialGeneration: 'stale-generation' }),
    { code: 'CONSUMER_GRANT_GENERATION_MISMATCH' }
  );
  await assert.rejects(
    () => setupResult.consumerCredentialService.previewGrant({ ...input, providerProfile: { ...profile, digest: 'stale-profile' } }),
    { code: 'CONSUMER_GRANT_PROFILE_MISMATCH' }
  );
});

test('Generation/profile-bound Grant mutation fails closed for unverified profile migration', async () => {
  const setupResult = await setup();
  const profile = { providerKey: 'threads', version: '2.0.0', providerKind: 'oauth', digest: 'threads-profile-current' };
  const originalGet = setupResult.providerRegistry.get.bind(setupResult.providerRegistry);
  setupResult.providerRegistry.get = (providerKey) => {
    const provider = originalGet(providerKey);
    return providerKey === 'threads' ? { ...provider, providerProfile: profile } : provider;
  };
  setupResult.credentials.set('unverified-profile-credential', new Credential({
    credentialId: 'unverified-profile-credential', credentialKey: 'unverified-public-key', providerKey: 'threads',
    credentialGeneration: 'generation-3', providerProfile: profile,
    providerProfileMigration: { migrationComplete: true, migrationVerified: false, profileDigest: profile.digest, source: 'test' },
    credentialMethodKey: 'oauth2', lifecycleState: 'active',
    secrets: [{ name: 'accessToken', value: 'unverified-profile-secret' }]
  }));
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Unverified profile consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await assert.rejects(
    () => setupResult.consumerGrantService.createGrant({ consumerId: consumer.apiToken.id, credentialId: 'unverified-profile-credential', providerKey: 'threads', secretNames: ['accessToken'] }),
    { code: 'CONSUMER_GRANT_PROFILE_MISMATCH' }
  );
});

test('Preview reports changed for equal-cardinality field replacement', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Replacement preview consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const grant = await setupResult.consumerGrantService.createGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const preview = await setupResult.consumerCredentialService.previewGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['refreshToken'], grantId: grant.grantId });
  assert.deepEqual(preview.delta, { added: ['threads-credential:refreshToken'], removed: ['threads-credential:accessToken'], status: 'changed' });
  assert.deepEqual((await setupResult.consumerGrantService.listGrants({ consumerId: consumer.apiToken.id }))[0].secretNames, ['accessToken']);
});

test('Preview reports unchanged and reduced set relations and rejects invalid proposals', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'Delta preview consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const grant = await setupResult.consumerGrantService.createGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken', 'refreshToken'] });
  const unchanged = await setupResult.consumerCredentialService.previewGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken', 'refreshToken'], grantId: grant.grantId });
  assert.deepEqual(unchanged.delta, { added: [], removed: [], status: 'unchanged' });
  const reduced = await setupResult.consumerCredentialService.previewGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'], grantId: grant.grantId });
  assert.deepEqual(reduced.delta, { added: [], removed: ['threads-credential:refreshToken'], status: 'reduced' });
  await assert.rejects(() => setupResult.consumerCredentialService.previewGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['clientId'] }), { code: 'CONSUMER_GRANT_SECRET_INVALID' });
});

test('HTTP management Access Scope and Credential reverse projection never expose secret values', async () => {
  const setupResult = await setup();
  const consumer = await setupResult.apiTokenService.createToken({ name: 'HTTP scope consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: consumer.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);
  try {
    const management = { authorization: `Bearer ${setupResult.managementToken}` };
    const scopeResponse = await fetch(`${baseUrl}/api/v1/management/consumer-grants/access-scope?consumerId=${encodeURIComponent(consumer.apiToken.id)}`, { headers: management });
    const scopeBody = await scopeResponse.json();
    assert.equal(scopeResponse.status, 200);
    assert.equal(scopeBody.data.summary.activeGrantCount, 1);
    assert.doesNotMatch(JSON.stringify(scopeBody), /consumer-(integration|refresh)-secret/);
    const reverseResponse = await fetch(`${baseUrl}/api/v1/management/credentials/threads-credential/access-scope`, { headers: management });
    const reverseBody = await reverseResponse.json();
    assert.equal(reverseResponse.status, 200);
    assert.deepEqual(reverseBody.data.consumers, [{ consumerId: consumer.apiToken.id, grantedSecretFields: ['accessToken'] }]);
    assert.doesNotMatch(JSON.stringify(reverseBody), /consumer-(integration|refresh)-secret/);
  } finally { server.close(); }
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

test('Consumer Discovery filters only the authorized public metadata and supports Discover-Select-Resolve', async () => {
  const setupResult = await setup();
  setupResult.credentials.set('threads-credential', new Credential({
    ...setupResult.credentials.get('threads-credential').toJSON(),
    metadata: { displayName: 'Shared Integration', tags: ['Primary', 'Social'] }
  }));
  setupResult.credentials.set('openai-credential', new Credential({
    ...setupResult.credentials.get('openai-credential').toJSON(),
    metadata: { displayName: 'Shared Integration', tags: ['Primary', 'AI'] }
  }));
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const filtered = await discover(baseUrl, { authorization: `Bearer ${token.token}` }, '?displayName=shared%20integration&tag=primary');
    const filteredBody = await filtered.json();
    assert.equal(filtered.status, 200);
    assert.deepEqual(filteredBody.data.credentials.map(({ credentialKey }) => credentialKey), ['threads-public-key']);
    assert.deepEqual(filteredBody.data.credentials[0].metadata, { displayName: 'Shared Integration', tags: ['Primary', 'Social'] });
    assertSafeDiscoveryBody(filteredBody);

    const selected = filteredBody.data.credentials[0].credentialKey;
    const resolved = await resolve(baseUrl, selected, { authorization: `Bearer ${token.token}` }, ['accessToken']);
    const resolvedBody = await resolved.json();
    assert.equal(resolved.status, 200);
    assert.equal(resolvedBody.data.secrets.accessToken, 'consumer-integration-secret');
    assert.doesNotMatch(JSON.stringify(filteredBody), /openai-public-key|openai-credential/);
  } finally {
    server.close();
  }
});

test('Consumer Discovery filters support zero, one, multiple and unfiltered results', async () => {
  const setupResult = await setup();
  setupResult.credentials.set('threads-credential', new Credential({
    ...setupResult.credentials.get('threads-credential').toJSON(),
    metadata: { displayName: 'Threads Primary', tags: ['shared'] }
  }));
  setupResult.credentials.set('openai-credential', new Credential({
    ...setupResult.credentials.get('openai-credential').toJSON(),
    metadata: { displayName: 'OpenAI Primary', tags: ['shared'] }
  }));
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'openai-credential', providerKey: 'openai', secretNames: ['apiKey'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    for (const [query, expected] of [
      ['', 2],
      ['?tag=shared', 2],
      ['?displayName=threads%20primary', 1],
      ['?displayName=not-found', 0]
    ]) {
      const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` }, query);
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.data.credentials.length, expected);
      assertSafeDiscoveryBody(body);
    }
  } finally {
    server.close();
  }
});

test('Consumer Discovery rejects unsupported and repeated filters without leaking query details', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    for (const query of ['?provider=threads', '?tag=one&tag=two']) {
      const response = await discover(baseUrl, { authorization: `Bearer ${token.token}` }, query);
      assert.equal(response.status, 400);
      const body = await response.json();
      assert.deepEqual(body.error, { code: 'INVALID_DISCOVERY_FILTER', message: 'Credential discovery filters are invalid' });
      assertSafeDiscoveryBody(body);
      assert.doesNotMatch(JSON.stringify(body), /threads|one|two/);
    }
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
    const resolveAudit = audit.filter((entry) => entry.action === 'consumer-credential.resolve');
    assert.equal(resolveAudit.length, 2);
    assert.equal(resolveAudit.every((entry) => entry.actorType === 'consumer'), true);
    assert.equal(resolveAudit.every((entry) => entry.userId === null), true);
    assert.equal(resolveAudit.every((entry) => entry.consumerId === token.apiToken.id), true);
    assert.equal(resolveAudit.every((entry) => entry.apiTokenId === token.apiToken.id), true);
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

test('Consumer REST API batch Resolves independent entries and returns safe partial errors', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'openai-credential', providerKey: 'openai', secretNames: ['apiKey'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const response = await batchResolve(baseUrl, { authorization: `Bearer ${token.token}` }, [
      { credentialKey: 'threads-public-key', secretNames: ['accessToken'] },
      { credentialKey: 'openai-public-key', secretNames: ['apiKey'] },
      { credentialKey: 'missing-public-key', secretNames: ['apiKey'] },
      { credentialKey: 'threads-public-key', secretNames: ['clientId'] }
    ]);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(body.data.summary, { total: 4, succeeded: 2, failed: 2 });
    assert.deepEqual(body.data.results.map(({ index, credentialKey, success, error }) => ({ index, credentialKey, success, code: error?.code })), [
      { index: 0, credentialKey: 'threads-public-key', success: true, code: undefined },
      { index: 1, credentialKey: 'openai-public-key', success: true, code: undefined },
      { index: 2, credentialKey: 'missing-public-key', success: false, code: 'RESOLVE_NOT_AVAILABLE' },
      { index: 3, credentialKey: 'threads-public-key', success: false, code: 'RESOLVE_NOT_AVAILABLE' }
    ]);
    assert.equal(body.data.results[0].data.secrets.accessToken, 'consumer-integration-secret');
    assert.equal(body.data.results[1].data.secrets.apiKey, 'consumer-openai-secret');
    assert.doesNotMatch(JSON.stringify(body.data.results.slice(2)), /consumer-(integration|openai|refresh)-secret/);
  } finally {
    server.close();
  }
});

test('Consumer REST API batch Resolve returns all-failure results and rejects invalid envelopes', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const failed = await batchResolve(baseUrl, { authorization: `Bearer ${token.token}` }, [
      { credentialKey: 'missing-a', secretNames: ['apiKey'] },
      { credentialKey: 'missing-b', secretNames: ['apiKey'] }
    ]);
    const failedBody = await failed.json();
    assert.equal(failed.status, 200);
    assert.deepEqual(failedBody.data.summary, { total: 2, succeeded: 0, failed: 2 });
    assert.deepEqual(failedBody.data.results.map(({ error }) => error.code), ['RESOLVE_NOT_AVAILABLE', 'RESOLVE_NOT_AVAILABLE']);

    const invalid = await batchResolve(baseUrl, { authorization: `Bearer ${token.token}` }, []);
    const invalidBody = await invalid.json();
    assert.equal(invalid.status, 400);
    assert.deepEqual(invalidBody.error, { code: 'INVALID_BATCH_REQUEST', message: 'Batch Resolve accepts between 1 and 20 requests' });
  } finally {
    server.close();
  }
});

test('Consumer Resolve isolates same-provider credentials across sequential, iterative and concurrent reuse', async () => {
  const setupResult = await setup();
  const secondCredential = new Credential({
    credentialId: 'threads-credential-2',
    credentialKey: 'threads-public-key-2',
    providerKey: 'threads',
    credentialMethodKey: 'oauth2',
    lifecycleState: 'active',
    secrets: [{ name: 'accessToken', value: 'consumer-second-secret' }, { name: 'refreshToken', value: 'consumer-second-refresh' }]
  });
  setupResult.credentials.set(secondCredential.credentialId, secondCredential);
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: secondCredential.credentialId, providerKey: 'threads', secretNames: ['accessToken'] });
  const { server, baseUrl } = await listen(setupResult.server.app);

  try {
    const expected = new Map([
      ['threads-public-key', 'consumer-integration-secret'],
      ['threads-public-key-2', 'consumer-second-secret']
    ]);
    for (let iteration = 0; iteration < 3; iteration += 1) {
      for (const [credentialKey, secret] of expected) {
        const response = await resolve(baseUrl, credentialKey, { authorization: `Bearer ${token.token}` }, ['accessToken']);
        assert.equal(response.status, 200);
        assert.deepEqual((await response.json()).data.secrets, { accessToken: secret });
      }
    }

    const concurrent = await Promise.all([...expected.keys()].flatMap((credentialKey) =>
      Array.from({ length: 4 }, () => resolve(baseUrl, credentialKey, { authorization: `Bearer ${token.token}` }, ['accessToken']))
    ));
    for (const response of concurrent) {
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.data.secrets.accessToken, expected.get(body.data.credentialKey));
    }

    const audit = JSON.stringify(await setupResult.auditLogService.list());
    assert.doesNotMatch(audit, /consumer-(integration|second|refresh)-secret/);
  } finally {
    server.close();
  }
});

test('Consumer REST API permits only secret fields of the credential selected method', async () => {
  const setupResult = await setup();
  const token = await setupResult.apiTokenService.createToken({ name: 'Consumer', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: token.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
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
  const setupResult = await setup();
  const scoped = await setupResult.apiTokenService.createToken({ name: 'Scoped', userId: 'admin-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const unscoped = await setupResult.apiTokenService.createToken({ name: 'Unscoped', userId: 'admin-user', scopes: ['credentials:read'], createdBy: 'admin-user' });
  const unauthorizedOwner = await setupResult.apiTokenService.createToken({ name: 'Viewer', userId: 'viewer-user', scopes: ['credentials:consume'], createdBy: 'admin-user' });
  const expired = await setupResult.apiTokenService.createToken({ name: 'Expired', userId: 'admin-user', scopes: ['credentials:consume'], expiresAt: '2026-07-15T08:00:00.000Z', createdBy: 'admin-user' });
  await setupResult.consumerGrantService.createGrant({ consumerId: scoped.apiToken.id, credentialId: 'threads-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  setupResult.credentials.set('threads-credential', new Credential({ ...setupResult.credentials.get('threads-credential').toJSON(), lifecycleState: 'revoked' }));
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
    assert.equal(inactive.status, 403);
    const inactiveBody = await inactive.json();
    assert.deepEqual(inactiveBody.error, {
      code: 'RESOLVE_NOT_AVAILABLE',
      message: 'The requested credential is not available to this consumer'
    });

    const noGrant = await resolve(baseUrl, 'openai-credential', { authorization: `Bearer ${scoped.token}` }, ['apiKey']);
    assert.equal(noGrant.status, 403);
    const noGrantBody = await noGrant.json();
    assert.deepEqual(noGrantBody.error, inactiveBody.error);

    const missingCredential = await resolve(baseUrl, 'missing-credential', { authorization: `Bearer ${scoped.token}` }, ['apiKey']);
    assert.equal(missingCredential.status, 403);
    const missingCredentialBody = await missingCredential.json();
    assert.deepEqual(missingCredentialBody.error, inactiveBody.error);

    await setupResult.apiTokenService.revokeToken(scoped.apiToken.id);
    const revoked = await resolve(baseUrl, 'threads-credential', { authorization: `Bearer ${scoped.token}` }, ['accessToken']);
    assert.equal(revoked.status, 401);
    assert.equal((await revoked.json()).error.code, 'API_TOKEN_AUTH_FAILED');
  } finally {
    server.close();
  }
});
