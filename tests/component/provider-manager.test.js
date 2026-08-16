import test from 'node:test';
import assert from 'node:assert/strict';

import { ProviderManager } from '../../src/managers/provider-manager.js';
import { ProviderCapabilities } from '../../src/models/provider-capabilities.js';
import { ProviderCapability } from '../../src/models/provider-capability.js';
import { ProviderResult } from '../../src/models/provider-result.js';
import { OAuthResult } from '../../src/models/oauth-result.js';
import { OAuthSecurityService } from '../../src/oauth/oauth-security-service.js';

function createLogger() {
  return {
    infoEntries: [],
    errorEntries: [],
    info(message, context = {}) {
      this.infoEntries.push({ message, context });
    },
    error(message, context = {}) {
      this.errorEntries.push({ message, context });
    }
  };
}

function createManager({ provider, capabilities }) {
  const logger = createLogger();
  const definition = {
    name: 'threads',
    provider,
    capabilities: new ProviderCapabilities(capabilities)
  };

  const providerRegistry = {
    get(name) {
      if (name !== 'threads') {
        throw new Error(`Provider not registered: ${name}`);
      }
      return definition;
    }
  };

  return {
    manager: new ProviderManager({ providerRegistry, logger }),
    logger
  };
}

test('ProviderManager delegates supported OAuth start and returns ProviderResult', async () => {
  const provider = {
    startOAuth(options) {
      return ProviderResult.success({ authorizationUrl: `https://example.test/${options.state}` });
    }
  };

  const { manager, logger } = createManager({
    provider,
    capabilities: [ProviderCapability.OAUTH]
  });

  const result = await manager.startOAuth('threads', { state: 'abc' });

  assert.equal(result.success, true);
  assert.equal(result.data.authorizationUrl, 'https://example.test/abc');
  assert.equal(logger.infoEntries.length, 2);
  assert.equal(logger.errorEntries.length, 0);
});

test('ProviderManager never writes provider failure messages to logs', async () => {
  const { manager, logger } = createManager({
    provider: {
      validateCredential() {
        return ProviderResult.failure({
          code: 'ECONNREFUSED',
          message: 'Connection failed for password very-secret'
        });
      }
    },
    capabilities: [ProviderCapability.VALIDATION]
  });

  const result = await manager.validateCredential({
    credentialId: 'credential-1',
    providerKey: 'threads'
  });

  assert.equal(result.success, false);
  assert.equal(logger.errorEntries.length, 1);
  assert.equal(JSON.stringify(logger.errorEntries[0]).includes('very-secret'), false);
  assert.deepEqual(logger.errorEntries[0].context.error, {
    name: 'ProviderError',
    code: 'ECONNREFUSED',
    statusCode: null
  });
});

test('ProviderManager carries encrypted provider configuration through start and callback', async () => {
  const calls = [];
  const provider = {
    startOAuth(options) {
      calls.push(['start', options.providerConfiguration]);
      return ProviderResult.success({ authorizationUrl: 'https://provider.example.test/oauth' });
    },
    handleOAuthCallback(options) {
      calls.push(['callback', options.providerConfiguration]);
      return ProviderResult.success(new OAuthResult({
        providerId: 'threads:account',
        provider: 'threads',
        accountId: 'account',
        accessToken: 'access-token'
      }));
    }
  };
  const definition = {
    name: 'threads',
    provider,
    capabilities: new ProviderCapabilities([ProviderCapability.OAUTH]),
    credentialFields: [
      { key: 'clientId', required: true, section: 'providerConfiguration' },
      { key: 'clientSecret', required: true, secret: true, section: 'providerConfiguration' },
      { key: 'redirectUri', required: true, section: 'providerConfiguration' }
    ]
  };
  const manager = new ProviderManager({
    providerRegistry: { get() { return definition; } },
    oauthSecurityService: new OAuthSecurityService(),
    providerConfigurationService: {
      async prepare({ values }) {
        return { configurationId: 'configuration-1', providerKey: 'threads', configuration: { ...values } };
      }
    },
    logger: createLogger()
  });
  const configuration = {
    clientId: 'client-id',
    clientSecret: 'client-secret',
    redirectUri: 'https://credential-hub.example.com/oauth/threads/callback'
  };

  const started = await manager.startOAuth('threads', { state: 'state-1', providerConfiguration: configuration });
  const completed = await manager.handleOAuthCallback('threads', { state: 'state-1', code: 'code-1' });

  assert.equal(started.data.providerConfigurationId, 'configuration-1');
  assert.deepEqual(calls, [['start', configuration], ['callback', configuration]]);
  assert.equal(completed.data.metadata.providerConfigurationId, 'configuration-1');
});

test('ProviderManager removes provider configuration after OAuth start and callback failures', async () => {
  const removed = [];
  const provider = {
    startOAuth() {
      return ProviderResult.failure({ code: 'OAUTH_START_FAILED', message: 'failed' });
    },
    handleOAuthCallback() {
      return ProviderResult.failure({ code: 'OAUTH_CALLBACK_FAILED', message: 'failed' });
    }
  };
  const definition = {
    name: 'threads',
    provider,
    capabilities: new ProviderCapabilities([ProviderCapability.OAUTH]),
    credentialFields: [{ key: 'clientId', required: true, section: 'providerConfiguration' }]
  };
  const configurationService = {
    async prepare({ values }) {
      return { configurationId: 'configuration-start', providerKey: 'threads', configuration: { ...values } };
    },
    async remove(id, providerKey) {
      removed.push([id, providerKey]);
      return true;
    }
  };
  const securityService = new OAuthSecurityService();
  const manager = new ProviderManager({
    providerRegistry: { get() { return definition; } },
    oauthSecurityService: securityService,
    providerConfigurationService: configurationService,
    logger: createLogger()
  });

  const start = await manager.startOAuth('threads', {
    state: 'failed-start',
    providerConfiguration: { clientId: 'client-id' }
  });
  assert.equal(start.success, false);

  provider.startOAuth = () => ProviderResult.success({ authorizationUrl: 'https://provider.example.test/oauth' });
  configurationService.prepare = async ({ values }) => ({
    configurationId: 'configuration-callback',
    providerKey: 'threads',
    configuration: { ...values }
  });
  await manager.startOAuth('threads', {
    state: 'failed-callback',
    providerConfiguration: { clientId: 'client-id' }
  });
  const callback = await manager.handleOAuthCallback('threads', {
    state: 'failed-callback',
    code: 'bad-code'
  });

  assert.equal(callback.success, false);
  assert.deepEqual(removed, [
    ['configuration-start', 'threads'],
    ['configuration-callback', 'threads']
  ]);
});

test('ProviderManager removes provider configuration when OAuth is cancelled', async () => {
  const removed = [];
  const provider = {
    startOAuth() {
      return ProviderResult.success({ authorizationUrl: 'https://provider.example.test/oauth' });
    }
  };
  const definition = {
    name: 'threads',
    provider,
    capabilities: new ProviderCapabilities([ProviderCapability.OAUTH]),
    credentialFields: [{ key: 'clientId', required: true, section: 'providerConfiguration' }]
  };
  const manager = new ProviderManager({
    providerRegistry: { get() { return definition; } },
    oauthSecurityService: new OAuthSecurityService(),
    providerConfigurationService: {
      async prepare({ values }) {
        return { configurationId: 'configuration-cancel', providerKey: 'threads', configuration: { ...values } };
      },
      async remove(id, providerKey) {
        removed.push([id, providerKey]);
        return true;
      }
    },
    logger: createLogger()
  });

  await manager.startOAuth('threads', {
    state: 'cancelled-state',
    providerConfiguration: { clientId: 'client-id' }
  });
  assert.equal(await manager.cancelOAuth('threads', 'cancelled-state'), true);
  assert.deepEqual(removed, [['configuration-cancel', 'threads']]);
});

test('ProviderManager removes provider configuration when OAuth state creation fails', async () => {
  const removed = [];
  const definition = {
    name: 'threads',
    provider: { startOAuth() { throw new Error('must not run'); } },
    capabilities: new ProviderCapabilities([ProviderCapability.OAUTH]),
    credentialFields: [{ key: 'clientId', required: true, section: 'providerConfiguration' }]
  };
  const manager = new ProviderManager({
    providerRegistry: { get() { return definition; } },
    oauthSecurityService: {
      createAuthorizationContext() { throw new Error('state creation failed'); }
    },
    providerConfigurationService: {
      async prepare({ values }) {
        return { configurationId: 'configuration-state-error', providerKey: 'threads', configuration: { ...values } };
      },
      async remove(id, providerKey) {
        removed.push([id, providerKey]);
        return true;
      }
    },
    logger: createLogger()
  });

  const result = await manager.startOAuth('threads', {
    providerConfiguration: { clientId: 'client-id' }
  });

  assert.equal(result.success, false);
  assert.deepEqual(removed, [['configuration-state-error', 'threads']]);
});

test('ProviderManager removes provider configuration for an expired OAuth state', async () => {
  const removed = [];
  const definition = {
    name: 'threads',
    provider: {
      startOAuth() { return ProviderResult.success({ authorizationUrl: 'https://provider.example.test/oauth' }); },
      handleOAuthCallback() { throw new Error('must not run'); }
    },
    capabilities: new ProviderCapabilities([ProviderCapability.OAUTH]),
    credentialFields: [{ key: 'clientId', required: true, section: 'providerConfiguration' }]
  };
  const manager = new ProviderManager({
    providerRegistry: { get() { return definition; } },
    oauthSecurityService: new OAuthSecurityService({ ttlMs: -1 }),
    providerConfigurationService: {
      async prepare({ values }) {
        return { configurationId: 'configuration-expired', providerKey: 'threads', configuration: { ...values } };
      },
      async remove(id, providerKey) {
        removed.push([id, providerKey]);
        return true;
      }
    },
    logger: createLogger()
  });

  await manager.startOAuth('threads', {
    state: 'expired-state',
    providerConfiguration: { clientId: 'client-id' }
  });
  const result = await manager.handleOAuthCallback('threads', {
    state: 'expired-state',
    code: 'code'
  });

  assert.equal(result.success, false);
  assert.equal(result.error.code, 'OAUTH_STATE_INVALID');
  assert.deepEqual(removed, [['configuration-expired', 'threads']]);
});

test('ProviderManager rejects unsupported capabilities before provider call', async () => {
  let called = false;
  const provider = {
    healthCheck() {
      called = true;
      return ProviderResult.success({ ok: true });
    }
  };

  const { manager, logger } = createManager({ provider, capabilities: [] });

  const result = await manager.healthCheck('threads');

  assert.equal(result.success, false);
  assert.equal(called, false);
  assert.match(result.error.message, /does not support capability/);
  assert.equal(logger.errorEntries.length, 1);
});

test('ProviderManager converts provider contract violations into ProviderResult failure', async () => {
  const provider = {
    startOAuth() {
      return { authorizationUrl: 'https://example.test' };
    }
  };

  const { manager, logger } = createManager({
    provider,
    capabilities: [ProviderCapability.OAUTH]
  });

  const result = await manager.startOAuth('threads');

  assert.equal(result.success, false);
  assert.match(result.error.message, /expected ProviderResult/);
  assert.equal(logger.errorEntries.length >= 1, true);
});

test('ProviderManager validates token operations before registry access', async () => {
  const logger = createLogger();
  const providerRegistry = {
    get() {
      throw new Error('registry should not be called');
    }
  };

  const manager = new ProviderManager({ providerRegistry, logger });
  const result = await manager.refreshToken(null);

  assert.equal(result.success, false);
  assert.equal(result.error.message, 'credential record is required');
  assert.equal(logger.errorEntries.length, 1);
});

test('ProviderManager returns public provider metadata without leaking provider definitions', () => {
  const logger = createLogger();
  const definition = {
    name: 'threads',
    provider: { internal: true },
    oauthService: { authorizationUrl: 'https://threads.net/oauth/authorize', internal: true },
    displayName: 'Threads',
    description: 'Meta Threads OAuth provider',
    capabilities: new ProviderCapabilities([
      ProviderCapability.OAUTH,
      ProviderCapability.REFRESH
    ])
  };

  const providerRegistry = {
    list() {
      return ['threads'];
    },
    has(name) {
      return name === 'threads';
    },
    get(name) {
      assert.equal(name, 'threads');
      return definition;
    }
  };

  const manager = new ProviderManager({ providerRegistry, logger });

  assert.deepEqual(manager.listProviders(), [
    {
      key: 'threads',
      displayName: 'Threads',
      description: 'Meta Threads OAuth provider',
      category: null,
      customProvider: false,
      capabilities: ['oauth', 'refresh'],
      credentialFields: [],
      providerConfigurationFields: [],
      credentialMethods: [],
      providerMethodBindings: [],
      authType: null,
      defaultScopes: [],
      oauthSecurity: null,
      oauthTechnical: { authorizationEndpoint: 'https://threads.net/oauth/authorize' }
    }
  ]);

  assert.deepEqual(manager.getProvider('threads'), {
    key: 'threads',
    displayName: 'Threads',
    description: 'Meta Threads OAuth provider',
    category: null,
    customProvider: false,
    capabilities: ['oauth', 'refresh'],
    credentialFields: [],
    providerConfigurationFields: [],
    credentialMethods: [],
    providerMethodBindings: [],
    authType: null,
    defaultScopes: [],
    oauthSecurity: null,
    oauthTechnical: { authorizationEndpoint: 'https://threads.net/oauth/authorize' }
  });
});

test('ProviderManager falls back to provider key when optional metadata is missing', () => {
  const logger = createLogger();
  const definition = {
    name: 'threads',
    provider: {},
    capabilities: new ProviderCapabilities([])
  };

  const providerRegistry = {
    has(name) {
      return name === 'threads';
    },
    get() {
      return definition;
    }
  };

  const manager = new ProviderManager({ providerRegistry, logger });

  assert.deepEqual(manager.getProvider('threads'), {
    key: 'threads',
    displayName: 'threads',
    description: null,
    category: null,
    customProvider: false,
    capabilities: [],
    credentialFields: [],
    providerConfigurationFields: [],
    credentialMethods: [],
    providerMethodBindings: [],
    authType: null,
    defaultScopes: [],
    oauthSecurity: null,
    oauthTechnical: null
  });
});

test('ProviderManager serializes declarative credential methods without runtime adapters', () => {
  const logger = createLogger();
  const definition = {
    displayName: 'Discord',
    capabilities: new ProviderCapabilities([]),
    credentialMethods: [{
      toJSON() {
        return { key: 'webhook', displayName: 'Webhook', credentialFields: [], operationCapabilities: [] };
      }
    }],
    providerMethodBindings: [{
      toJSON() {
        return { methodKey: 'webhook', displayName: 'Discord Webhook', metadata: {}, operationCapabilities: [] };
      },
      operationAdapters: { validation() {} }
    }]
  };
  const providerRegistry = {
    has(name) { return name === 'discord'; },
    get() { return definition; }
  };

  const provider = new ProviderManager({ providerRegistry, logger }).getProvider('discord');

  assert.deepEqual(provider.credentialMethods, [{
    key: 'webhook', displayName: 'Webhook', credentialFields: [], operationCapabilities: []
  }]);
  assert.deepEqual(provider.providerMethodBindings, [{
    methodKey: 'webhook', displayName: 'Discord Webhook', metadata: {}, operationCapabilities: []
  }]);
  assert.equal('operationAdapters' in provider.providerMethodBindings[0], false);
});
