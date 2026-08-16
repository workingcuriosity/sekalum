import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';

function createServer() {
  const providers = new Map([
    ['threads', {
      key: 'threads',
      displayName: 'Threads',
      description: 'Meta Threads OAuth provider',
      capabilities: ['oauth', 'refresh', 'validation'],
      credentialFields: [],
      credentialMethods: [{
        key: 'oauth2',
        displayName: 'OAuth 2.0',
        credentialFields: [],
        operationCapabilities: ['refresh']
      }, {
        key: 'webhook',
        displayName: 'Webhook',
        credentialFields: [],
        operationCapabilities: []
      }],
      providerMethodBindings: [{
        methodKey: 'oauth2',
        displayName: 'Threads OAuth 2.0',
        metadata: {},
        operationCapabilities: []
      }, {
        methodKey: 'webhook',
        displayName: 'Threads Webhook',
        metadata: { eventTypes: ['message.created'] },
        operationCapabilities: []
      }],
      oauthTechnical: { authorizationEndpoint: 'https://threads.net/oauth/authorize' }
    }]
  ]);

  const providerManager = {
      listProviders() {
        return Array.from(providers.values());
      },
      getProvider(providerKey) {
        return providers.get(providerKey) ?? null;
      },
      getProviderCapabilities(providerKey) {
        return providers.get(providerKey)?.capabilities ?? null;
      }
    };
  const customProviderService = {
    async create(input) {
      if (input.providerConfigurationFields || input.oauth || input.runtimeOperations || input.secrets || input.credentialMethods?.some((method) => method.operationCapabilities?.length)) {
        const error = new Error('Provider definition contains unsupported property');
        error.code = 'PROVIDER_DEFINITION_INVALID';
        error.statusCode = 400;
        throw error;
      }
      if (providers.has(input.key)) {
        const error = new Error(`Provider '${input.key}' already exists`);
        error.code = 'PROVIDER_ALREADY_EXISTS';
        error.statusCode = 409;
        throw error;
      }
      providers.set(input.key, {
        key: input.key,
        displayName: input.displayName,
        description: input.description ?? null,
        category: input.category,
        capabilities: [],
        credentialFields: input.credentialFields,
        credentialMethods: input.credentialMethods.map((method) => ({ ...method, operationCapabilities: [] })),
        providerMethodBindings: input.providerMethodBindings.map((binding) => ({ ...binding, metadata: {}, operationCapabilities: [] })),
        providerConfigurationFields: [],
        authType: null,
        defaultScopes: [],
        oauthSecurity: null,
        oauthTechnical: null
      });
      return { key: input.key };
    }
  };

  return new OAuthCallbackServer({
    providerManager,
    customProviderService,
    importTokenCommand: {},
    credentialManager: {},
    config: {
      get() {
        return 0;
      }
    },
    logger: {
      success() {},
      error() {}
    }
  });
}

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

test('HTTP providers list endpoint returns registered providers', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.deepEqual(body.data, [
      {
        providerKey: 'threads',
        key: 'threads',
        displayName: 'Threads',
        description: 'Meta Threads OAuth provider',
        category: null,
        customProvider: false,
        capabilities: ['oauth', 'refresh', 'validation'],
        credentialFields: [],
        providerConfigurationFields: [],
        credentialMethods: [
          { key: 'oauth2', displayName: 'OAuth 2.0', credentialFields: [], operationCapabilities: ['refresh'] },
          { key: 'webhook', displayName: 'Webhook', credentialFields: [], operationCapabilities: [] }
        ],
        providerMethodBindings: [
          { methodKey: 'oauth2', displayName: 'Threads OAuth 2.0', metadata: {}, operationCapabilities: [] },
          { methodKey: 'webhook', displayName: 'Threads Webhook', metadata: { eventTypes: ['message.created'] }, operationCapabilities: [] }
        ],
        authType: null,
        defaultScopes: [],
        oauthSecurity: null,
        oauthTechnical: {
          authorizationEndpoint: 'https://threads.net/oauth/authorize',
          callbackPath: '/oauth/threads/callback',
          redirectUri: `${baseUrl}/oauth/threads/callback`
        }
      }
    ]);
  } finally {
    server.close();
  }
});

test('HTTP providers get endpoint returns provider metadata', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/threads`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.deepEqual(body.data, {
      providerKey: 'threads',
      key: 'threads',
      displayName: 'Threads',
      description: 'Meta Threads OAuth provider',
      category: null,
      customProvider: false,
      capabilities: ['oauth', 'refresh', 'validation'],
      credentialFields: [],
      providerConfigurationFields: [],
      credentialMethods: [
        { key: 'oauth2', displayName: 'OAuth 2.0', credentialFields: [], operationCapabilities: ['refresh'] },
        { key: 'webhook', displayName: 'Webhook', credentialFields: [], operationCapabilities: [] }
      ],
      providerMethodBindings: [
        { methodKey: 'oauth2', displayName: 'Threads OAuth 2.0', metadata: {}, operationCapabilities: [] },
        { methodKey: 'webhook', displayName: 'Threads Webhook', metadata: { eventTypes: ['message.created'] }, operationCapabilities: [] }
      ],
      authType: null,
      defaultScopes: [],
      oauthSecurity: null,
      oauthTechnical: {
        authorizationEndpoint: 'https://threads.net/oauth/authorize',
        callbackPath: '/oauth/threads/callback',
        redirectUri: `${baseUrl}/oauth/threads/callback`
      }
    });
  } finally {
    server.close();
  }
});

test('HTTP providers capabilities endpoint returns provider capabilities', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/threads/capabilities`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.deepEqual(body.data, {
      providerKey: 'threads',
      capabilities: ['oauth', 'refresh', 'validation']
    });
  } finally {
    server.close();
  }
});

test('HTTP providers endpoint returns not found for unknown provider', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/missing`);
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'NOT_FOUND');
    assert.match(body.error.message, /Provider not found/);
  } finally {
    server.close();
  }
});

test('HTTP providers create endpoint makes a declarative provider immediately available with public methods and bindings', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);
  const input = {
    key: 'acme-service', displayName: 'Acme Service', category: 'CRM', description: 'Declarative provider',
    credentialMethods: [{ key: 'api-key', displayName: 'API key', credentialFields: [{ key: 'apiKey', label: 'API key', type: 'api-key', secret: true }], operationCapabilities: [] }],
    providerMethodBindings: [{ methodKey: 'api-key', displayName: 'Acme API key' }],
    credentialFields: [{ key: 'apiKey', label: 'API key', type: 'api-key', secret: true }]
  };

  try {
    const created = await fetch(`${baseUrl}/api/v1/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin' }, body: JSON.stringify(input)
    });
    const body = await created.json();

    assert.equal(created.status, 201);
    assert.equal(body.success, true);
    assert.equal(body.data.providerKey, 'acme-service');
    assert.equal(body.data.category, 'CRM');
    assert.deepEqual(body.data.credentialMethods.map(({ key, displayName, operationCapabilities }) => ({ key, displayName, operationCapabilities })), [{ key: 'api-key', displayName: 'API key', operationCapabilities: [] }]);
    assert.deepEqual(body.data.providerMethodBindings, [{ methodKey: 'api-key', displayName: 'Acme API key', metadata: {}, operationCapabilities: [] }]);
    assert.equal('provider' in body.data, false);
    assert.equal('secrets' in body.data, false);

    const selected = await fetch(`${baseUrl}/api/v1/providers/acme-service`);
    assert.equal(selected.status, 200);
    assert.equal((await selected.json()).data.providerKey, 'acme-service');
  } finally {
    server.close();
  }
});

test('HTTP providers create endpoint rejects provider configuration and duplicate definitions', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    for (const input of [
      { key: 'unsafe', providerConfigurationFields: [] },
      { key: 'unsafe', credentialMethods: [{ operationCapabilities: ['refresh'] }] }
    ]) {
      const forbidden = await fetch(`${baseUrl}/api/v1/providers`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin' }, body: JSON.stringify(input)
      });
      assert.equal(forbidden.status, 400);
      assert.equal((await forbidden.json()).error.code, 'PROVIDER_DEFINITION_INVALID');
    }

    const duplicate = await fetch(`${baseUrl}/api/v1/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin' }, body: JSON.stringify({ key: 'threads' })
    });
    assert.equal(duplicate.status, 409);
    assert.equal((await duplicate.json()).error.code, 'PROVIDER_ALREADY_EXISTS');
  } finally {
    server.close();
  }
});
