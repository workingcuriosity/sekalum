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
  const customDefinitions = new Map();

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
      const summary = {
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
      };
      customDefinitions.set(input.key, { ...summary, enabled: true });
      providers.set(input.key, summary);
      return { key: input.key };
    },
    async listManagement() {
      return [...customDefinitions.values()].map(({ key, displayName, description, category, enabled }) => ({
        providerKey: key,
        key,
        customProvider: true,
        enabled,
        displayName,
        description,
        category
      }));
    },
    async disable(providerKey) {
      const definition = customDefinitions.get(providerKey);
      if (!definition) {
        const error = new Error(`Built-in provider '${providerKey}' cannot be changed`);
        error.code = 'BUILTIN_PROVIDER_IMMUTABLE';
        error.statusCode = 400;
        throw error;
      }
      definition.enabled = false;
      providers.delete(providerKey);
      return { providerKey, enabled: false, customProvider: true, displayName: definition.displayName, description: definition.description, category: definition.category };
    },
    async enable(providerKey) {
      const definition = customDefinitions.get(providerKey);
      if (!definition) {
        const error = new Error(`Built-in provider '${providerKey}' cannot be changed`);
        error.code = 'BUILTIN_PROVIDER_IMMUTABLE';
        error.statusCode = 400;
        throw error;
      }
      definition.enabled = true;
      providers.set(providerKey, { ...definition });
      return { providerKey, enabled: true, customProvider: true, displayName: definition.displayName, description: definition.description, category: definition.category };
    },
    async update(providerKey, input) {
      const definition = customDefinitions.get(providerKey);
      if (!definition) {
        const error = new Error(`Provider '${providerKey}' cannot be changed`);
        error.code = 'BUILTIN_PROVIDER_IMMUTABLE';
        error.statusCode = 400;
        throw error;
      }
      const updated = { ...definition, ...input, key: providerKey, enabled: definition.enabled };
      customDefinitions.set(providerKey, updated);
      providers.set(providerKey, {
        ...updated,
        customProvider: true,
        providerKey,
        capabilities: [],
        providerConfigurationFields: [],
        authType: null,
        defaultScopes: [],
        oauthSecurity: null,
        oauthTechnical: null
      });
      return { providerKey, enabled: updated.enabled, customProvider: true, displayName: updated.displayName, description: updated.description, category: updated.category, classification: 'NON_BREAKING_METADATA_CHANGE' };
    },
    async delete(providerKey) {
      if (!customDefinitions.has(providerKey)) {
        const error = new Error(`Provider '${providerKey}' cannot be changed`);
        error.code = 'BUILTIN_PROVIDER_IMMUTABLE';
        error.statusCode = 400;
        throw error;
      }
      customDefinitions.delete(providerKey);
      providers.delete(providerKey);
      return { providerKey, enabled: false, customProvider: true };
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

test('HTTP provider lifecycle routes require the bounded action and preserve management visibility', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);
  const input = {
    key: 'acme-service', displayName: 'Acme Service', category: 'CRM', description: 'Declarative provider',
    credentialMethods: [{ key: 'api-key', displayName: 'API key', credentialFields: [{ key: 'apiKey', label: 'API key', type: 'api-key', secret: true }], operationCapabilities: [] }],
    providerMethodBindings: [{ methodKey: 'api-key', displayName: 'Acme API key' }],
    credentialFields: [{ key: 'apiKey', label: 'API key', type: 'api-key', secret: true }]
  };

  try {
    await fetch(`${baseUrl}/api/v1/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin' }, body: JSON.stringify(input)
    });

    const disabled = await fetch(`${baseUrl}/api/v1/providers/acme-service/disable`, {
      method: 'POST', headers: { 'x-credential-hub-user': 'admin' }
    });
    assert.equal(disabled.status, 200);
    assert.deepEqual((await disabled.json()).data, {
      providerKey: 'acme-service', enabled: false, customProvider: true,
      displayName: 'Acme Service', description: 'Declarative provider', category: 'CRM'
    });

    const runtimeLookup = await fetch(`${baseUrl}/api/v1/providers/acme-service`);
    assert.equal(runtimeLookup.status, 404);

    const management = await fetch(`${baseUrl}/api/v1/management/providers`);
    const managementBody = await management.json();
    assert.equal(management.status, 200);
    assert.equal(managementBody.data.items.find((item) => item.providerKey === 'acme-service').enabled, false);

    const enabled = await fetch(`${baseUrl}/api/v1/providers/acme-service/enable`, {
      method: 'POST', headers: { 'x-credential-hub-user': 'admin' }
    });
    assert.equal(enabled.status, 200);
    assert.equal((await enabled.json()).data.enabled, true);

    const builtIn = await fetch(`${baseUrl}/api/v1/providers/threads/disable`, {
      method: 'POST', headers: { 'x-credential-hub-user': 'admin' }
    });
    assert.equal(builtIn.status, 400);
    assert.equal((await builtIn.json()).error.code, 'BUILTIN_PROVIDER_IMMUTABLE');
  } finally {
    server.close();
  }
});

test('HTTP provider management routes edit metadata and delete an unused custom provider', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);
  const input = {
    key: 'acme-service', displayName: 'Acme Service', category: 'CRM', description: 'Declarative provider',
    credentialMethods: [{ key: 'api-key', displayName: 'API key', credentialFields: [{ key: 'apiKey', label: 'API key', type: 'api-key', secret: true }], operationCapabilities: [] }],
    providerMethodBindings: [{ methodKey: 'api-key', displayName: 'Acme API key' }],
    credentialFields: [{ key: 'apiKey', label: 'API key', type: 'api-key', secret: true }]
  };

  try {
    await fetch(`${baseUrl}/api/v1/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin' }, body: JSON.stringify(input)
    });

    const updated = await fetch(`${baseUrl}/api/v1/providers/acme-service`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', 'x-credential-hub-user': 'admin' },
      body: JSON.stringify({ ...input, displayName: 'Acme Operations', category: 'Operations' })
    });
    const updatedBody = await updated.json();
    assert.equal(updated.status, 200);
    assert.equal(updatedBody.success, true);
    assert.equal(updatedBody.data.displayName, 'Acme Operations');
    assert.equal(updatedBody.classification, 'NON_BREAKING_METADATA_CHANGE');

    const deleted = await fetch(`${baseUrl}/api/v1/providers/acme-service`, {
      method: 'DELETE', headers: { 'x-credential-hub-user': 'admin' }
    });
    const deletedBody = await deleted.json();
    assert.equal(deleted.status, 200);
    assert.equal(deletedBody.success, true);
    assert.equal(deletedBody.data.providerKey, 'acme-service');

    const missing = await fetch(`${baseUrl}/api/v1/providers/acme-service`);
    assert.equal(missing.status, 404);
  } finally {
    server.close();
  }
});
