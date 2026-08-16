import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';

function createServer(credentials, providerSummaries = {}) {
  return new OAuthCallbackServer({
    providerManager: {
      getProvider(providerKey) {
        const provider = providerSummaries[providerKey];
        if (!provider) {
          const error = new Error(`Provider ${providerKey} not found`);
          error.code = 'NOT_FOUND';
          throw error;
        }

        return provider;
      }
    },
    importTokenCommand: {},
    credentialManager: {
      async listCredentials(options = {}) {
        const normalize = (value) => String(value ?? '').trim().toLowerCase();
        const toValue = (credential) => typeof credential.toJSON === 'function' ? credential.toJSON() : credential;
        const inferType = (credential) => {
          const names = (credential.secrets ?? []).map((secret) => secret.name);
          if (names.includes('apiKey')) return 'api-key';
          if (names.includes('host') || names.includes('password') || names.includes('privateKey')) return 'connection';
          if (names.includes('accessToken') || names.includes('refreshToken')) return 'oauth';
          return credential.metadata?.custom?.credentialType ?? 'unknown';
        };

        if (!options || Object.keys(options).length === 0) return credentials;

        const allowedSort = ['name', 'provider', 'type', 'state', 'expiresAt', 'createdAt', 'updatedAt'];
        const sort = options.sort ?? 'createdAt';
        const order = normalize(options.order ?? 'asc');

        if (!allowedSort.includes(sort)) {
          const error = new Error(`Unsupported credential sort field '${sort}'`);
          error.code = 'UNSUPPORTED_SORT_FIELD';
          throw error;
        }

        if (!['asc', 'desc'].includes(order)) {
          const error = new Error(`Unsupported credential sort order '${options.order}'`);
          error.code = 'UNSUPPORTED_SORT_ORDER';
          throw error;
        }

        return credentials.filter((credential) => {
          const value = toValue(credential);
          const metadata = value.metadata ?? {};
          const type = metadata.type ?? metadata.credentialType ?? metadata.custom?.type ?? inferType(value);

          if (options.provider && normalize(value.providerKey) !== normalize(options.provider)) return false;
          if (options.type && normalize(type) !== normalize(options.type)) return false;
          if (options.state && normalize(value.lifecycleState) !== normalize(options.state)) return false;

          if (options.search) {
            const haystack = [
              value.credentialId,
              value.providerKey,
              value.externalReference,
              metadata.displayName,
              metadata.description,
              ...(metadata.tags ?? [])
            ].filter(Boolean).join(' ').toLowerCase();
            if (!haystack.includes(normalize(options.search))) return false;
          }

          return true;
        }).sort((left, right) => {
          const leftValue = toValue(left);
          const rightValue = toValue(right);
          const sortValue = (value) => {
            const metadata = value.metadata ?? {};
            const type = metadata.type ?? metadata.credentialType ?? metadata.custom?.type ?? inferType(value);
            if (sort === 'name') return normalize(metadata.displayName ?? value.externalReference ?? value.credentialId);
            if (sort === 'provider') return normalize(value.providerKey);
            if (sort === 'type') return normalize(type);
            if (sort === 'state') return normalize(value.lifecycleState);
            if (sort === 'expiresAt') return metadata.expiresAt ? new Date(metadata.expiresAt).getTime() : Number.MAX_SAFE_INTEGER;
            if (sort === 'updatedAt') return value.updatedAt ? new Date(value.updatedAt).getTime() : 0;
            return value.createdAt ? new Date(value.createdAt).getTime() : 0;
          };
          const l = sortValue(leftValue);
          const r = sortValue(rightValue);
          if (l < r) return order === 'asc' ? -1 : 1;
          if (l > r) return order === 'asc' ? 1 : -1;
          return 0;
        });
      },
      async executeBulkAction({ action, credentialIds }) {
        const supportedActions = ['validate', 'refresh', 'revoke', 'health-check', 'delete'];
        if (!supportedActions.includes(action)) {
          const error = new Error(`Unsupported bulk credential action '${action}'`);
          error.code = 'UNSUPPORTED_BULK_ACTION';
          throw error;
        }

        const results = [];
        for (const credentialId of credentialIds) {
          try {
            if (action === 'delete') {
              await this.deleteCredential(credentialId);
              results.push({ credentialId, success: true, data: { credentialId, deleted: true } });
            } else {
              const credential = await this.getCredential(credentialId);
              if (!credential) throw new Error('Credential not found');
              const managerAction = action === 'health-check' ? 'healthCheck' : action;
              const result = await this[managerAction](credential);
              if (!result.success) throw new Error(result.error?.message ?? 'Lifecycle action failed');
              results.push({ credentialId, success: true, data: result.data });
            }
          } catch (error) {
            results.push({
              credentialId,
              success: false,
              error: { code: error.code ?? 'BULK_ACTION_FAILED', message: error.message }
            });
          }
        }

        const succeeded = results.filter((result) => result.success).length;
        return {
          action,
          requested: credentialIds.length,
          succeeded,
          failed: results.length - succeeded,
          results
        };
      },

      async getCredential(credentialId) {
        return credentials.find((credential) => {
          const value = typeof credential.toJSON === 'function'
            ? credential.toJSON()
            : credential;

          return value.credentialId === credentialId;
        }) ?? null;
      },

      async deleteCredential(credentialId) {
        const index = credentials.findIndex((credential) => {
          const value = typeof credential.toJSON === 'function'
            ? credential.toJSON()
            : credential;

          return value.credentialId === credentialId;
        });

        if (index < 0) {
          throw new Error('Credential not found');
        }

        credentials.splice(index, 1);
      },

      async validate(credential) {
        return {
          success: true,
          data: { action: 'validate', credential }
        };
      },
      async refresh(credential) {
        return {
          success: true,
          data: { action: 'refresh', credential }
        };
      },
      async revoke(credential) {
        return {
          success: true,
          data: { action: 'revoke', credential }
        };
      },
      async healthCheck(credential) {
        return {
          success: true,
          data: { action: 'health-check', credential }
        };
      },
      async testConnection(input) {
        return {
          providerKey: input.providerKey,
          status: 'connected',
          messageKey: 'credential.connection.success',
          checkedAt: '2026-07-13T10:00:00.000Z',
          secret: input.secrets?.[0]?.value ?? null
        };
      },
      async updateCredential(credentialId, updates) {
        const index = credentials.findIndex((credential) => {
          const value = typeof credential.toJSON === 'function'
            ? credential.toJSON()
            : credential;

          return value.credentialId === credentialId;
        });

        if (index < 0) {
          throw new Error('Credential not found');
        }

        const current = typeof credentials[index].toJSON === 'function'
          ? credentials[index].toJSON()
          : credentials[index];

        const updated = {
          ...current,
          ...updates,
          credentialId,
          metadata: {
            ...(current.metadata ?? {}),
            ...(updates.metadata ?? {})
          },
          version: (current.version ?? 1) + 1
        };

        credentials[index] = {
          toJSON() {
            return updated;
          }
        };

        return credentials[index];
      },
      async register(credentialInput) {
        const credential = {
          toJSON() {
            return {
              credentialId: credentialInput.credentialId,
              providerKey: credentialInput.providerKey,
              externalReference: credentialInput.externalReference ?? null,
              lifecycleState: credentialInput.lifecycleState ?? 'REGISTERED',
              secrets: credentialInput.secrets ?? [],
              metadata: credentialInput.metadata ?? {},
              version: 1
            };
          }
        };

        credentials.push(credential);
        return credential;
      }
    },
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

test('HTTP credentials list endpoint returns success response with pagination', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    },
    {
      toJSON() {
        return { credentialId: 'credential-2', providerKey: 'threads' };
      }
    }
  ]);

  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials?limit=1&offset=1`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data[0].credentialId, 'credential-2');
    assert.equal(body.data[0].providerKey, 'threads');
    assert.equal(body.data[0].providerName, 'threads');
    assert.equal(body.data[0].status, undefined);
    assert.deepEqual(body.pagination, {
      limit: 1,
      offset: 1,
      page: 2,
      pageSize: 1,
      count: 1,
      total: 2
    });
  } finally {
    server.close();
  }
});

test('HTTP credentials list endpoint supports search, filters, sorting and page parameters', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return {
          credentialId: 'credential-google-main',
          providerKey: 'google',
          externalReference: 'main-account',
          lifecycleState: 'active',
          secrets: [{ name: 'accessToken', value: 'hidden' }],
          metadata: {
            displayName: 'Main Google Account',
            description: 'Primary calendar OAuth credential',
            expiresAt: '2026-08-01T00:00:00.000Z',
            custom: { lastValidatedAt: '2026-07-01T00:00:00.000Z' }
          },
          createdAt: '2026-07-01T00:00:00.000Z'
        };
      }
    },
    {
      toJSON() {
        return {
          credentialId: 'credential-openai-backup',
          providerKey: 'openai',
          lifecycleState: 'registered',
          secrets: [{ name: 'apiKey', value: 'hidden' }],
          metadata: { displayName: 'Backup OpenAI Key' },
          createdAt: '2026-07-02T00:00:00.000Z'
        };
      }
    },
    {
      toJSON() {
        return {
          credentialId: 'credential-google-old',
          providerKey: 'google',
          lifecycleState: 'revoked',
          secrets: [{ name: 'accessToken', value: 'hidden' }],
          metadata: { displayName: 'Old Google Account' },
          createdAt: '2026-06-01T00:00:00.000Z'
        };
      }
    }
  ]);

  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials?search=calendar&provider=google&type=oauth&state=active&sort=name&order=desc&page=1&pageSize=5`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.pagination.total, 1);
    assert.equal(body.data.length, 1);
    assert.equal(body.data[0].credentialId, 'credential-google-main');
    assert.equal(body.data[0].credentialType, 'oauth');
    assert.equal(body.data[0].status, 'active');
    assert.equal(body.data[0].expiresAt, '2026-08-01T00:00:00.000Z');
    assert.equal(body.data[0].lastValidatedAt, '2026-07-01T00:00:00.000Z');
    assert.deepEqual(body.data[0].supportedActions, ['validate', 'health-check', 'refresh', 'revoke']);
  } finally {
    server.close();
  }
});


test('HTTP credentials list endpoint returns UI metadata for filter and sorting controls', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return {
          credentialId: 'credential-google-main',
          providerKey: 'google',
          lifecycleState: 'active',
          secrets: [{ name: 'accessToken', value: 'hidden' }],
          metadata: { displayName: 'Main Google Account' },
          createdAt: '2026-07-01T00:00:00.000Z'
        };
      }
    }
  ]);

  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials?provider=google&type=oauth&sort=name&order=desc&page=1&pageSize=10`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.deepEqual(body.meta.query, {
      search: null,
      provider: 'google',
      type: 'oauth',
      state: null,
      sort: 'name',
      order: 'desc'
    });
    assert.deepEqual(body.meta.availableFilters.type.values, ['oauth', 'api-key', 'connection', 'unknown']);
    assert.deepEqual(body.meta.availableFilters.state.values, ['registered', 'active', 'expired', 'revoked', 'deleted']);
    assert.deepEqual(body.meta.availableFilters.search.fields, ['credentialId', 'providerKey', 'externalReference', 'displayName', 'description', 'tags']);
  } finally {
    server.close();
  }
});


test('HTTP credentials meta endpoint describes the UI contract without loading credentials', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/meta`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.resource, 'credentials');
    assert.equal(body.data.endpoints.list.path, '/api/v1/credentials');
    assert.equal(body.data.endpoints.bulk.path, '/api/v1/credentials/bulk');
    assert.deepEqual(body.data.sorting.fields, ['name', 'provider', 'type', 'state', 'expiresAt', 'createdAt', 'updatedAt']);
    assert.deepEqual(body.data.pagination.preferredParameters, ['page', 'pageSize']);
    assert.deepEqual(body.data.pagination.legacyParameters, ['limit', 'offset']);
    assert.deepEqual(body.data.actions.bulk, ['validate', 'refresh', 'revoke', 'health-check', 'delete']);
    assert.deepEqual(body.data.responseShapes.detail, ['provider', 'credentialMethod', 'lifecycle', 'display', 'secretInventory', 'supportedActions']);
  } finally {
    server.close();
  }
});


test('HTTP credentials list endpoint rejects unsupported sort fields', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials?sort=secretValue`);
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'BAD_REQUEST');
    assert.match(body.error.message, /Unsupported credential sort field/);
  } finally {
    server.close();
  }
});


test('HTTP credentials list endpoint rejects invalid pagination', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials?limit=0`);
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'BAD_REQUEST');
    assert.match(body.error.message, /pageSize|limit/);
  } finally {
    server.close();
  }
});


test('HTTP credentials get endpoint returns a credential by id', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    }
  ]);

  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/credential-1`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.credentialId, 'credential-1');
    assert.equal(body.data.providerKey, 'threads');
    assert.equal(body.data.provider.providerKey, 'threads');
    assert.equal(body.data.display.name, 'credential-1');
    assert.deepEqual(body.data.secretInventory, []);
  } finally {
    server.close();
  }
});


test('HTTP credentials get endpoint returns detail view with provider metadata, lifecycle and secret inventory', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return {
          credentialId: 'credential-google-main',
          providerKey: 'google',
          externalReference: 'main-account',
          lifecycleState: 'active',
          secrets: [
            { name: 'accessToken', value: 'access-token-value' },
            { name: 'refreshToken', value: 'refresh-token-value' }
          ],
          metadata: {
            displayName: 'Main Google Account',
            description: 'Primary calendar OAuth credential',
            tags: ['calendar', 'production'],
            expiresAt: '2026-08-01T00:00:00.000Z',
            custom: {
              lastValidatedAt: '2026-07-01T00:00:00.000Z',
              lastRefreshAt: '2026-07-02T00:00:00.000Z',
              healthStatus: 'up'
            }
          },
          createdAt: '2026-07-01T00:00:00.000Z',
          updatedAt: '2026-07-03T00:00:00.000Z',
          version: 2
        };
      }
    }
  ], {
    google: {
      key: 'google',
      displayName: 'Google',
      description: 'Google OAuth provider',
      capabilities: ['oauth', 'refresh', 'health-check', 'revoke', 'validation']
    }
  });

  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/credential-google-main`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.credentialId, 'credential-google-main');
    assert.equal(body.data.credentialType, 'oauth');
    assert.equal(body.data.provider.displayName, 'Google');
    assert.deepEqual(body.data.provider.capabilities, ['oauth', 'refresh', 'health-check', 'revoke', 'validation']);
    assert.deepEqual(body.data.supportedActions, ['validate', 'health-check', 'refresh', 'revoke']);
    assert.deepEqual(body.data.lifecycle, {
      state: 'active',
      createdAt: '2026-07-01T00:00:00.000Z',
      updatedAt: '2026-07-03T00:00:00.000Z',
      expiresAt: '2026-08-01T00:00:00.000Z',
      lastValidatedAt: '2026-07-01T00:00:00.000Z',
      lastRefreshAt: '2026-07-02T00:00:00.000Z',
      healthStatus: 'up'
    });
    assert.deepEqual(body.data.display, {
      name: 'Main Google Account',
      description: 'Primary calendar OAuth credential',
      tags: ['calendar', 'production']
    });
    assert.deepEqual(body.data.secretInventory, [
      { name: 'accessToken', type: null, required: null, hasValue: true, valueMasked: '********' },
      { name: 'refreshToken', type: null, required: null, hasValue: true, valueMasked: '********' }
    ]);
  } finally {
    server.close();
  }
});

test('HTTP credentials get endpoint returns not found for unknown credential', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/missing`);
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'NOT_FOUND');
    assert.match(body.error.message, /Credential not found/);
  } finally {
    server.close();
  }
});

test('HTTP credentials create endpoint returns created credential', async () => {
  const credentials = [];
  const httpServer = createServer(credentials);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        credentialId: 'credential-3',
        providerKey: 'threads',
        externalReference: 'account-3',
        secrets: [
          { name: 'accessToken', value: 'access-token-3' }
        ],
        metadata: {
          accountName: 'Threads Account'
        }
      })
    });
    const body = await response.json();

    assert.equal(response.status, 201);
    assert.equal(body.success, true);
    assert.equal(body.data.credentialId, 'credential-3');
    assert.equal(body.data.providerKey, 'threads');
  } finally {
    server.close();
  }
});

test('HTTP credentials create endpoint rejects invalid body', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'CREDENTIAL_CREATE_INVALID');
    assert.equal(body.messageKey, 'credential.create.invalid');
    assert.match(body.error.message, /body/);
  } finally {
    server.close();
  }
});


test('HTTP credentials update endpoint updates a credential', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return {
          credentialId: 'credential-1',
          providerKey: 'threads',
          metadata: { accountName: 'Old Name' },
          secrets: [{ name: 'accessToken', value: 'access-token-must-not-leak' }],
          version: 1
        };
      }
    }
  ]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/credential-1`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        metadata: { accountName: 'New Name' }
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.credentialId, 'credential-1');
    assert.equal(body.data.metadata.accountName, 'New Name');
    assert.equal(body.data.version, 2);
    assert.equal('secrets' in body.data, false);
    assert.equal(body.data.secretInventory[0].hasValue, true);
    assert.doesNotMatch(JSON.stringify(body), /access-token-must-not-leak/);
  } finally {
    server.close();
  }
});

test('HTTP credentials update endpoint returns not found for unknown credential', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/missing`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        metadata: { accountName: 'New Name' }
      })
    });
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'NOT_FOUND');
    assert.match(body.error.message, /Credential not found/);
  } finally {
    server.close();
  }
});


test('HTTP credentials delete endpoint deletes a credential', async () => {
  const credentials = [
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    }
  ];
  const httpServer = createServer(credentials);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/credential-1`, {
      method: 'DELETE'
    });

    assert.equal(response.status, 204);
    assert.equal(await response.text(), '');
    assert.equal(credentials.length, 0);
  } finally {
    server.close();
  }
});

test('HTTP credentials delete endpoint returns not found for unknown credential', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/missing`, {
      method: 'DELETE'
    });
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'NOT_FOUND');
    assert.match(body.error.message, /Credential not found/);
  } finally {
    server.close();
  }
});


test('HTTP credentials validate endpoint executes lifecycle action', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    }
  ]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/credential-1/validate`, {
      method: 'POST'
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.action, 'validate');
    assert.equal(body.data.credential.credentialId, 'credential-1');
  } finally {
    server.close();
  }
});

test('HTTP credential connection-test endpoint is BASE_PATH-safe and never returns submitted secrets', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/test-connection`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        providerKey: 'openai',
        secrets: [{ name: 'apiKey', value: 'sk-never-return-this-secret' }]
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.deepEqual(body, {
      success: true,
      data: {
        providerKey: 'openai',
        status: 'connected',
        messageKey: 'credential.connection.success',
        checkedAt: '2026-07-13T10:00:00.000Z'
      }
    });
    assert.equal(JSON.stringify(body).includes('sk-never-return-this-secret'), false);
  } finally {
    server.close();
  }
});

test('HTTP credentials refresh endpoint executes lifecycle action', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    }
  ]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/credential-1/refresh`, {
      method: 'POST'
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.action, 'refresh');
    assert.equal(body.data.credential.credentialId, 'credential-1');
  } finally {
    server.close();
  }
});

test('HTTP credentials revoke endpoint executes lifecycle action', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    }
  ]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/credential-1/revoke`, {
      method: 'POST'
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.action, 'revoke');
    assert.equal(body.data.credential.credentialId, 'credential-1');
  } finally {
    server.close();
  }
});

test('HTTP credentials health-check endpoint executes lifecycle action', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    }
  ]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/credential-1/health-check`, {
      method: 'POST'
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.action, 'health-check');
    assert.equal(body.data.credential.credentialId, 'credential-1');
  } finally {
    server.close();
  }
});

test('HTTP credentials lifecycle endpoint returns not found for unknown credential', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/missing/validate`, {
      method: 'POST'
    });
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'NOT_FOUND');
    assert.match(body.error.message, /Credential not found/);
  } finally {
    server.close();
  }
});


test('HTTP credentials bulk endpoint executes lifecycle action for multiple credentials', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    },
    {
      toJSON() {
        return { credentialId: 'credential-2', providerKey: 'google' };
      }
    }
  ]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/bulk`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        action: 'validate',
        credentialIds: ['credential-1', 'credential-2']
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.action, 'validate');
    assert.equal(body.data.requested, 2);
    assert.equal(body.data.succeeded, 2);
    assert.equal(body.data.failed, 0);
    assert.deepEqual(body.data.results.map((result) => result.credentialId), ['credential-1', 'credential-2']);
    assert.deepEqual(body.data.results.map((result) => result.success), [true, true]);
  } finally {
    server.close();
  }
});

test('HTTP credentials bulk endpoint reports partial failures without aborting the batch', async () => {
  const httpServer = createServer([
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    }
  ]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/bulk`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        action: 'health-check',
        credentialIds: ['credential-1', 'missing']
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, false);
    assert.equal(body.data.requested, 2);
    assert.equal(body.data.succeeded, 1);
    assert.equal(body.data.failed, 1);
    assert.equal(body.data.results[0].success, true);
    assert.equal(body.data.results[1].credentialId, 'missing');
    assert.equal(body.data.results[1].success, false);
    assert.match(body.data.results[1].error.message, /Credential not found/);
  } finally {
    server.close();
  }
});

test('HTTP credentials bulk endpoint deletes multiple credentials', async () => {
  const credentials = [
    {
      toJSON() {
        return { credentialId: 'credential-1', providerKey: 'threads' };
      }
    },
    {
      toJSON() {
        return { credentialId: 'credential-2', providerKey: 'google' };
      }
    }
  ];
  const httpServer = createServer(credentials);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/bulk`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        action: 'delete',
        credentialIds: ['credential-1', 'credential-2']
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.succeeded, 2);
    assert.equal(credentials.length, 0);
  } finally {
    server.close();
  }
});

test('HTTP credentials bulk endpoint rejects invalid requests', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const emptyIdsResponse = await fetch(`${baseUrl}/api/v1/credentials/bulk`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'validate', credentialIds: [] })
    });
    const emptyIdsBody = await emptyIdsResponse.json();

    assert.equal(emptyIdsResponse.status, 400);
    assert.equal(emptyIdsBody.success, false);
    assert.equal(emptyIdsBody.error.code, 'BAD_REQUEST');

    const unsupportedActionResponse = await fetch(`${baseUrl}/api/v1/credentials/bulk`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'rotate', credentialIds: ['credential-1'] })
    });
    const unsupportedActionBody = await unsupportedActionResponse.json();

    assert.equal(unsupportedActionResponse.status, 400);
    assert.equal(unsupportedActionBody.success, false);
    assert.equal(unsupportedActionBody.error.code, 'BAD_REQUEST');
    assert.match(unsupportedActionBody.error.message, /Unsupported bulk credential action/);
  } finally {
    server.close();
  }
});
