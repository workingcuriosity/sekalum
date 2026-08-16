import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';

function createServer({ credentials = [], providers = [], schedulerJobs = [] } = {}) {
  return new OAuthCallbackServer({
    providerManager: {
      listProviders() {
        return providers;
      }
    },
    importTokenCommand: {},
    credentialManager: {
      async listCredentials() {
        return credentials;
      }
    },
    schedulerService: {
      running: false,
      listJobs() {
        return schedulerJobs;
      }
    },
    accessManagementService: {
      async listUsers() {
        return [];
      },
      async isAuthorizationRequired() {
        return false;
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

test('HTTP dashboard endpoint aggregates credential, provider and scheduler state', async () => {
  const soon = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
  const past = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const httpServer = createServer({
    credentials: [
      {
        toJSON() {
          return {
            credentialId: 'credential-1',
            providerKey: 'threads',
            lifecycleState: 'active',
            metadata: { displayName: 'Threads Main', expiresAt: soon }
          };
        }
      },
      {
        toJSON() {
          return {
            credentialId: 'credential-2',
            providerKey: 'missing-provider',
            lifecycleState: 'expired',
            metadata: { expiresAt: past }
          };
        }
      }
    ],
    providers: [
      {
        key: 'threads',
        displayName: 'Threads',
        capabilities: ['oauth', 'refresh']
      },
      {
        key: 'openai',
        displayName: 'OpenAI',
        capabilities: ['validation']
      }
    ],
    schedulerJobs: [{ name: 'refresh-expired-tokens', intervalHours: 12 }]
  });

  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/dashboard?expiringWithinDays=14`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.deepEqual(body.meta, {
    apiVersion: 'v1'
    });

    assert.equal(body.data.credentials.total, 2);
    assert.deepEqual(body.data.credentials.byLifecycleState, {
      active: 1,
      expired: 1
    });
    assert.equal(body.data.credentials.expiringSoonCount, 1);
    assert.equal(body.data.credentials.expiredCount, 1);
    assert.equal(body.data.providers.total, 2);
    assert.equal(body.data.providers.withCredentials, 1);
    assert.equal(body.data.providers.withoutCredentials, 1);
    assert.deepEqual(body.data.providers.byCapability, {
      oauth: 1,
      refresh: 1,
      'health-check': 0,
      revoke: 0,
      validation: 1
    });
    assert.equal(body.data.providers.items[0].credentialCount, 1);
    assert.equal(body.data.providers.items[0].supportsOAuth, true);
    assert.equal(body.data.providers.items[0].supportsRefresh, true);
    assert.equal(body.data.providers.items[1].supportsValidation, true);
    assert.equal(body.data.integrationHealth.total, 2);
    assert.equal(body.data.integrationHealth.items[0].grant.count, 0);
    assert.equal(body.data.integrationHealth.items[0].resolve.status, 'warning');
    assert.equal(body.data.integrationHealth.items[1].status, 'error');
    assert.equal(JSON.stringify(body.data.integrationHealth).includes('secretNames'), false);
    assert.equal(body.data.scheduler.jobCount, 1);
    assert.deepEqual(body.data.warnings.unknownProviderCredentials, ['credential-2']);
    assert.deepEqual(body.data.warnings.expiringSoonCredentials, ['credential-1']);
    assert.deepEqual(body.data.warnings.expiredCredentials, ['credential-2']);
  } finally {
    server.close();
  }
});

test('HTTP dashboard endpoint rejects invalid expiring window', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/dashboard?expiringWithinDays=0`);
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'BAD_REQUEST');
    assert.match(body.error.message, /expiringWithinDays/);
  } finally {
    server.close();
  }
});
