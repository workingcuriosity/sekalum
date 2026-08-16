import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';

function createServer({ managementService } = {}) {
  return new OAuthCallbackServer({
    providerManager: { listProviders() { return []; } },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    schedulerService: { getStatus() { return { started: false, running: false, jobs: [] }; } },
    managementService,
    config: { get() { return 0; } },
    logger: { success() {}, error() {} }
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

const managementPayload = {
  generatedAt: '2026-07-08T08:00:00.000Z',
  status: 'ok',
  credentials: {
    total: 1,
    byLifecycleState: { active: 1 },
    byProvider: { threads: 1 },
    items: [{ credentialId: 'credential-1', providerKey: 'threads', lifecycleState: 'active' }]
  },
  providers: {
    total: 1,
    byCapability: { oauth: 1 },
    items: [{ providerKey: 'threads', key: 'threads', displayName: 'Threads', capabilities: ['oauth'] }]
  },
  scheduler: {
    available: true,
    started: true,
    running: false,
    jobs: [{ name: 'refresh-expired-tokens', intervalHours: 12 }],
    jobCount: 1,
    runCount: 2,
    failureCount: 0
  }
};

test('HTTP management status endpoint returns aggregated management state', async () => {
  const httpServer = createServer({
    managementService: {
      async getStatus() {
        return managementPayload;
      }
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/management/status`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.deepEqual(body.meta, { apiVersion: 'v1' });
    assert.deepEqual(body.data, managementPayload);
  } finally {
    server.close();
  }
});

test('HTTP management detail endpoints delegate to ManagementService', async () => {
  const calls = [];
  const httpServer = createServer({
    managementService: {
      async getStatus() { return managementPayload; },
      async getProviders() {
        calls.push('providers');
        return managementPayload.providers;
      },
      async getScheduler() {
        calls.push('scheduler');
        return managementPayload.scheduler;
      },
      async getCredentials() {
        calls.push('credentials');
        return managementPayload.credentials;
      }
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const providers = await (await fetch(`${baseUrl}/api/v1/management/providers`)).json();
    const scheduler = await (await fetch(`${baseUrl}/api/v1/management/scheduler`)).json();
    const credentials = await (await fetch(`${baseUrl}/api/v1/management/credentials`)).json();

    assert.deepEqual(providers.data, managementPayload.providers);
    assert.deepEqual(scheduler.data, managementPayload.scheduler);
    assert.deepEqual(credentials.data, managementPayload.credentials);
    assert.deepEqual(calls, ['providers', 'scheduler', 'credentials']);
  } finally {
    server.close();
  }
});

test('HTTP management endpoint returns structured errors', async () => {
  const httpServer = createServer({
    managementService: {
      async getStatus() {
        throw new Error('Management unavailable');
      }
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/management/status`);
    const body = await response.json();

    assert.equal(response.status, 500);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'INTERNAL_ERROR');
    assert.match(body.error.message, /Management unavailable/);
  } finally {
    server.close();
  }
});

test('HTTP scheduler management endpoints delegate to ManagementService', async () => {
  const calls = [];
  const httpServer = createServer({
    managementService: {
      async getStatus() { return managementPayload; },
      async startScheduler() {
        calls.push('start');
        return { ...managementPayload.scheduler, started: true };
      },
      async runSchedulerOnce() {
        calls.push('run-once');
        return { ...managementPayload.scheduler, runCount: 3 };
      },
      async stopScheduler() {
        calls.push('stop');
        return { ...managementPayload.scheduler, started: false };
      }
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const started = await (await fetch(`${baseUrl}/api/v1/management/scheduler/start`, { method: 'POST' })).json();
    const run = await (await fetch(`${baseUrl}/api/v1/management/scheduler/run-once`, { method: 'POST' })).json();
    const stopped = await (await fetch(`${baseUrl}/api/v1/management/scheduler/stop`, { method: 'POST' })).json();

    assert.equal(started.data.started, true);
    assert.equal(run.data.runCount, 3);
    assert.equal(stopped.data.started, false);
    assert.deepEqual(calls, ['start', 'run-once', 'stop']);
  } finally {
    server.close();
  }
});

test('HTTP provider health-check management endpoint delegates to ManagementService', async () => {
  const calls = [];
  const httpServer = createServer({
    managementService: {
      async getStatus() { return managementPayload; },
      async executeProviderHealthCheck(providerKey) {
        calls.push(providerKey);
        return { providerKey, action: 'health-check', success: true, data: { status: 'up' }, error: null };
      }
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/management/providers/threads/health-check`, { method: 'POST' });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.providerKey, 'threads');
    assert.equal(body.data.success, true);
    assert.deepEqual(calls, ['threads']);
  } finally {
    server.close();
  }
});
