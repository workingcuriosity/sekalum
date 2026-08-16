import test from 'node:test';
import assert from 'node:assert/strict';

import { ManagementService } from '../../src/services/management-service.js';

test('ManagementService aggregates management status', async () => {
  const service = new ManagementService({
    credentialManager: {
      async listCredentials() {
        return [
          {
            toJSON() {
              return {
                credentialId: 'credential-1',
                providerKey: 'threads',
                lifecycleState: 'active',
                metadata: {
                  displayName: 'Threads Main',
                  expiresAt: '2026-08-01T00:00:00.000Z'
                },
                version: 2
              };
            }
          },
          {
            credentialId: 'credential-2',
            providerKey: 'openai',
            lifecycleState: 'registered',
            metadata: { displayName: 'OpenAI API' }
          }
        ];
      }
    },
    providerManager: {
      listProviders() {
        return [
          { key: 'threads', displayName: 'Threads', capabilities: ['oauth', 'refresh'] },
          { key: 'openai', displayName: 'OpenAI', capabilities: ['validation'] }
        ];
      }
    },
    schedulerService: {
      getStatus() {
        return {
          started: true,
          running: false,
          startedAt: '2026-07-08T08:00:00.000Z',
          lastRunAt: '2026-07-08T08:00:00.000Z',
          lastSuccessAt: '2026-07-08T08:00:01.000Z',
          lastErrorAt: null,
          lastErrorMessage: null,
          nextRunAt: '2026-07-08T20:00:00.000Z',
          runCount: 4,
          failureCount: 0,
          jobs: [{ name: 'refresh-expired-tokens', intervalHours: 12 }],
          jobCount: 1
        };
      }
    }
  });

  const status = await service.getStatus();

  assert.equal(status.status, 'ok');
  assert.equal(status.credentials.total, 2);
  assert.deepEqual(status.credentials.byLifecycleState, { active: 1, registered: 1 });
  assert.deepEqual(status.credentials.byProvider, { threads: 1, openai: 1 });
  assert.equal(status.credentials.items[0].credentialId, 'credential-1');
  assert.equal(status.credentials.items[0].displayName, 'Threads Main');
  assert.equal(status.providers.total, 2);
  assert.deepEqual(status.providers.byCapability, { oauth: 1, refresh: 1, validation: 1 });
  assert.equal(status.providers.items[0].providerKey, 'threads');
  assert.equal(status.scheduler.available, true);
  assert.equal(status.scheduler.started, true);
  assert.equal(status.scheduler.jobCount, 1);
  assert.equal(status.scheduler.runCount, 4);
});

test('ManagementService delegates credential operations to CredentialManager', async () => {
  const calls = [];
  const service = new ManagementService({
    credentialManager: {
      async executeBulkAction(payload) {
        calls.push(['bulk', payload]);
        return { action: payload.action, requested: payload.credentialIds.length, succeeded: 2, failed: 0 };
      },
      async executeLifecycleAction(credentialId, action) {
        calls.push(['lifecycle', credentialId, action]);
        return { credentialId, lifecycleState: 'active' };
      }
    },
    providerManager: { listProviders() { return []; } }
  });

  const bulkResult = await service.executeCredentialBulkAction({
    credentialIds: ['credential-1', 'credential-2'],
    action: 'validate'
  });
  const lifecycleResult = await service.executeCredentialLifecycleAction('credential-1', 'refresh');

  assert.deepEqual(bulkResult, { action: 'validate', requested: 2, succeeded: 2, failed: 0 });
  assert.deepEqual(lifecycleResult, { credentialId: 'credential-1', lifecycleState: 'active' });
  assert.deepEqual(calls, [
    ['bulk', { credentialIds: ['credential-1', 'credential-2'], action: 'validate' }],
    ['lifecycle', 'credential-1', 'refresh']
  ]);
});

test('ManagementService delegates scheduler operations and returns updated status', async () => {
  let started = false;
  let running = false;
  let runCount = 0;

  const service = new ManagementService({
    credentialManager: { async listCredentials() { return []; } },
    providerManager: { listProviders() { return []; } },
    schedulerService: {
      getStatus() {
        return {
          started,
          running,
          runCount,
          failureCount: 0,
          jobs: [{ name: 'refresh-expired-tokens', intervalHours: 12 }]
        };
      },
      async start() {
        started = true;
      },
      stop() {
        started = false;
      },
      async runOnce() {
        running = true;
        runCount += 1;
        running = false;
      }
    }
  });

  const startedStatus = await service.startScheduler();
  const runStatus = await service.runSchedulerOnce();
  const stoppedStatus = await service.stopScheduler();

  assert.equal(startedStatus.started, true);
  assert.equal(runStatus.runCount, 1);
  assert.equal(stoppedStatus.started, false);
});

test('ManagementService reports degraded status when scheduler is missing', async () => {
  const service = new ManagementService({
    credentialManager: { async listCredentials() { return []; } },
    providerManager: { listProviders() { return []; } }
  });

  const status = await service.getStatus();

  assert.equal(status.status, 'degraded');
  assert.equal(status.scheduler.available, false);
});

test('ManagementService fails clearly when required collaborators are missing', async () => {
  const service = new ManagementService({
    providerManager: { listProviders() { return []; } }
  });

  await assert.rejects(
    () => service.getCredentials(),
    /ManagementService requires CredentialManager\.listCredentials\(\)/
  );

  await assert.rejects(
    () => service.runSchedulerOnce(),
    /ManagementService requires SchedulerService\.runOnce\(\)/
  );
});


test('ManagementService audits scheduler management actions', async () => {
  const auditEntries = [];
  const service = new ManagementService({
    credentialManager: { async listCredentials() { return []; } },
    providerManager: { listProviders() { return []; } },
    schedulerService: {
      getStatus() {
        return { started: true, running: false, runCount: 1, failureCount: 0, jobs: [] };
      },
      async start() {},
      stop() {},
      async runOnce() {}
    },
    auditLogService: {
      async record(entry) {
        auditEntries.push(entry);
      }
    }
  });

  await service.startScheduler({ actorUserId: 'admin' });
  await service.runSchedulerOnce({ actorUserId: 'admin' });
  await service.stopScheduler({ actorUserId: 'admin' });

  assert.deepEqual(auditEntries.map((entry) => entry.action), [
    'scheduler.started',
    'scheduler.run_once',
    'scheduler.stopped'
  ]);
  assert.equal(auditEntries[0].userId, 'admin');
  assert.equal(auditEntries[0].targetType, 'scheduler');
  assert.equal(auditEntries[0].result, 'success');
});

test('ManagementService executes and audits provider health check action', async () => {
  const auditEntries = [];
  const service = new ManagementService({
    credentialManager: { async listCredentials() { return []; } },
    providerManager: {
      listProviders() { return []; },
      async healthCheck(providerKey) {
        return { success: true, data: { status: 'up', providerKey } };
      }
    },
    auditLogService: {
      async record(entry) {
        auditEntries.push(entry);
      }
    }
  });

  const result = await service.executeProviderHealthCheck('threads', { actorUserId: 'operator' });

  assert.equal(result.providerKey, 'threads');
  assert.equal(result.action, 'health-check');
  assert.equal(result.success, true);
  assert.deepEqual(auditEntries, [{
    userId: 'operator',
    action: 'provider.health_check',
    targetType: 'provider',
    targetId: 'threads',
    result: 'success',
    details: null
  }]);
});
