import test from 'node:test';
import assert from 'node:assert/strict';

import { DashboardService } from '../../src/services/dashboard-service.js';

test('DashboardService aggregates credentials, providers and scheduler jobs', async () => {
  const soon = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString();
  const past = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const service = new DashboardService({
    credentialManager: {
      async listCredentials() {
        return [
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
            credentialId: 'credential-2',
            providerKey: 'missing-provider',
            lifecycleState: 'expired',
            metadata: { expiresAt: past }
          }
        ];
      }
    },
    providerManager: {
      listProviders() {
        return [
          { key: 'threads', displayName: 'Threads', capabilities: ['oauth'] },
          { key: 'openai', displayName: 'OpenAI', capabilities: ['validation'] }
        ];
      }
    },
    schedulerService: {
  getStatus() {
    return {
      started: true,
      running: false,
      startedAt: '2026-07-07T08:00:00.000Z',
      lastRunAt: '2026-07-07T08:00:00.000Z',
      lastSuccessAt: '2026-07-07T08:00:01.000Z',
      lastErrorAt: null,
      lastErrorMessage: null,
      nextRunAt: '2026-07-07T20:00:00.000Z',
      runCount: 3,
      failureCount: 0,
      jobs: [{ name: 'refresh-expired-tokens', intervalHours: 12 }],
      jobCount: 1
    };
  }
}
  });

  const dashboard = await service.getDashboard({ expiringWithinDays: 14 });

  assert.equal(dashboard.credentials.total, 2);
  assert.deepEqual(dashboard.credentials.byLifecycleState, { active: 1, expired: 1 });
  assert.equal(dashboard.credentials.expiringSoonCount, 1);
  assert.equal(dashboard.credentials.expiredCount, 1);
  assert.equal(dashboard.providers.total, 2);
  assert.equal(dashboard.providers.withCredentials, 1);
  assert.equal(dashboard.providers.withoutCredentials, 1);
  assert.deepEqual(dashboard.providers.byCapability, {
    oauth: 1,
    refresh: 0,
    'health-check': 0,
    revoke: 0,
    validation: 1
  });
  assert.equal(dashboard.providers.items[0].credentialCount, 1);
  assert.equal(dashboard.providers.items[0].supportsOAuth, true);
  assert.equal(dashboard.providers.items[0].supportsRefresh, false);
  assert.equal(dashboard.providers.items[1].supportsValidation, true);
  assert.equal(dashboard.scheduler.jobCount, 1);
 
  assert.equal(dashboard.scheduler.started, true);
assert.equal(dashboard.scheduler.running, false);
assert.equal(dashboard.scheduler.runCount, 3);
assert.equal(dashboard.scheduler.failureCount, 0);
assert.equal(dashboard.scheduler.lastRunAt, '2026-07-07T08:00:00.000Z');
assert.equal(dashboard.scheduler.lastSuccessAt, '2026-07-07T08:00:01.000Z');
assert.equal(dashboard.scheduler.lastErrorMessage, null);
assert.equal(dashboard.scheduler.nextRunAt, '2026-07-07T20:00:00.000Z');

  assert.deepEqual(dashboard.warnings.unknownProviderCredentials, ['credential-2']);
  assert.deepEqual(dashboard.warnings.expiringSoonCredentials, ['credential-1']);
  assert.deepEqual(dashboard.warnings.expiredCredentials, ['credential-2']);

  assert.equal(dashboard.credentials.validCount, 1);
assert.equal(dashboard.credentials.withExpirationCount, 2);
assert.equal(dashboard.credentials.withoutExpirationCount, 0);
assert.deepEqual(dashboard.credentials.byCredentialType, {
  unknown: 2
});
});

test('DashboardService rejects invalid expiring window', async () => {
  const service = new DashboardService({
    credentialManager: { async listCredentials() { return []; } },
    providerManager: { listProviders() { return []; } }
  });

  await assert.rejects(
    () => service.getDashboard({ expiringWithinDays: 0 }),
    (error) => {
      assert.equal(error.code, 'BAD_REQUEST');
      assert.equal(error.statusCode, 400);
      assert.match(error.message, /expiringWithinDays/);
      return true;
    }
  );
});

test('DashboardService returns partial dashboard data when a section fails', async () => {
  const service = new DashboardService({
    credentialManager: {
      async listCredentials() {
        throw new Error('Credential store unavailable');
      }
    },
    providerManager: {
      listProviders() {
        return [
          { key: 'threads', displayName: 'Threads', capabilities: ['oauth'] }
        ];
      }
    },
    schedulerService: {
      getStatus() {
        throw new Error('Scheduler status unavailable');
      }
    }
  });

  const dashboard = await service.getDashboard();

  assert.equal(dashboard.credentials.status, 'unavailable');
  assert.equal(dashboard.credentials.total, 0);

  assert.equal(dashboard.providers.total, 1);
  assert.equal(dashboard.providers.items[0].providerKey, 'threads');

  assert.equal(dashboard.scheduler.status, 'unavailable');
  assert.equal(dashboard.scheduler.jobCount, 0);

  assert.deepEqual(dashboard.warnings.serviceErrors, [
    {
      section: 'credentials',
      message: 'Credential store unavailable'
    },
    {
      section: 'scheduler',
      message: 'Scheduler status unavailable'
    }
  ]);
});

test('DashboardService adds lifecycle v2 summaries', async () => {
  const credential = {
    credentialId: 'credential-1',
    providerKey: 'threads',
    lifecycleState: 'active',
    metadata: {
      displayName: 'Threads Main',
      lastRotatedAt: '2026-05-01T00:00:00.000Z'
    }
  };

  const service = new DashboardService({
    credentialManager: {
      async listCredentials() {
        return [credential];
      },
      async listSecretVersions(credentialId) {
        assert.equal(credentialId, 'credential-1');
        return [
          { version: 2, createdAt: '2026-07-01T00:00:00.000Z' },
          { version: 1, createdAt: '2026-06-01T00:00:00.000Z' }
        ];
      }
    },
    providerManager: {
      listProviders() {
        return [{ key: 'threads', displayName: 'Threads', capabilities: ['refresh'] }];
      }
    },
    credentialPolicyService: {
      async listPolicies() {
        return [
          { policyId: 'policy-1', name: 'Threads Rotation', status: 'active', providerKey: 'threads' }
        ];
      },
      async evaluateCredential(input) {
        assert.equal(input.credentialId, 'credential-1');
        return {
          credentialId: 'credential-1',
          providerKey: 'threads',
          compliant: false,
          warnings: [{ type: 'rotation-date-missing' }],
          violations: [{ type: 'rotation-overdue' }],
          matchedPolicies: []
        };
      }
    },
    credentialRotationService: {
      async planRotation() {
        return {
          plannedAt: '2026-07-08T10:00:00.000Z',
          requested: 1,
          candidates: 1,
          skipped: 0,
          items: [
            {
              credentialId: 'credential-1',
              providerKey: 'threads',
              findings: [{ type: 'rotation-overdue' }],
              policies: [{ policyId: 'policy-1' }]
            }
          ]
        };
      }
    },
    credentialHistoryService: {
      async summarizeCredentialHistory(credentialId, options) {
        assert.equal(credentialId, 'credential-1');
        assert.equal(options.includeEntries, false);
        return {
          total: 3,
          firstEventAt: '2026-06-01T00:00:00.000Z',
          lastEventAt: '2026-07-01T00:00:00.000Z',
          countsBySource: { 'audit-log': 1, 'secret-version': 2 },
          countsByResult: { success: 3 }
        };
      }
    },
    lifecycleNotificationService: {
      async summarizeNotifications() {
        return {
          generatedAt: '2026-07-08T10:00:00.000Z',
          total: 2,
          open: 1,
          acknowledged: 0,
          resolved: 1,
          critical: 1,
          warning: 1,
          info: 0,
          byStatus: { open: 1, resolved: 1 },
          bySeverity: { critical: 1, warning: 1 }
        };
      }
    }
  });

  const dashboard = await service.getDashboard();

  assert.equal(dashboard.lifecycle.policies.total, 1);
  assert.equal(dashboard.lifecycle.policies.violationCount, 1);
  assert.deepEqual(dashboard.lifecycle.policies.credentialsWithViolations, ['credential-1']);
  assert.equal(dashboard.lifecycle.rotation.dueCount, 1);
  assert.equal(dashboard.lifecycle.rotation.candidates[0].findingCount, 1);
  assert.equal(dashboard.lifecycle.secretVersions.totalVersions, 2);
  assert.equal(dashboard.lifecycle.secretVersions.credentialsWithVersions, 1);
  assert.equal(dashboard.lifecycle.history.totalEvents, 3);
  assert.equal(dashboard.lifecycle.notifications.critical, 1);
  assert.equal(dashboard.lifecycle.health, 'critical');
});

test('DashboardService derives secret-free integration health from existing states', async () => {
  const soon = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const service = new DashboardService({
    credentialManager: {
      async listCredentials() {
        return [
          { credentialId: 'healthy-credential', providerKey: 'twitch', credentialMethodKey: 'oauth2', lifecycleState: 'active', metadata: { displayName: 'Twitch Main', expiresAt: soon } },
          { credentialId: 'warning-credential', providerKey: 'twitch', credentialMethodKey: 'oauth2', lifecycleState: 'registered', metadata: {} },
          { credentialId: 'error-credential', providerKey: 'missing', credentialMethodKey: 'oauth2', lifecycleState: 'expired', metadata: {} }
        ];
      }
    },
    providerManager: {
      listProviders() {
        return [{ key: 'twitch', displayName: 'Twitch', capabilities: ['oauth', 'refresh'] }];
      }
    },
    consumerGrantService: {
      async listGrants() {
        return [{ credentialId: 'healthy-credential', providerKey: 'twitch', secretNames: ['accessToken'] }];
      }
    }
  });

  const dashboard = await service.getDashboard();
  assert.equal(dashboard.integrationHealth.total, 3);
  assert.equal(dashboard.integrationHealth.items[0].status, 'healthy');
  assert.equal(dashboard.integrationHealth.items[0].grant.count, 1);
  assert.equal(dashboard.integrationHealth.items[1].status, 'warning');
  assert.equal(dashboard.integrationHealth.items[2].status, 'error');
  assert.equal('secrets' in dashboard.integrationHealth.items[0], false);
  assert.deepEqual(dashboard.integrationHealth.counts, { healthy: 1, warning: 1, error: 1, unknown: 0 });
});
