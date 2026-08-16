import test from 'node:test';
import assert from 'node:assert/strict';

import { LifecycleNotificationStatus } from '../../src/models/lifecycle-notification.js';
import { LifecycleNotificationService } from '../../src/services/lifecycle-notification-service.js';

test('LifecycleNotificationService creates notifications from policy findings', async () => {
  const auditEntries = [];
  const service = new LifecycleNotificationService({
    auditLogService: { async record(entry) { auditEntries.push(entry); } },
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const notifications = await service.createForPolicyEvaluation({
    credentialId: 'cred-1',
    providerKey: 'twitch',
    matchedPolicies: [{ policyId: 'oauth-30', name: 'OAuth 30' }],
    violations: [{ policyId: 'oauth-30', type: 'rotation-overdue', daysOverdue: 2 }],
    warnings: [{ policyId: 'oauth-30', type: 'expires-soon', daysUntilExpiry: 5 }]
  }, { userId: 'system', roleKey: 'admin' });

  assert.equal(notifications.length, 2);
  assert.equal(notifications[0].severity, 'critical');
  assert.equal(notifications[1].severity, 'warning');
  assert.deepEqual(auditEntries.map((entry) => entry.action), [
    'lifecycle-notification.created',
    'lifecycle-notification.created'
  ]);
});

test('LifecycleNotificationService acknowledges and resolves notifications', async () => {
  const service = new LifecycleNotificationService({
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const notification = await service.createNotification({
    type: 'policy.expired',
    severity: 'critical',
    message: 'Credential expired',
    credentialId: 'cred-1',
    providerKey: 'google'
  });

  const acknowledged = await service.acknowledgeNotification(notification.notificationId);
  const resolved = await service.resolveNotification(notification.notificationId);

  assert.equal(acknowledged.status, LifecycleNotificationStatus.ACKNOWLEDGED);
  assert.equal(resolved.status, LifecycleNotificationStatus.RESOLVED);
  assert.equal(resolved.resolvedAt.toISOString(), '2026-07-08T10:00:00.000Z');
});

test('LifecycleNotificationService filters and summarizes notifications', async () => {
  const service = new LifecycleNotificationService({
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  await service.createNotification({ type: 'rotation.failed', severity: 'critical', message: 'failed', providerKey: 'twitch' });
  await service.createNotification({ type: 'rotation.completed', severity: 'info', message: 'ok', providerKey: 'discord' });

  const twitchNotifications = await service.listNotifications({ providerKey: 'twitch' });
  const summary = await service.summarizeNotifications();

  assert.equal(twitchNotifications.length, 1);
  assert.equal(summary.total, 2);
  assert.equal(summary.open, 2);
  assert.equal(summary.critical, 1);
  assert.equal(summary.info, 1);
});

test('CredentialRotationService records lifecycle notifications for rotation results', async () => {
  const { CredentialRotationService } = await import('../../src/services/credential-rotation-service.js');
  const notifications = [];
  const service = new CredentialRotationService({
    credentialManager: {
      async listCredentials() { return [{ credentialId: 'cred-1', providerKey: 'twitch' }]; },
      async refresh() { throw new Error('provider down'); }
    },
    credentialPolicyService: {
      async evaluateCredential() {
        return {
          matchedPolicies: [{ policyId: 'oauth-30', name: 'OAuth 30', rotationIntervalDays: 30, criticality: 'critical' }],
          warnings: [],
          violations: [{ policyId: 'oauth-30', type: 'rotation-overdue', daysOverdue: 1 }]
        };
      }
    },
    lifecycleNotificationService: {
      async createForRotationResult(result) { notifications.push(result); }
    }
  });

  const result = await service.rotateDueCredentials();

  assert.equal(result.failed, 1);
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].success, false);
  assert.equal(notifications[0].credentialId, 'cred-1');
});
