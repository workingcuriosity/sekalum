import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialRotationService } from '../../src/services/credential-rotation-service.js';
import { ProviderResult } from '../../src/models/provider-result.js';

test('CredentialRotationService plans overdue credential rotations from policies', async () => {
  const service = new CredentialRotationService({
    credentialManager: {
      async listCredentials() {
        return [
          { credentialId: 'cred-1', providerKey: 'twitch' },
          { credentialId: 'cred-2', providerKey: 'discord' }
        ];
      },
      async refresh() {}
    },
    credentialPolicyService: {
      async evaluateCredential(credential) {
        return credential.credentialId === 'cred-1'
          ? {
              matchedPolicies: [{ policyId: 'oauth-30', name: 'OAuth 30', rotationIntervalDays: 30, criticality: 'high' }],
              warnings: [],
              violations: [{ policyId: 'oauth-30', type: 'rotation-overdue', daysOverdue: 5 }]
            }
          : { matchedPolicies: [], warnings: [], violations: [] };
      }
    },
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const plan = await service.planRotation();

  assert.equal(plan.requested, 2);
  assert.equal(plan.candidates, 1);
  assert.equal(plan.skipped, 1);
  assert.equal(plan.items[0].credentialId, 'cred-1');
  assert.equal(plan.items[0].findings[0].type, 'rotation-overdue');
});

test('CredentialRotationService rotates due credentials and records audit entries', async () => {
  const auditEntries = [];
  const refreshed = [];
  const service = new CredentialRotationService({
    credentialManager: {
      async listCredentials() {
        return [{ credentialId: 'cred-1', providerKey: 'twitch' }];
      },
      async refresh(credentialId) {
        refreshed.push(credentialId);
        return ProviderResult.success({ credential: { credentialId, providerKey: 'twitch', version: 2 } });
      }
    },
    credentialPolicyService: {
      async evaluateCredential() {
        return {
          matchedPolicies: [{ policyId: 'oauth-30', name: 'OAuth 30', rotationIntervalDays: 30, criticality: 'high' }],
          warnings: [],
          violations: [{ policyId: 'oauth-30', type: 'rotation-overdue', daysOverdue: 1 }]
        };
      }
    },
    auditLogService: {
      async record(entry) { auditEntries.push(entry); }
    },
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const result = await service.rotateDueCredentials({}, { userId: 'system', roleKey: 'system' });

  assert.deepEqual(refreshed, ['cred-1']);
  assert.equal(result.succeeded, 1);
  assert.equal(result.failed, 0);
  assert.equal(result.results[0].credential.version, 2);
  assert.deepEqual(auditEntries.map((entry) => entry.action), [
    'credential-rotation.started',
    'credential-rotation.completed'
  ]);
});

test('CredentialRotationService keeps batch running when one rotation fails', async () => {
  const service = new CredentialRotationService({
    credentialManager: {
      async listCredentials() {
        return [
          { credentialId: 'cred-1', providerKey: 'twitch' },
          { credentialId: 'cred-2', providerKey: 'discord' }
        ];
      },
      async refresh(credentialId) {
        if (credentialId === 'cred-1') throw new Error('provider unavailable');
        return ProviderResult.success({ credential: { credentialId, providerKey: 'discord' } });
      }
    },
    credentialPolicyService: {
      async evaluateCredential() {
        return {
          matchedPolicies: [{ policyId: 'oauth-30', name: 'OAuth 30', rotationIntervalDays: 30, criticality: 'normal' }],
          warnings: [],
          violations: [{ policyId: 'oauth-30', type: 'rotation-overdue', daysOverdue: 1 }]
        };
      }
    }
  });

  const result = await service.rotateDueCredentials();

  assert.equal(result.succeeded, 1);
  assert.equal(result.failed, 1);
  assert.equal(result.results[0].success, false);
  assert.equal(result.results[1].success, true);
});

test('CredentialRotationService can include missing rotation dates as warning candidates', async () => {
  const service = new CredentialRotationService({
    credentialManager: {
      async listCredentials() { return [{ credentialId: 'cred-1', providerKey: 'twitch' }]; },
      async refresh() {}
    },
    credentialPolicyService: {
      async evaluateCredential() {
        return {
          matchedPolicies: [{ policyId: 'oauth-30', name: 'OAuth 30', rotationIntervalDays: 30, criticality: 'low' }],
          warnings: [{ policyId: 'oauth-30', type: 'rotation-date-missing' }],
          violations: []
        };
      }
    }
  });

  assert.equal((await service.planRotation()).candidates, 0);
  assert.equal((await service.planRotation({ includeWarnings: true })).candidates, 1);
});

test('CredentialRotationService uses provider rotation framework and reports skipped providers', async () => {
  const service = new CredentialRotationService({
    credentialManager: {
      async listCredentials() {
        return [{ credentialId: 'cred-skip', providerKey: 'ftp' }];
      },
      async refresh() {
        throw new Error('direct refresh must not be called');
      }
    },
    credentialPolicyService: {
      async evaluateCredential() {
        return {
          matchedPolicies: [{ policyId: 'rotation', name: 'Rotation', rotationIntervalDays: 30, criticality: 'medium' }],
          warnings: [],
          violations: [{ policyId: 'rotation', type: 'rotation-overdue' }]
        };
      }
    },
    providerRotationFramework: {
      async rotateCredential(item) {
        return {
          credentialId: item.credentialId,
          providerKey: item.providerKey,
          success: false,
          skipped: true,
          reason: 'provider-refresh-not-supported',
          findings: item.findings
        };
      }
    }
  });

  const result = await service.rotateDueCredentials();

  assert.equal(result.succeeded, 0);
  assert.equal(result.failed, 0);
  assert.equal(result.skipped, 1);
  assert.equal(result.results[0].skipped, true);
  assert.equal(result.results[0].reason, 'provider-refresh-not-supported');
});
