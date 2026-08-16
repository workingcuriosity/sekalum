import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialPolicy } from '../../src/models/credential-policy.js';
import { CredentialPolicyService } from '../../src/services/credential-policy-service.js';

test('CredentialPolicy validates required lifecycle policy fields', () => {
  assert.throws(() => new CredentialPolicy({ name: 'OAuth' }), /policyId/);
  assert.throws(() => new CredentialPolicy({ policyId: 'p1' }), /name/);
  assert.throws(() => new CredentialPolicy({ policyId: 'p1', name: 'OAuth', rotationIntervalDays: 0 }), /rotationIntervalDays/);
  assert.throws(() => new CredentialPolicy({ policyId: 'p1', name: 'OAuth', criticality: 'urgent' }), /criticality/);
});

test('CredentialPolicyService creates, lists and persists policies', async () => {
  const saved = [];
  const service = new CredentialPolicyService({
    store: {
      async load() { return saved.at(-1) ?? { policies: [] }; },
      async save(data) { saved.push(data); }
    },
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  const policy = await service.createPolicy({
    policyId: 'oauth-standard',
    name: 'OAuth Standard',
    providerKey: 'twitch',
    credentialType: 'oauth',
    rotationIntervalDays: 30,
    requiresRotation: true,
    criticality: 'high'
  });

  assert.equal(policy.policyId, 'oauth-standard');
  assert.equal(policy.createdAt.toISOString(), '2026-07-08T10:00:00.000Z');
  assert.equal(saved.length, 1);

  const policies = await service.listPolicies({ providerKey: 'twitch' });
  assert.equal(policies.length, 1);
  assert.equal(policies[0].name, 'OAuth Standard');
});

test('CredentialPolicyService evaluates expiry and rotation policy violations', async () => {
  const service = new CredentialPolicyService({ clock: () => new Date('2026-07-08T10:00:00.000Z') });

  await service.createPolicy({
    policyId: 'oauth-rotation',
    name: 'OAuth Rotation',
    providerKey: 'twitch',
    credentialType: 'oauth',
    rotationIntervalDays: 30,
    expiryWarningDays: 10,
    requiresRotation: true
  });

  const result = await service.evaluateCredential({
    credentialId: 'cred-1',
    providerKey: 'twitch',
    updatedAt: '2026-05-01T00:00:00.000Z',
    metadata: {
      type: 'oauth',
      expiresAt: '2026-07-12T00:00:00.000Z',
      lastRotatedAt: '2026-05-15T00:00:00.000Z'
    }
  });

  assert.equal(result.compliant, false);
  assert.equal(result.matchedPolicies.length, 1);
  assert.deepEqual(result.warnings, [{ policyId: 'oauth-rotation', type: 'expires-soon', daysUntilExpiry: 3 }]);
  assert.equal(result.violations.length, 1);
  assert.equal(result.violations[0].type, 'rotation-overdue');
});

test('CredentialPolicyService records audit entries for policy changes', async () => {
  const auditEntries = [];
  const service = new CredentialPolicyService({
    auditLogService: {
      async record(entry) { auditEntries.push(entry); }
    }
  });

  await service.createPolicy({ policyId: 'api-policy', name: 'API Policy' }, { userId: 'admin-1', roleKey: 'admin' });
  await service.disablePolicy('api-policy', { userId: 'admin-1', roleKey: 'admin' });

  assert.equal(auditEntries.length, 3);
  assert.equal(auditEntries[0].action, 'credential-policy.created');
  assert.equal(auditEntries[1].action, 'credential-policy.updated');
  assert.equal(auditEntries[2].action, 'credential-policy.disabled');
  assert.equal(auditEntries[0].targetType, 'credential-policy');
});
