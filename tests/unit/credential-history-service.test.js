import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialHistoryService } from '../../src/services/credential-history-service.js';
import { CredentialSecretVersion } from '../../src/models/credential-secret-version.js';

test('CredentialHistoryService combines credential audit events and secret versions', async () => {
  const service = new CredentialHistoryService({
    auditLogService: {
      async list(filters) {
        assert.equal(filters.targetType, 'credential');
        assert.equal(filters.targetId, 'cred-1');
        return [
          {
            entryId: 'audit-1',
            timestamp: '2026-07-08T10:00:00.000Z',
            userId: 'admin',
            roleKey: 'administrator',
            action: 'credential-policy.created',
            targetType: 'credential',
            targetId: 'cred-1',
            result: 'success',
            details: { policyId: 'policy-1' }
          }
        ];
      }
    },
    secretVersioningService: {
      async listCredentialVersions(credentialId) {
        assert.equal(credentialId, 'cred-1');
        return [new CredentialSecretVersion({
          versionId: 'version-1',
          credentialId: 'cred-1',
          version: 1,
          secrets: [{ name: 'apiKey', value: 'secret' }],
          reason: 'initial-import',
          createdAt: '2026-07-08T10:01:00.000Z',
          createdBy: 'system'
        })];
      }
    }
  });

  const entries = await service.listCredentialHistory('cred-1');

  assert.equal(entries.length, 2);
  assert.deepEqual(entries.map((entry) => entry.source), ['secret-version', 'audit-log']);
  assert.equal(entries[0].historyId, 'secret-version:version-1');
  assert.equal(entries[1].historyId, 'audit:audit-1');
});

test('CredentialHistoryService supports source and limit filters', async () => {
  const service = new CredentialHistoryService({
    auditLogService: {
      async list() {
        return [{
          entryId: 'audit-1',
          timestamp: '2026-07-08T10:00:00.000Z',
          userId: 'admin',
          roleKey: null,
          action: 'credential.updated',
          targetType: 'credential',
          targetId: 'cred-1',
          result: 'success',
          details: null
        }];
      }
    },
    secretVersioningService: {
      async listCredentialVersions() {
        return [new CredentialSecretVersion({
          versionId: 'version-1',
          credentialId: 'cred-1',
          version: 1,
          secrets: [],
          createdAt: '2026-07-08T10:01:00.000Z'
        })];
      }
    }
  });

  const entries = await service.listCredentialHistory('cred-1', {
    source: 'audit-log',
    limit: 1
  });

  assert.equal(entries.length, 1);
  assert.equal(entries[0].source, 'audit-log');
});

test('CredentialHistoryService summarizes credential history', async () => {
  const service = new CredentialHistoryService({
    auditLogService: {
      async list() {
        return [{
          entryId: 'audit-1',
          timestamp: '2026-07-08T10:00:00.000Z',
          userId: 'system',
          roleKey: null,
          action: 'credential-rotation.completed',
          targetType: 'credential',
          targetId: 'cred-1',
          result: 'success',
          details: null
        }];
      }
    },
    secretVersioningService: {
      async listCredentialVersions() {
        return [new CredentialSecretVersion({
          versionId: 'version-1',
          credentialId: 'cred-1',
          version: 1,
          secrets: [],
          createdAt: '2026-07-08T09:00:00.000Z'
        })];
      }
    }
  });

  const summary = await service.summarizeCredentialHistory('cred-1', { includeEntries: false });

  assert.equal(summary.total, 2);
  assert.deepEqual(summary.countsBySource, { 'audit-log': 1, 'secret-version': 1 });
  assert.deepEqual(summary.countsByResult, { success: 2 });
  assert.equal(summary.entries.length, 0);
  assert.equal(summary.lastEventAt, '2026-07-08T10:00:00.000Z');
  assert.equal(summary.firstEventAt, '2026-07-08T09:00:00.000Z');
});
