import test from 'node:test';
import assert from 'node:assert/strict';

import { ProviderRotationFramework } from '../../src/services/provider-rotation-framework.js';
import { ProviderCapability } from '../../src/models/provider-capability.js';
import { ProviderResult } from '../../src/models/provider-result.js';

test('ProviderRotationFramework rotates credentials when provider supports refresh', async () => {
  const refreshed = [];
  const auditEntries = [];
  const service = new ProviderRotationFramework({
    credentialManager: {
      async getCredential(credentialId) {
        return { credentialId, providerKey: 'twitch' };
      },
      async refresh(credentialId) {
        refreshed.push(credentialId);
        return ProviderResult.success({ credential: { credentialId, providerKey: 'twitch', version: 2 } });
      }
    },
    providerManager: {
      getProviderCapabilities(providerKey) {
        assert.equal(providerKey, 'twitch');
        return [ProviderCapability.REFRESH, ProviderCapability.VALIDATION];
      }
    },
    auditLogService: {
      async record(entry) { auditEntries.push(entry); }
    }
  });

  const result = await service.rotateCredential({ credentialId: 'cred-1', providerKey: 'twitch', findings: [] });

  assert.deepEqual(refreshed, ['cred-1']);
  assert.equal(result.success, true);
  assert.equal(result.skipped, false);
  assert.equal(result.credential.version, 2);
  assert.deepEqual(auditEntries.map((entry) => entry.action), [
    'provider-rotation.started',
    'provider-rotation.completed'
  ]);
});

test('ProviderRotationFramework skips credentials when provider lacks refresh capability', async () => {
  const notifications = [];
  const service = new ProviderRotationFramework({
    credentialManager: {
      async getCredential(credentialId) {
        return { credentialId, providerKey: 'ftp' };
      },
      async refresh() {
        throw new Error('refresh must not be called');
      }
    },
    providerManager: {
      getProviderCapabilities() {
        return [ProviderCapability.HEALTH_CHECK];
      }
    },
    lifecycleNotificationService: {
      async createForRotationResult(result) { notifications.push(result); }
    }
  });

  const result = await service.rotateCredential({ credentialId: 'cred-2', providerKey: 'ftp', findings: [] });

  assert.equal(result.success, false);
  assert.equal(result.skipped, true);
  assert.equal(result.reason, 'provider-refresh-not-supported');
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].skipped, true);
});

test('ProviderRotationFramework isolates provider rotation failures as errors for caller', async () => {
  const service = new ProviderRotationFramework({
    credentialManager: {
      async getCredential(credentialId) {
        return { credentialId, providerKey: 'discord' };
      },
      async refresh() {
        return ProviderResult.failure({ code: 'REMOTE_FAILURE', message: 'remote failed' });
      }
    },
    providerManager: {
      getProviderCapabilities() {
        return [ProviderCapability.REFRESH];
      }
    }
  });

  await assert.rejects(
    () => service.rotateCredential({ credentialId: 'cred-3', providerKey: 'discord', findings: [] }),
    /remote failed/
  );
});

test('ProviderRotationFramework summarizes mixed rotation results', () => {
  const service = new ProviderRotationFramework({
    credentialManager: { async refresh() {} },
    providerManager: { getProviderCapabilities() { return []; } }
  });

  const summary = service.summarize([
    { success: true },
    { success: false, skipped: true },
    { success: false }
  ]);

  assert.equal(summary.requested, 3);
  assert.equal(summary.succeeded, 1);
  assert.equal(summary.skipped, 1);
  assert.equal(summary.failed, 1);
});
