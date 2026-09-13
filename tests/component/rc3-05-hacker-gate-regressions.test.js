import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { LifecycleState } from '../../src/models/lifecycle-state.js';
import { CredentialManager } from '../../src/managers/credential-manager.js';
import { ConsumerCredentialService } from '../../src/services/consumer-credential-service.js';
import { ProviderResult } from '../../src/models/provider-result.js';

function providerRegistry() {
  return {
    get() {
      return {
        getCredentialMethod() {
          return { key: 'api-key', credentialFields: [{ key: 'apiKey', secret: true }] };
        },
        getProviderMethodBinding() { return { methodKey: 'api-key' }; }
      };
    }
  };
}

function credentialStore(initial) {
  let current = Credential.from(initial);
  return {
    async load() { return current; },
    async loadByCredentialKey() { return current; },
    async saveConditional(next, { expectedVersion }) {
      if (current.version !== expectedVersion) {
        const error = new Error('credential changed');
        error.code = 'CREDENTIAL_LIFECYCLE_CONFLICT';
        throw error;
      }
      current = Credential.from(next);
      return current;
    },
    async save(next) { current = Credential.from(next); return current; },
    get current() { return current; }
  };
}

test('REVOKE-FIRST-ATTACK-001: durable containment prevents secret delivery during cleanup failure', async () => {
  const active = new Credential({
    credentialId: 'attack-credential',
    credentialKey: 'attack-key',
    credentialGeneration: 'attack-generation-a',
    providerKey: 'attack-provider',
    credentialMethodKey: 'api-key',
    lifecycleState: LifecycleState.ACTIVE,
    secrets: [{ name: 'apiKey', value: 'attack-secret' }]
  });
  const store = credentialStore(active);
  const grant = { grantId: 'attack-grant', consumerId: 'attack-consumer', credentialId: active.credentialId, credentialGeneration: active.credentialGeneration, providerKey: active.providerKey, secretNames: ['apiKey'] };
  const consumer = new ConsumerCredentialService({
    credentialStore: store,
    consumerGrantService: { async findGrant() { return grant; } },
    providerRegistry: providerRegistry(),
    auditLogService: { async record() {} }
  });
  const manager = new CredentialManager({
    credentialStore: store,
    providerManager: { async revokeCredential() { return ProviderResult.failure({ code: 'PROVIDER_REVOKE_FAILED', message: 'remote cleanup failed' }); } },
    secretVersioningService: { async invalidateHistoryForCredential() { throw Object.assign(new Error('history cleanup failed'), { code: 'SECRET_HISTORY_CLEANUP_FAILED' }); } },
    auditLogService: { async record() {} }
  });

  const revoked = await manager.revoke(active);
  assert.equal(revoked.success, true);
  assert.equal(store.current.lifecycleState, LifecycleState.REVOKED);
  assert.equal(store.current.decommissioning.providerCleanup.status, 'failed_retryable');
  assert.equal(store.current.decommissioning.secretHistoryCleanup.status, 'failed_retryable');

  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(
      consumer.resolve({ consumerId: grant.consumerId, credentialKey: active.credentialKey, secretNames: ['apiKey'] }),
      (error) => error.code === 'CREDENTIAL_NOT_CONSUMABLE'
    );
  }
  assert.equal(store.current.secrets[0].value, 'attack-secret');
});

test('ORPHAN-RESURRECTION-ATTACK-001: an old generation grant cannot authorize a replacement credential', async () => {
  const replacement = new Credential({
    credentialId: 'resurrection-credential',
    credentialKey: 'resurrection-key',
    credentialGeneration: 'generation-b',
    providerKey: 'same-provider',
    credentialMethodKey: 'api-key',
    lifecycleState: LifecycleState.ACTIVE,
    externalReference: 'same-external-account',
    secrets: [{ name: 'apiKey', value: 'replacement-secret' }],
    metadata: { displayName: 'Same account' }
  });
  const store = credentialStore(replacement);
  const oldGrant = { grantId: 'old-grant', consumerId: 'resurrection-consumer', credentialId: replacement.credentialId, credentialGeneration: 'generation-a', providerKey: replacement.providerKey, secretNames: ['apiKey'] };
  const consumer = new ConsumerCredentialService({
    credentialStore: store,
    consumerGrantService: { async findGrant() { return oldGrant; } },
    providerRegistry: providerRegistry(),
    auditLogService: { async record() {} }
  });

  await assert.rejects(
    consumer.resolve({ consumerId: oldGrant.consumerId, credentialKey: replacement.credentialKey, secretNames: ['apiKey'] }),
    (error) => error.code === 'GRANT_MISSING'
  );
  assert.equal(store.current.credentialGeneration, 'generation-b');
  assert.equal(store.current.secrets[0].value, 'replacement-secret');
});
