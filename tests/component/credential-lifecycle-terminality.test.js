import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { CredentialManager } from '../../src/managers/credential-manager.js';
import { ConsumerCredentialService } from '../../src/services/consumer-credential-service.js';
import { Credential } from '../../src/models/credential.js';
import { LifecycleState } from '../../src/models/lifecycle-state.js';
import { OAuthResult } from '../../src/models/oauth-result.js';
import { ProviderResult } from '../../src/models/provider-result.js';
import { DerivedRuntimeMaterial } from '../../src/models/derived-runtime-material.js';
import { CredentialCollectionStoreAdapter } from '../../src/storage/credential-collection-store-adapter.js';
import { CredentialSecretVersionService } from '../../src/services/credential-secret-version-service.js';
import { JsonStore } from '../../src/storage/json-store.js';

function oauthCredential(id = 'lifecycle-race') {
  return new Credential({
    credentialId: id,
    credentialKey: `${id}-key`,
    providerKey: 'twitch',
    credentialMethodKey: 'oauth2',
    externalReference: 'main',
    lifecycleState: LifecycleState.ACTIVE,
    secrets: [{ name: 'accessToken', value: 'old-access' }, { name: 'refreshToken', value: 'old-refresh' }]
  });
}

function apiCredential(id = 'validate-race') {
  return new Credential({
    credentialId: id,
    credentialKey: `${id}-key`,
    providerKey: 'example',
    credentialMethodKey: 'api-key',
    lifecycleState: LifecycleState.ACTIVE,
    secrets: [{ name: 'apiKey', value: 'api-key-value' }]
  });
}

async function fileBackedStore() {
  const basePath = await fs.mkdtemp(path.join(os.tmpdir(), 'sekalum-credential-lifecycle-'));
  const store = new CredentialCollectionStoreAdapter({ jsonStore: new JsonStore(), basePath });
  return {
    store,
    async cleanup() { await fs.rm(basePath, { recursive: true, force: true }); }
  };
}

function gatedProvider({ onRefresh = null, onValidate = null } = {}) {
  let refreshStarted;
  let validateStarted;
  let releaseRefresh;
  let releaseValidate;
  const refreshGate = new Promise((resolve) => { releaseRefresh = resolve; });
  const validateGate = new Promise((resolve) => { releaseValidate = resolve; });
  return {
    provider: {
      async refreshCredential() {
        refreshStarted?.();
        await refreshGate;
        return ProviderResult.success(new OAuthResult({
          providerId: 'twitch:main', provider: 'twitch', accountId: 'main',
          accessToken: 'new-access', refreshToken: 'new-refresh'
        }));
      },
      async validateCredential() {
        validateStarted?.();
        await validateGate;
        return ProviderResult.success({ validated: true });
      },
      async revokeCredential() {
        return ProviderResult.success({ revoked: true });
      }
    },
    waitForRefresh() { return new Promise((resolve) => { refreshStarted = resolve; }); },
    waitForValidate() { return new Promise((resolve) => { validateStarted = resolve; }); },
    releaseRefresh,
    releaseValidate,
    onRefresh,
    onValidate
  };
}

test('refresh cannot overwrite a concurrent revoke in the real file-backed store', async () => {
  const { store, cleanup } = await fileBackedStore();
  try {
    const credential = oauthCredential('refresh-revoke');
    await store.save(credential);
    const gated = gatedProvider();
    const manager = new CredentialManager({ credentialStore: store, providerManager: gated.provider });

    const refresh = manager.refresh(credential);
    await gated.waitForRefresh();
    const revoked = await manager.revoke(credential.credentialId);
    assert.equal(revoked.data.credential.lifecycleState, LifecycleState.REVOKED);
    gated.releaseRefresh();

    await assert.rejects(refresh, { code: 'CREDENTIAL_LIFECYCLE_CONFLICT' });
    assert.equal((await store.load(credential.credentialId)).lifecycleState, LifecycleState.REVOKED);
  } finally {
    await cleanup();
  }
});

test('terminal revoke and delete invalidate historical Secret versions before local terminal persistence', async () => {
  const { store, cleanup } = await fileBackedStore();
  const historyPath = path.join(path.dirname(store.filePath), 'credential-secret-versions.json');
  const history = new CredentialSecretVersionService({ store: {
    async load() {
      try { return await new JsonStore().load(historyPath); }
      catch (error) { if (error.code === 'ENOENT') return { versions: [] }; throw error; }
    },
    async save(value) { await new JsonStore().save(historyPath, value); }
  } });
  try {
    const credential = oauthCredential('terminal-history');
    await store.save(credential);
    await history.recordCredentialVersion(credential);
    const manager = new CredentialManager({
      credentialStore: store,
      providerManager: gatedProvider().provider,
      secretVersioningService: history
    });

    const revoked = await manager.revoke(credential.credentialId);
    assert.equal(revoked.data.credential.lifecycleState, LifecycleState.REVOKED);
    await assert.rejects(() => history.getCredentialVersion(credential.credentialId, 1), { code: 'SECRET_VERSION_UNAVAILABLE' });

    const deletedCredential = oauthCredential('terminal-delete');
    await store.save(deletedCredential);
    await history.recordCredentialVersion(deletedCredential);
    const deleted = await manager.delete(deletedCredential.credentialId);
    assert.equal(deleted.lifecycleState, LifecycleState.DELETED);
    await assert.rejects(() => history.getCredentialVersion(deletedCredential.credentialId, 1), { code: 'SECRET_VERSION_UNAVAILABLE' });
  } finally {
    await cleanup();
  }
});

test('revoke-first retains durable containment when history invalidation cannot persist', async () => {
  const stored = new Map();
  const credential = apiCredential('terminal-invalidation-failure');
  stored.set(credential.credentialId, credential);
  const manager = new CredentialManager({
    credentialStore: {
      async load(id) { return stored.get(id); },
      async save(value) { stored.set(value.credentialId, value); },
      async delete(id) { stored.delete(id); return true; }
    },
    providerManager: {
      async revokeCredential() { return ProviderResult.success({ revoked: true }); }
    },
    secretVersioningService: {
      async invalidateHistoryForCredential() { throw new Error('history storage unavailable'); }
    }
  });

  const revoked = await manager.revoke(credential.credentialId);
  assert.equal(revoked.data.credential.lifecycleState, LifecycleState.REVOKED);
  assert.equal(stored.get(credential.credentialId).lifecycleState, LifecycleState.REVOKED);
  assert.equal(stored.get(credential.credentialId).decommissioning.secretHistoryCleanup.status, 'failed_retryable');
});

test('refresh cannot recreate a credential after concurrent delete', async () => {
  const { store, cleanup } = await fileBackedStore();
  try {
    const credential = oauthCredential('refresh-delete');
    await store.save(credential);
    const gated = gatedProvider();
    const manager = new CredentialManager({ credentialStore: store, providerManager: gated.provider });

    const refresh = manager.refresh(credential);
    await gated.waitForRefresh();
    const deleted = await manager.delete(credential.credentialId);
    assert.equal(deleted.lifecycleState, LifecycleState.DELETED);
    await assert.rejects(() => store.load(credential.credentialId), { code: 'NOT_FOUND' });
    gated.releaseRefresh();

    await assert.rejects(refresh, { code: 'CREDENTIAL_LIFECYCLE_CONFLICT' });
    await assert.rejects(() => store.load(credential.credentialId), { code: 'NOT_FOUND' });
  } finally {
    await cleanup();
  }
});

test('validate cannot reactivate a revoked credential after provider work completes', async () => {
  const { store, cleanup } = await fileBackedStore();
  try {
    const credential = apiCredential();
    await store.save(credential);
    const gated = gatedProvider();
    const manager = new CredentialManager({ credentialStore: store, providerManager: gated.provider });

    const validation = manager.validate(credential);
    await gated.waitForValidate();
    await manager.revoke(credential.credentialId);
    gated.releaseValidate();

    await assert.rejects(validation, { code: 'CREDENTIAL_LIFECYCLE_CONFLICT' });
    assert.equal((await store.load(credential.credentialId)).lifecycleState, LifecycleState.REVOKED);
  } finally {
    await cleanup();
  }
});

function resolveRaceSetup() {
  let current = new Credential({
    credentialId: 'resolve-race', credentialKey: 'resolve-race-key', providerKey: 'example', credentialMethodKey: 'api-key',
    lifecycleState: LifecycleState.ACTIVE, secrets: [{ name: 'apiKey', value: 'resolve-secret' }, { name: 'secondaryKey', value: 'secondary-secret' }]
  });
  let grant = { consumerId: 'consumer-1', credentialId: current.credentialId, providerKey: current.providerKey, secretNames: ['apiKey', 'secondaryKey'] };
  let started;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const service = new ConsumerCredentialService({
    credentialStore: {
      async load() { return current; },
      async loadByCredentialKey() { return current; }
    },
    consumerGrantService: { async findGrant() { return grant; } },
    providerRegistry: {
      get() {
        return {
          getCredentialMethod() { return { credentialFields: [{ key: 'apiKey', secret: true }, { key: 'secondaryKey', secret: true }] }; },
          getProviderMethodBinding() { return { methodKey: 'api-key' }; }
        };
      }
    },
    credentialManager: {
      async refreshIfDue() {
        started?.();
        await gate;
        return current;
      }
    }
  });
  return {
    service,
    waitUntilAuthorized: () => new Promise((resolve) => { started = resolve; }),
    release,
    revoke() { current = current.withLifecycleState(LifecycleState.REVOKED); },
    removeGrant() { grant = null; },
    narrowGrant() { grant = { ...grant, secretNames: ['apiKey'] }; }
  };
}

test('Resolve revalidates lifecycle before returning material after revoke', async () => {
  const context = resolveRaceSetup();
  const resolving = context.service.resolve({ consumerId: 'consumer-1', credentialKey: 'resolve-race-key', secretNames: ['apiKey'] });
  await context.waitUntilAuthorized();
  context.revoke();
  context.release();
  await assert.rejects(resolving, { code: 'CREDENTIAL_NOT_CONSUMABLE' });
});

test('Resolve revalidates a grant after deletion and narrowing', async () => {
  const removed = resolveRaceSetup();
  const removing = removed.service.resolve({ consumerId: 'consumer-1', credentialKey: 'resolve-race-key', secretNames: ['apiKey'] });
  await removed.waitUntilAuthorized();
  removed.removeGrant();
  removed.release();
  await assert.rejects(removing, { code: 'GRANT_MISSING' });

  const narrowed = resolveRaceSetup();
  const narrowing = narrowed.service.resolve({ consumerId: 'consumer-1', credentialKey: 'resolve-race-key', secretNames: ['apiKey', 'secondaryKey'] });
  await narrowed.waitUntilAuthorized();
  narrowed.narrowGrant();
  narrowed.release();
  await assert.rejects(narrowing, { code: 'SECRET_NOT_GRANTED' });
});

test('derived Resolve revalidates lifecycle after derivation completes', async () => {
  const profile = { digest: 'profile-v1', identity() { return { digest: 'profile-v1' }; } };
  const contract = {
    supportsRuntimeDerivation: true,
    derivationMethod: 'derive-v1',
    requiredDurableInputs: ['signingIdentity'],
    supportedAudiences: ['https://example.test'],
    supportedScopes: ['read'],
    derivedFields: ['runtimeToken'],
    refreshThresholdMs: 0
  };
  let current = new Credential({
    credentialId: 'derived-race', credentialKey: 'derived-race-key', providerKey: 'example', providerProfile: profile,
    credentialMethodKey: 'service-account', lifecycleState: LifecycleState.ACTIVE,
    secrets: [{ name: 'signingIdentity', value: 'identity' }],
    metadata: { custom: { runtimeDerivation: { audience: 'https://example.test', scopes: ['read'] } } },
    version: 4
  });
  let release;
  let started;
  const gate = new Promise((resolve) => { release = resolve; });
  const contractProvider = {
    providerProfile: profile,
    runtimeDerivation: contract,
    getCredentialMethod() {
      return { credentialFields: [
        { key: 'signingIdentity', secret: true },
        { key: 'runtimeToken', secret: true, materialization: 'derived' }
      ] };
    },
    getProviderMethodBinding() { return { methodKey: 'service-account' }; }
  };
  const service = new ConsumerCredentialService({
    credentialStore: {
      async load() { return current; },
      async loadByCredentialKey() { return current; }
    },
    consumerGrantService: {
      async findGrant() {
        return { consumerId: 'consumer-1', credentialId: current.credentialId, providerKey: current.providerKey, secretNames: ['runtimeToken'] };
      }
    },
    providerRegistry: { get() { return contractProvider; } },
    credentialManager: {
      async deriveRuntimeMaterial(credential, options) {
        started?.();
        await gate;
        return ProviderResult.success(new DerivedRuntimeMaterial({
          credentialIdentity: credential.credentialId,
          providerProfile: profile,
          derivationMethod: contract.derivationMethod,
          values: { runtimeToken: 'derived-secret' },
          expiresAt: new Date(Date.now() + 60_000),
          effectiveScopes: options.scopes,
          audience: options.audience,
          runtimeContext: options.runtimeContext,
          sourceVersion: credential.version
        }));
      }
    }
  });

  const startedGate = new Promise((resolve) => { started = resolve; });
  const resolving = service.resolve({ consumerId: 'consumer-1', credentialKey: current.credentialKey, secretNames: ['runtimeToken'] });
  await startedGate;
  current = current.withLifecycleState(LifecycleState.REVOKED);
  release();
  await assert.rejects(resolving, { code: 'CREDENTIAL_NOT_CONSUMABLE' });
});
