import test from 'node:test';
import assert from 'node:assert/strict';

import { RuntimePublicProjectionService } from '../../src/services/runtime-public-projection-service.js';

const credential = (overrides = {}) => ({
  providerKey: 'twitch',
  metadata: { custom: { providerConfigurationId: 'configuration-1' } },
  ...overrides
});

const provider = (fields = []) => ({ credentialFields: fields });

const runtimePublicField = (key = 'clientId', overrides = {}) => ({
  key,
  section: 'providerConfiguration',
  runtimePublic: true,
  secret: false,
  ...overrides
});

const createService = ({ providerDefinition = provider(), record = null, load = null } = {}) => {
  const calls = [];
  const providerConfigurationService = {
    async load(configurationId, providerKey) {
      calls.push(['load', configurationId, providerKey]);
      if (load) return load(configurationId, providerKey);
      return record;
    },
    toPublicJSON() {
      throw new Error('management serialization must not be used');
    }
  };
  const service = new RuntimePublicProjectionService({
    providerConfigurationService,
    providerRegistry: { get() { return providerDefinition; } }
  });
  return { calls, service };
};

test('RuntimePublicProjectionService projects allowlisted values from the bound configuration', async () => {
  const { service } = createService({
    providerDefinition: provider([
      runtimePublicField('clientId'),
      runtimePublicField('scopes')
    ]),
    record: {
      configurationId: 'configuration-1',
      providerKey: 'twitch',
      configuration: { clientId: 'public-client', scopes: ['read:user'] }
    }
  });

  assert.deepEqual(await service.project({ credential: credential() }), {
    runtimePublic: { clientId: 'public-client', scopes: ['read:user'] }
  });
});

test('RuntimePublicProjectionService applies the Runtime-Public allowlist', async () => {
  const { service } = createService({
    providerDefinition: provider([
      runtimePublicField('clientId'),
      { key: 'redirectUri', section: 'providerConfiguration', runtimePublic: false, secret: false }
    ]),
    record: {
      configurationId: 'configuration-1',
      providerKey: 'twitch',
      configuration: { clientId: 'public-client', redirectUri: 'https://internal.example/callback' }
    }
  });

  assert.deepEqual(await service.project({ credential: credential() }), {
    runtimePublic: { clientId: 'public-client' }
  });
});

test('RuntimePublicProjectionService excludes secrets and internal fields defensively', async () => {
  const { service } = createService({
    providerDefinition: provider([
      runtimePublicField('clientId'),
      runtimePublicField('clientSecret', { secret: true }),
      runtimePublicField('providerConfigurationId'),
      runtimePublicField('routing')
    ]),
    record: {
      configurationId: 'configuration-1',
      providerKey: 'twitch',
      configuration: {
        clientId: 'public-client',
        clientSecret: 'must-not-leak',
        providerConfigurationId: 'configuration-1',
        routing: 'internal-route'
      }
    }
  });

  assert.deepEqual(await service.project({ credential: credential() }), {
    runtimePublic: { clientId: 'public-client' }
  });
});

test('RuntimePublicProjectionService fails closed for a wrong provider', async () => {
  const { service } = createService({
    providerDefinition: provider([runtimePublicField()]),
    record: {
      configurationId: 'configuration-1',
      providerKey: 'google',
      configuration: { clientId: 'wrong-provider' }
    }
  });

  assert.equal(await service.project({ credential: credential() }), null);
});

test('RuntimePublicProjectionService fails closed when the provider is unavailable', async () => {
  const { service } = createService({
    providerDefinition: null,
    record: {
      configurationId: 'configuration-1',
      providerKey: 'twitch',
      configuration: { clientId: 'must-not-leak' }
    }
  });

  assert.equal(await service.project({ credential: credential() }), null);
});

test('RuntimePublicProjectionService fails closed when configuration is missing', async () => {
  const { service } = createService({
    providerDefinition: provider([runtimePublicField()]),
    load() { throw new Error('missing configuration'); }
  });

  assert.equal(await service.project({ credential: credential() }), null);
});

test('RuntimePublicProjectionService omits an empty projection', async () => {
  const { service } = createService({
    providerDefinition: provider([runtimePublicField()]),
    record: {
      configurationId: 'configuration-1',
      providerKey: 'twitch',
      configuration: {}
    }
  });

  assert.equal(await service.project({ credential: credential() }), null);
});

test('RuntimePublicProjectionService fails closed for an invalid configuration record', async () => {
  const { calls, service } = createService({
    providerDefinition: provider([runtimePublicField()]),
    record: {
      configurationId: 'different-configuration',
      providerKey: 'twitch',
      configuration: { clientId: 'public-client' }
    }
  });

  assert.equal(await service.project({ credential: credential() }), null);
  assert.deepEqual(calls, [['load', 'configuration-1', 'twitch']]);
});

test('RuntimePublicProjectionService does not use management serialization', async () => {
  const { service } = createService({
    providerDefinition: provider([runtimePublicField()]),
    record: {
      configurationId: 'configuration-1',
      providerKey: 'twitch',
      configuration: { clientId: 'public-client' }
    }
  });

  await assert.doesNotReject(() => service.project({ credential: credential() }));
});
