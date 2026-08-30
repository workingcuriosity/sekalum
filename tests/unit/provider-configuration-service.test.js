import test from 'node:test';
import assert from 'node:assert/strict';

import { ProviderConfigurationService } from '../../src/services/provider-configuration-service.js';

function fields() {
  return [
    { key: 'clientId', required: true, secret: false, section: 'providerConfiguration' },
    { key: 'clientSecret', required: true, secret: true, section: 'providerConfiguration' },
    { key: 'redirectUri', required: true, secret: false, section: 'providerConfiguration' },
    { key: 'displayName', required: true, secret: false, section: 'credentialDisplay' }
  ];
}

function createService() {
  const records = new Map();
  const store = {
    async save(record) { records.set(record.configurationId, structuredClone(record)); return record; },
    async list() { return [...records.values()].map((record) => structuredClone(record)); },
    async load(id) { return structuredClone(records.get(id)); },
    async delete(id) { return records.delete(id); }
  };
  return { service: new ProviderConfigurationService({ store }), records };
}

test('provider configuration validates required application fields before persistence', async () => {
  const { service, records } = createService();

  await assert.rejects(
    () => service.prepare({ providerKey: 'x', fields: fields(), values: { clientId: 'x-client' } }),
    (error) => error.code === 'PROVIDER_CONFIGURATION_MISSING'
  );
  assert.equal(records.size, 0);
});

test('provider configuration removal verifies ownership and deletes the encrypted record', async () => {
  const { service, records } = createService();
  const record = await service.prepare({
    providerKey: 'x',
    fields: fields(),
    values: {
      clientId: 'x-client',
      clientSecret: 'x-secret',
      redirectUri: 'https://credential-hub.example.com/oauth/x/callback'
    }
  });

  await assert.rejects(
    () => service.remove(record.configurationId, 'google'),
    (error) => error.code === 'PROVIDER_CONFIGURATION_INVALID'
  );
  assert.equal(records.size, 1);
  assert.equal(await service.remove(record.configurationId, 'x'), true);
  assert.equal(records.size, 0);
});

test('provider configuration public result masks secret fields without returning values', async () => {
  const { service } = createService();
  const record = await service.prepare({
    providerKey: 'x',
    fields: fields(),
    values: {
      clientId: 'x-client',
      clientSecret: 'x-secret',
      redirectUri: 'https://credential-hub.example.com/oauth/x/callback'
    }
  });
  const publicRecord = service.toPublicJSON(record, fields());

  assert.deepEqual(publicRecord.configuredFields.sort(), ['clientId', 'clientSecret', 'redirectUri']);
  assert.deepEqual(publicRecord.maskedFields, ['clientSecret']);
  assert.equal(JSON.stringify(publicRecord).includes('x-secret'), false);
});

test('provider configuration cleanup removes only expired temporary flow records', async () => {
  const { service, records } = createService();
  const now = new Date('2026-08-27T12:00:00.000Z');
  records.set('referenced', {
    configurationId: 'referenced',
    providerKey: 'x',
    lifecycle: 'temporary_oauth_flow',
    expiresAt: '2026-08-27T11:00:00.000Z'
  });
  records.set('expired-temporary', {
    configurationId: 'expired-temporary',
    providerKey: 'x',
    lifecycle: 'temporary_oauth_flow',
    expiresAt: '2026-08-27T11:00:00.000Z'
  });
  records.set('live-temporary', {
    configurationId: 'live-temporary',
    providerKey: 'x',
    lifecycle: 'temporary_oauth_flow',
    expiresAt: '2026-08-27T13:00:00.000Z'
  });
  records.set('durable-unreferenced', { configurationId: 'durable-unreferenced', providerKey: 'x' });
  records.set('unknown', { configurationId: 'unknown', providerKey: 'x', expiresAt: '2026-08-27T11:00:00.000Z' });

  const result = await service.removeExpiredTemporaryFlowConfigurations(['referenced'], now);

  assert.deepEqual(result.removed, ['expired-temporary']);
  assert.deepEqual(result.failed, []);
  assert.equal(records.has('referenced'), true);
  assert.equal(records.has('expired-temporary'), false);
  assert.equal(records.has('live-temporary'), true);
  assert.equal(records.has('durable-unreferenced'), true);
  assert.equal(records.has('unknown'), true);
});

test('new OAuth-flow configuration records carry explicit temporary ownership and expiry', async () => {
  const { service } = createService();
  const record = await service.prepare({
    providerKey: 'x',
    fields: fields(),
    values: {
      clientId: 'x-client',
      clientSecret: 'x-secret',
      redirectUri: 'https://credential-hub.example.com/oauth/x/callback'
    },
    temporary: true,
    expiresAt: '2026-08-27T13:00:00.000Z'
  });

  assert.equal(record.lifecycle, 'temporary_oauth_flow');
  assert.equal(record.expiresAt, '2026-08-27T13:00:00.000Z');
});
