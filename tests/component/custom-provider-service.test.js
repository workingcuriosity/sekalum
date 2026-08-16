import test from 'node:test';
import assert from 'node:assert/strict';

import { CustomProviderService } from '../../src/services/custom-provider-service.js';
import { CustomProviderDefinitionStore } from '../../src/storage/custom-provider-definition-store.js';
import { ProviderRegistry } from '../../src/registry/provider-registry.js';
import { ProviderManager } from '../../src/managers/provider-manager.js';

function createService(records = []) {
  const store = {
    async list() { return structuredClone(records); },
    async save(definition) { records.push(structuredClone(definition)); return definition; },
    async delete(key) {
      const index = records.findIndex((entry) => entry.key === key);
      if (index >= 0) records.splice(index, 1);
    }
  };
  const registry = new ProviderRegistry({ logger: { info() {} } });
  return { service: new CustomProviderService({ store, providerRegistry: registry }), registry, records };
}

function provider() {
  return {
    key: 'acme-service',
    displayName: 'Acme Service',
    category: 'CRM',
    description: 'Declarative test provider',
    credentialMethods: [{
      key: 'api-key', displayName: 'API key', description: 'Use an API key',
      credentialFields: [{ key: 'apiKey', label: 'API key', type: 'api-key', required: true, secret: true, section: 'accountCredentials' }]
    }],
    providerMethodBindings: [{ methodKey: 'api-key', displayName: 'Acme API key', description: 'Use an API key' }],
    credentialFields: [{ key: 'apiKey', label: 'API key', type: 'api-key', required: true, secret: true, section: 'accountCredentials' }]
  };
}

test('CustomProviderService persists and immediately registers a declarative provider', async () => {
  const { service, registry, records } = createService();
  const created = await service.create(provider());

  assert.equal(records.length, 1);
  assert.equal(created.key, 'acme-service');
  assert.equal(registry.has('acme-service'), true);
  assert.equal(registry.get('acme-service').metadata.customProvider, true);
  assert.deepEqual(registry.get('acme-service').providerMethodBindings[0].toJSON(), {
    methodKey: 'api-key', displayName: 'Acme API key', description: 'Use an API key', metadata: {}, operationCapabilities: []
  });
});

test('a created custom provider is immediately available through the public ProviderManager contract', async () => {
  const { service, registry } = createService();
  await service.create(provider());
  const manager = new ProviderManager({ providerRegistry: registry, logger: { error() {} } });
  const summary = manager.getProvider('acme-service');

  assert.equal(summary.key, 'acme-service');
  assert.equal(summary.displayName, 'Acme Service');
  assert.equal(summary.category, 'CRM');
  assert.deepEqual(summary.capabilities, []);
  assert.deepEqual(summary.providerConfigurationFields, []);
  assert.deepEqual(summary.credentialMethods.map(({ key, displayName, description, operationCapabilities }) => ({ key, displayName, description, operationCapabilities })), [{
    key: 'api-key', displayName: 'API key', description: 'Use an API key', operationCapabilities: []
  }]);
  assert.deepEqual(summary.providerMethodBindings, [{
    methodKey: 'api-key', displayName: 'Acme API key', description: 'Use an API key', metadata: {}, operationCapabilities: []
  }]);
  assert.equal(summary.credentialFields[0].key, 'apiKey');
  assert.equal(summary.credentialFields[0].secret, true);
  assert.equal(summary.credentialFields[0].defaultValue, null);
  assert.equal('operationAdapters' in summary.providerMethodBindings[0], false);
});

test('CustomProviderService hydrates persisted definitions on restart', async () => {
  const { service, registry } = createService([provider()]);
  await service.hydrate();
  assert.equal(registry.has('acme-service'), true);

  const manager = new ProviderManager({ providerRegistry: registry, logger: { error() {} } });
  assert.deepEqual(manager.getProvider('acme-service').credentialMethods.map((method) => method.key), ['api-key']);
  assert.deepEqual(manager.getProvider('acme-service').providerMethodBindings.map((binding) => binding.methodKey), ['api-key']);
});

test('CustomProviderService rolls back persistence when registration fails', async () => {
  const records = [];
  const store = {
    async list() { return structuredClone(records); },
    async save(definition) { records.push(structuredClone(definition)); return definition; },
    async delete(key) {
      const index = records.findIndex((entry) => entry.key === key);
      if (index >= 0) records.splice(index, 1);
    }
  };
  const registry = {
    has() { return false; },
    register() { throw new Error('Registry unavailable'); }
  };
  const service = new CustomProviderService({ store, providerRegistry: registry });

  await assert.rejects(service.create(provider()), /Registry unavailable/);
  assert.deepEqual(records, []);
});

test('CustomProviderService rejects executable, OAuth, configuration, and secret values', async () => {
  const { service } = createService();
  for (const property of ['providerConfigurationFields', 'oauth', 'hooks', 'scripts', 'code', 'secrets']) {
    await assert.rejects(service.create({ ...provider(), [property]: [] }), { code: 'PROVIDER_DEFINITION_INVALID' });
  }
  await assert.rejects(service.create({
    ...provider(),
    credentialMethods: [{ ...provider().credentialMethods[0], operationCapabilities: ['refresh'] }]
  }), { code: 'PROVIDER_DEFINITION_INVALID' });
  await assert.rejects(service.create({
    ...provider(),
    providerMethodBindings: [{ ...provider().providerMethodBindings[0], operationAdapters: { refresh: 'not-executable' } }]
  }), { code: 'PROVIDER_DEFINITION_INVALID' });
  for (const property of ['defaultValue', 'validation', 'options', 'csvAliases', 'systemManaged']) {
    await assert.rejects(service.create({
      ...provider(),
      credentialMethods: [{
        ...provider().credentialMethods[0],
        credentialFields: [{ ...provider().credentialMethods[0].credentialFields[0], [property]: 'not-declarative' }]
      }]
    }), { code: 'PROVIDER_DEFINITION_INVALID' });
  }
  await assert.rejects(service.create({
    ...provider(),
    credentialMethods: [{
      ...provider().credentialMethods[0],
      credentialFields: [{ ...provider().credentialMethods[0].credentialFields[0], section: 'providerConfiguration' }]
    }]
  }), { code: 'PROVIDER_DEFINITION_INVALID' });
  await assert.rejects(service.create({ ...provider(), providerMethodBindings: [] }), { code: 'PROVIDER_DEFINITION_INVALID' });
  await assert.rejects(service.create({ ...provider(), credentialMethods: [{ ...provider().credentialMethods[0], credentialFields: [{ ...provider().credentialMethods[0].credentialFields[0], defaultValue: 'not-a-secret' }] }] }), { code: 'PROVIDER_DEFINITION_INVALID' });
  await assert.rejects(service.create({
    ...provider(),
    credentialFields: [{ ...provider().credentialFields[0], section: 'providerConfiguration' }]
  }), { code: 'PROVIDER_DEFINITION_INVALID' });
});

test('CustomProviderDefinitionStore persists data-only definitions and rejects duplicate keys', async () => {
  const files = new Map();
  const jsonStore = {
    async exists(filePath) { return files.has(filePath); },
    async load(filePath) { return structuredClone(files.get(filePath)); },
    async save(filePath, value) { files.set(filePath, structuredClone(value)); }
  };
  const store = new CustomProviderDefinitionStore({ jsonStore, basePath: '/test-storage' });
  const definition = provider();

  await store.save(definition);
  definition.displayName = 'Mutated after save';
  assert.deepEqual(await store.list(), [provider()]);
  await assert.rejects(store.save(provider()), { code: 'PROVIDER_ALREADY_EXISTS' });
  assert.equal(await store.delete('acme-service'), true);
  assert.deepEqual(await store.list(), []);
  assert.equal(await store.delete('acme-service'), false);
});
