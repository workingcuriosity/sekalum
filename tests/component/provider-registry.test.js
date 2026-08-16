import test from 'node:test';
import assert from 'node:assert/strict';

import { ProviderRegistry } from '../../src/registry/provider-registry.js';
import { ProviderDefinition } from '../../src/models/provider-definition.js';
import { ProviderCapabilities } from '../../src/models/provider-capabilities.js';
import { ProviderCapability } from '../../src/models/provider-capability.js';
import { ProviderRegistrationError } from '../../src/errors/provider-registration-error.js';

function createLogger() {
  return {
    messages: [],
    info(message) {
      this.messages.push(message);
    }
  };
}

function createDefinition(overrides = {}) {
  return new ProviderDefinition({
    name: 'threads',
    provider: {},
    apiClient: {},
    capabilities: new ProviderCapabilities([]),
    ...overrides
  });
}

test('ProviderRegistry registers and resolves provider definitions', () => {
  const logger = createLogger();
  const registry = new ProviderRegistry({ logger });
  const definition = createDefinition();

  registry.register(definition);

  assert.equal(registry.has('threads'), true);
  assert.equal(registry.get('threads'), definition);
  assert.deepEqual(registry.list(), ['threads']);
  assert.equal(registry.count(), 1);
});

test('ProviderRegistry rejects duplicate providers', () => {
  const registry = new ProviderRegistry({ logger: createLogger() });
  const definition = createDefinition();

  registry.register(definition);

  assert.throws(() => registry.register(definition), /Provider already registered/);
});

test('ProviderRegistry requires apiClient', () => {
  const registry = new ProviderRegistry({ logger: createLogger() });
  const definition = createDefinition({ apiClient: null });

  assert.throws(
    () => registry.register(definition),
    ProviderRegistrationError
  );
});

test('ProviderRegistry requires oauthService for OAuth capability', () => {
  const registry = new ProviderRegistry({ logger: createLogger() });
  const definition = createDefinition({
    oauthService: null,
    capabilities: new ProviderCapabilities([ProviderCapability.OAUTH])
  });

  assert.throws(
    () => registry.register(definition),
    ProviderRegistrationError
  );
});


test('ProviderDefinition accepts optional public metadata', () => {
  const definition = createDefinition({
    displayName: 'Threads',
    description: 'Meta Threads OAuth provider',
    metadata: {
      documentationUrl: 'https://example.test/docs'
    }
  });

  assert.equal(definition.displayName, 'Threads');
  assert.equal(definition.description, 'Meta Threads OAuth provider');
  assert.deepEqual(definition.metadata, {
    documentationUrl: 'https://example.test/docs'
  });
});

test('ProviderDefinition exposes credential fields without changing public metadata', () => {
  const definition = createDefinition({
    metadata: { authType: 'api-key' },
    credentialFields: [{
      key: 'apiKey',
      label: 'API key',
      type: 'api-key',
      required: true,
      secret: true
    }]
  });

  assert.deepEqual(definition.metadata, { authType: 'api-key' });
  assert.deepEqual(definition.credentialFields.map((field) => field.toJSON()), [{
    key: 'apiKey',
    label: 'API key',
    type: 'api-key',
    required: true,
    secret: true,
    description: null,
    placeholder: null,
    defaultValue: null,
    validation: null,
    options: null,
    csvAliases: ['apiKey'],
    group: 'Credential-Daten',
    section: 'accountCredentials',
    inputType: 'api-key',
    displayOrder: 0,
    readonly: false,
    visible: true,
    userConfigurable: true,
    systemManaged: false
  }]);
});

test('ProviderDefinition rejects secret field defaults before public metadata can be created', () => {
  assert.throws(
    () => createDefinition({
      credentialFields: [{
        key: 'apiKey',
        label: 'API key',
        type: 'api-key',
        secret: true,
        defaultValue: 'must-not-be-exposed'
      }]
    }),
    /secret fields must not define defaultValue/
  );
});


test('ProviderRegistry rejects framework capabilities in provider definitions', () => {
  const registry = new ProviderRegistry({ logger: createLogger() });
  const definition = createDefinition({
    capabilities: new ProviderCapabilities([ProviderCapability.BACKUP])
  });

  assert.throws(
    () => registry.register(definition),
    /provider capabilities must only contain public provider operations: backup/
  );
});

test('ProviderDefinition exposes multiple declarative method bindings without provider-specific field fallback', () => {
  const definition = createDefinition({
    credentialMethods: [
      { key: 'oauth2', credentialFields: [{ key: 'accessToken', label: 'Access token', type: 'password', secret: true }], operationCapabilities: ['refresh'] },
      { key: 'webhook', credentialFields: [{ key: 'signingSecret', label: 'Signing secret', type: 'password', secret: true }], operationCapabilities: [] }
    ],
    providerMethodBindings: [{ methodKey: 'oauth2' }, { methodKey: 'webhook', metadata: { eventTypes: ['message.created'] } }]
  });

  assert.equal(definition.getCredentialMethod('oauth2').credentialFields[0].key, 'accessToken');
  assert.equal(definition.getProviderMethodBinding('webhook').metadata.eventTypes[0], 'message.created');
  assert.equal(definition.getCredentialMethod('missing'), null);
});

test('ProviderDefinition rejects duplicate and unbound credential method configurations', () => {
  assert.throws(() => createDefinition({
    credentialMethods: [{ key: 'api-key' }, { key: 'api-key' }]
  }), /credentialMethods contain duplicate keys/);
  assert.throws(() => createDefinition({
    credentialMethods: [{ key: 'api-key' }],
    providerMethodBindings: [{ methodKey: 'oauth2' }]
  }), /binding references unknown credential method/);
  assert.throws(() => createDefinition({
    credentialMethods: [{ key: 'api-key' }],
    providerMethodBindings: [{ methodKey: 'api-key' }, { methodKey: 'api-key' }]
  }), /providerMethodBindings contain duplicate method keys/);
});
