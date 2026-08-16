import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';
import {
  CustomProviderServiceProvider,
  parseCustomProviderDefinitions
} from '../../src/providers/custom/custom-provider-service-provider.js';

test('custom provider definitions are declarative, validated and registered without runtime operations', () => {
  const definitions = parseCustomProviderDefinitions([{
    name: 'example-api',
    displayName: 'Example API',
    description: 'Example declarative provider',
    authType: 'api-key',
    credentialFields: [
      { key: 'displayName', label: 'Display name', required: true },
      { key: 'apiKey', label: 'API key', type: 'api-key', required: true, secret: true, csvAliases: ['api_key'] }
    ]
  }]);

  const container = new Container();
  new ApplicationServiceProvider().register(container);
  const config = container.resolve(TOKENS.CONFIG);
  config.env = { ...config.env, CUSTOM_PROVIDER_DEFINITIONS: JSON.stringify(definitions.map((definition) => ({
    ...definition,
    credentialFields: definition.credentialFields.map((field) => field.toJSON())
  }))) };
  new CustomProviderServiceProvider().register(container);

  const provider = container.resolve(TOKENS.PROVIDER_REGISTRY).get('example-api');
  assert.deepEqual(provider.capabilities.toArray(), []);
  assert.deepEqual(provider.metadata.runtimeOperations, []);
  assert.equal(provider.metadata.customProvider, true);
  assert.deepEqual(provider.credentialFields.map((field) => field.key), ['displayName', 'apiKey']);
});

test('custom provider definitions reject executable or OAuth configuration', () => {
  assert.throws(
    () => parseCustomProviderDefinitions('[{"name":"unsafe-provider","displayName":"Unsafe","authType":"oauth2","credentialFields":[{"key":"apiKey","label":"API key"}]}]'),
    /unsupported authType/
  );
  assert.throws(
    () => parseCustomProviderDefinitions('[{"name":"unsafe-provider","displayName":"Unsafe","authType":"api-key","module":"foreign-code","credentialFields":[{"key":"apiKey","label":"API key"}]}]'),
    /unsupported property 'module'/
  );
  assert.throws(
    () => parseCustomProviderDefinitions('[{"name":"unsafe-provider","displayName":"Unsafe","authType":"api-key","credentialFields":[{"key":"apiKey","label":"API key","type":"api-key","secret":true,"defaultValue":"must-not-be-exposed"}]}]'),
    /secret fields must not define defaultValue/
  );
});
