import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialMethod } from '../../src/models/credential-method.js';
import { ProviderMethodBinding } from '../../src/models/provider-method-binding.js';

const apiKeyField = { key: 'apiKey', label: 'API key', type: 'api-key', required: true, secret: true };

test('CredentialMethod owns reusable field schema, secret classification and declared operations', () => {
  const method = new CredentialMethod({
    key: 'api-key', displayName: 'API Key', credentialFields: [apiKeyField],
    operationCapabilities: ['validation', 'health-check']
  });

  assert.equal(method.supportsOperation('validation'), true);
  assert.equal(method.supportsOperation('refresh'), false);
  assert.deepEqual(method.toJSON().credentialFields.map((field) => field.key), ['apiKey']);
  assert.equal(Object.isFrozen(method), true);
});

test('CredentialMethod rejects invalid schema and non-operation capabilities', () => {
  assert.throws(() => new CredentialMethod({ credentialFields: [] }), /key.*required/);
  assert.throws(() => new CredentialMethod({ key: 'api-key', credentialFields: [apiKeyField, apiKeyField] }), /duplicate keys/);
  assert.throws(() => new CredentialMethod({ key: 'api-key', operationCapabilities: ['backup'] }), /unsupported operation/);
});

test('ProviderMethodBinding is provider-local and only adapts declared method operations', () => {
  const method = new CredentialMethod({ key: 'webhook', credentialFields: [{ key: 'signingSecret', label: 'Signing secret', type: 'password', secret: true }], operationCapabilities: [] });
  const binding = new ProviderMethodBinding({ methodKey: 'webhook', metadata: { setupUrl: 'https://example.test/hooks' } });
  binding.validateAgainst(method);
  assert.deepEqual(binding.toJSON().operationCapabilities, []);
  assert.throws(
    () => new ProviderMethodBinding({ methodKey: 'webhook', operationAdapters: { backup() {} } }),
    /unsupported adapter operation/
  );
  const invalidBinding = new ProviderMethodBinding({ methodKey: 'webhook', operationAdapters: { validation() {} } });
  assert.throws(() => invalidBinding.validateAgainst(method), /not declared/);
});
