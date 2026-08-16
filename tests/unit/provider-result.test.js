import test from 'node:test';
import assert from 'node:assert/strict';

import { ProviderResult } from '../../src/models/provider-result.js';

test('ProviderResult.success creates immutable success result', () => {
  const data = { authorizationUrl: 'https://example.test/oauth' };
  const result = ProviderResult.success(data);

  assert.equal(result.success, true);
  assert.equal(result.data, data);
  assert.equal(result.error, null);
  assert.equal(Object.isFrozen(result), true);
});

test('ProviderResult.failure normalizes Error instances', () => {
  const result = ProviderResult.failure(new Error('Something failed'));

  assert.equal(result.success, false);
  assert.equal(result.data, null);
  assert.equal(result.error.name, 'Error');
  assert.equal(result.error.message, 'Something failed');
});

test('ProviderResult.failure normalizes plain object errors', () => {
  const result = ProviderResult.failure({ code: 'E_PROVIDER', message: 'Provider failed' });

  assert.equal(result.success, false);
  assert.equal(result.error.name, 'ProviderError');
  assert.equal(result.error.code, 'E_PROVIDER');
  assert.equal(result.error.message, 'Provider failed');
});

test('ProviderResult.failure normalizes primitive errors', () => {
  const result = ProviderResult.failure('plain failure');

  assert.equal(result.success, false);
  assert.deepEqual(result.error, {
    name: 'ProviderError',
    message: 'plain failure'
  });
});
