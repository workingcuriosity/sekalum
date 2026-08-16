import test from 'node:test';
import assert from 'node:assert/strict';

import { ProviderCapabilities } from '../../src/models/provider-capabilities.js';
import { ProviderCapability } from '../../src/models/provider-capability.js';

test('ProviderCapabilities checks single capabilities', () => {
  const capabilities = new ProviderCapabilities([
    ProviderCapability.OAUTH,
    ProviderCapability.REFRESH
  ]);

  assert.equal(capabilities.has(ProviderCapability.OAUTH), true);
  assert.equal(capabilities.has(ProviderCapability.REFRESH), true);
  assert.equal(capabilities.has(ProviderCapability.HEALTH_CHECK), false);
});

test('ProviderCapabilities checks all required capabilities', () => {
  const capabilities = new ProviderCapabilities([
    ProviderCapability.OAUTH,
    ProviderCapability.REFRESH
  ]);

  assert.equal(capabilities.hasAll([
    ProviderCapability.OAUTH,
    ProviderCapability.REFRESH
  ]), true);

  assert.equal(capabilities.hasAll([
    ProviderCapability.OAUTH,
    ProviderCapability.HEALTH_CHECK
  ]), false);
});

test('ProviderCapabilities checks any supported capability', () => {
  const capabilities = new ProviderCapabilities([
    ProviderCapability.OAUTH
  ]);

  assert.equal(capabilities.hasAny([
    ProviderCapability.REFRESH,
    ProviderCapability.OAUTH
  ]), true);

  assert.equal(capabilities.hasAny([
    ProviderCapability.REFRESH,
    ProviderCapability.HEALTH_CHECK
  ]), false);
});

test('ProviderCapabilities exports capabilities as array', () => {
  const capabilities = new ProviderCapabilities([
    ProviderCapability.OAUTH,
    ProviderCapability.REFRESH
  ]);

  assert.deepEqual(capabilities.toArray(), [
    ProviderCapability.OAUTH,
    ProviderCapability.REFRESH
  ]);
});


test('ProviderCapabilities protects internal capability set from external mutation', () => {
  const capabilityInput = [ProviderCapability.OAUTH];
  const capabilities = new ProviderCapabilities(capabilityInput);

  capabilityInput.push(ProviderCapability.REFRESH);

  assert.deepEqual(capabilities.toArray(), [ProviderCapability.OAUTH]);
  assert.equal(Object.hasOwn(capabilities, 'capabilities'), false);
});

test('ProviderCapabilities returns defensive arrays', () => {
  const capabilities = new ProviderCapabilities([
    ProviderCapability.OAUTH
  ]);

  const exportedCapabilities = capabilities.toArray();
  exportedCapabilities.push(ProviderCapability.REFRESH);

  assert.deepEqual(capabilities.toArray(), [ProviderCapability.OAUTH]);
});
