import test from 'node:test';
import assert from 'node:assert/strict';

import { oauthConfigurationValue } from '../../src/oauth/oauth-provider-configuration.js';

test('Wizard provider configuration takes precedence over environment compatibility values', () => {
  const config = { get() { return 'environment-client'; } };
  const value = oauthConfigurationValue({
    providerConfiguration: { clientId: 'wizard-client' },
    field: 'clientId',
    config,
    environmentKey: 'X_CLIENT_ID'
  });

  assert.equal(value, 'wizard-client');
});

test('environment configuration remains an explicit compatibility fallback', () => {
  const config = { get(key) { return key === 'X_CLIENT_ID' ? 'environment-client' : null; } };
  const value = oauthConfigurationValue({
    field: 'clientId',
    config,
    environmentKey: 'X_CLIENT_ID'
  });

  assert.equal(value, 'environment-client');
});
