import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { GoogleServiceProvider } from '../../src/providers/google/google-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

test('GoogleServiceProvider registers Google provider metadata and capabilities', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new GoogleServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('google');

  assert.equal(definition.name, 'google');
  assert.equal(definition.displayName, 'Google OAuth2');
  assert.equal(definition.description, 'Google OAuth2 provider for Google account credentials');
  assert.deepEqual(definition.capabilities.toArray(), [
    'oauth',
    'refresh',
    'health-check'
  ]);
  assert.deepEqual(definition.metadata, {
    authType: 'oauth2',
    defaultScopes: ['openid', 'email', 'profile']
  });
});
