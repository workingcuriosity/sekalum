import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { FacebookServiceProvider } from '../../src/providers/facebook/facebook-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

// Verifies provider contract metadata, capabilities, OAuth security requirements, and Meta family metadata.
test('FacebookServiceProvider registers Facebook provider metadata, capabilities and security requirements', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new FacebookServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('facebook');

  assert.equal(definition.name, 'facebook');
  assert.equal(definition.displayName, 'Facebook OAuth2');
  assert.equal(definition.description, 'Facebook OAuth2 provider for Facebook Graph API credentials');
  assert.deepEqual(definition.capabilities.toArray(), [
    'oauth',
    'refresh',
    'health-check'
  ]);
  assert.deepEqual(definition.oauthSecurityRequirements.toJSON(), {
    state: 'required',
    pkce: 'disabled',
    nonce: 'disabled'
  });
  assert.deepEqual(definition.metadata, {
    authType: 'oauth2',
    defaultScopes: ['public_profile', 'email'],
    api: 'facebook-graph-api',
    platformFamily: 'meta',
    credentialType: 'user-token'
  });
});
