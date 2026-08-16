import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { KickServiceProvider } from '../../src/providers/kick/kick-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

// Verifies provider contract metadata, capabilities, and PKCE security requirements.
test('KickServiceProvider registers Kick provider metadata, capabilities and PKCE requirements', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new KickServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('kick');

  assert.equal(definition.name, 'kick');
  assert.equal(definition.displayName, 'Kick OAuth2.1');
  assert.equal(definition.description, 'Kick OAuth 2.1 provider with PKCE for Kick Public API credentials');
  assert.deepEqual(definition.capabilities.toArray(), [
    'oauth',
    'refresh',
    'health-check'
  ]);
  assert.deepEqual(definition.oauthSecurityRequirements.toJSON(), {
    state: 'required',
    pkce: 'required',
    nonce: 'disabled'
  });
  assert.deepEqual(definition.metadata, {
    authType: 'oauth2.1',
    defaultScopes: ['user:read', 'channel:read'],
    api: 'kick-public-api',
    pkce: 'required'
  });
});
