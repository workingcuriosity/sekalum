import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { XServiceProvider } from '../../src/providers/x/x-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

// Verifies provider contract metadata, capabilities, and PKCE security requirements.
test('XServiceProvider registers X provider metadata, capabilities and PKCE requirements', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new XServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('x');

  assert.equal(definition.name, 'x');
  assert.equal(definition.displayName, 'X OAuth2');
  assert.equal(definition.description, 'X OAuth2 user provider with PKCE for X API credentials');
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
    authType: 'oauth2',
    defaultScopes: ['users.read', 'offline.access'],
    api: 'x-api-v2',
    pkce: 'required',
    credentialType: 'user-token'
  });
});
