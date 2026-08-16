import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { InstagramServiceProvider } from '../../src/providers/instagram/instagram-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

test('InstagramServiceProvider registers Instagram provider metadata, capabilities and security requirements', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new InstagramServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('instagram');

  assert.equal(definition.name, 'instagram');
  assert.equal(definition.displayName, 'Instagram OAuth2');
  assert.equal(definition.description, 'Instagram OAuth2 provider for Instagram API credentials');
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
    defaultScopes: ['instagram_business_basic'],
    api: 'instagram-api',
    platformFamily: 'meta',
    credentialType: 'user-token'
  });
});
