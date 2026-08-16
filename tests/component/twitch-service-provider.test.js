import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { TwitchServiceProvider } from '../../src/providers/twitch/twitch-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

test('TwitchServiceProvider registers Twitch provider metadata and capabilities', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new TwitchServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('twitch');

  assert.equal(definition.name, 'twitch');
  assert.equal(definition.displayName, 'Twitch OAuth2');
  assert.equal(definition.description, 'Twitch OAuth2 provider for Helix API credentials');
  assert.deepEqual(definition.capabilities.toArray(), [
    'oauth',
    'refresh',
    'health-check'
  ]);
  assert.deepEqual(definition.metadata, {
    authType: 'oauth2',
    defaultScopes: ['user:read:email'],
    api: 'helix'
  });

  const runtimePublicFields = definition.credentialFields
    .filter((field) => field.runtimePublic)
    .map((field) => field.key);
  assert.deepEqual(runtimePublicFields, ['clientId']);
  assert.equal(definition.credentialFields.find((field) => field.key === 'clientId').secret, false);
  assert.equal(definition.credentialFields.find((field) => field.key === 'clientSecret').secret, true);
  assert.deepEqual(
    definition.getCredentialMethod('oauth2').credentialFields
      .filter((field) => field.runtimePublic)
      .map((field) => field.key),
    ['clientId']
  );
});
