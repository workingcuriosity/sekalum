import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { DiscordServiceProvider } from '../../src/providers/discord/discord-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

// Verifies provider contract metadata, capabilities, and OAuth security requirements.
test('DiscordServiceProvider registers Discord provider metadata, capabilities and security requirements', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new DiscordServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('discord');

  assert.equal(definition.name, 'discord');
  assert.equal(definition.displayName, 'Discord OAuth2');
  assert.equal(definition.description, 'Discord OAuth2 user provider for Discord API credentials');
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
    defaultScopes: ['identify', 'email', 'guilds'],
    api: 'discord-api',
    credentialType: 'user-token'
  });
});
