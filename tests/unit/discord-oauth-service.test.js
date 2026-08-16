import test from 'node:test';
import assert from 'node:assert/strict';

import { DiscordOAuthService } from '../../src/oauth/discord/discord-oauth-service.js';
import { OAuthResult } from '../../src/models/oauth-result.js';

function createConfig(env = {}) {
  return {
    require(key) {
      if (!env[key]) {
        throw new Error(`Missing required config value: ${key}`);
      }
      return env[key];
    }
  };
}

function createService(apiClientOverrides = {}) {
  const apiClient = {
    async exchangeCodeForToken() {
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        scope: 'identify email guilds',
        token_type: 'Bearer'
      };
    },
    async refreshAccessToken() {
      return {
        access_token: 'new-access-token',
        expires_in: 3600,
        scope: 'identify email guilds',
        token_type: 'Bearer'
      };
    },
    async getCurrentUser() {
      return {
        id: 'discord-user-1',
        username: 'communityuser',
        global_name: 'Community User',
        discriminator: '0',
        email: 'community@example.test',
        avatar: 'avatar-hash',
        locale: 'de',
        verified: true,
        mfa_enabled: false
      };
    },
    ...apiClientOverrides
  };

  const service = new DiscordOAuthService({
    apiClient,
    config: createConfig({
      DISCORD_CLIENT_ID: 'discord-client-id',
      DISCORD_CLIENT_SECRET: 'discord-client-secret',
      DISCORD_REDIRECT_URI: 'https://credential.example.test/oauth/discord/callback'
    })
  });

  return { service, apiClient };
}

test('DiscordOAuthService creates authorization URL for Discord OAuth2 flow', () => {
  const { service } = createService();

  const authorizationUrl = service.getAuthorizationUrl({ state: 'state-123' });
  const url = new URL(authorizationUrl);

  assert.equal(url.origin + url.pathname, 'https://discord.com/oauth2/authorize');
  assert.equal(url.searchParams.get('client_id'), 'discord-client-id');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://credential.example.test/oauth/discord/callback');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('scope'), 'identify email guilds');
  assert.equal(url.searchParams.get('state'), 'state-123');
});

test('DiscordOAuthService authenticates code and returns OAuthResult', async () => {
  const calls = [];
  const { service } = createService({
    async exchangeCodeForToken(payload) {
      calls.push(['exchange', payload]);
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        scope: 'identify email guilds',
        token_type: 'Bearer'
      };
    },
    async getCurrentUser(payload) {
      calls.push(['user', payload]);
      return {
        id: 'discord-user-1',
        username: 'communityuser',
        global_name: 'Community User',
        discriminator: '0',
        email: 'community@example.test'
      };
    }
  });

  const result = await service.authenticate({ code: 'auth-code' });

  assert.ok(result instanceof OAuthResult);
  assert.equal(result.provider, 'discord');
  assert.equal(result.providerId, 'discord:discord-user-1');
  assert.equal(result.accountId, 'discord-user-1');
  assert.equal(result.accountName, 'Community User');
  assert.equal(result.accessToken, 'access-token');
  assert.equal(result.refreshToken, 'refresh-token');
  assert.deepEqual(result.scopes, ['identify', 'email', 'guilds']);
  assert.equal(result.metadata.username, 'communityuser');
  assert.deepEqual(calls, [
    ['exchange', {
      code: 'auth-code',
      redirectUri: 'https://credential.example.test/oauth/discord/callback'
    }],
    ['user', { accessToken: 'access-token' }]
  ]);
});

test('DiscordOAuthService refresh keeps existing refresh token when Discord does not return a new one', async () => {
  const { service } = createService();

  const result = await service.refresh({ refreshToken: 'existing-refresh-token' });

  assert.equal(result.accessToken, 'new-access-token');
  assert.equal(result.refreshToken, 'existing-refresh-token');
});

test('DiscordOAuthService healthCheck reports failed provider API calls without throwing', async () => {
  const { service } = createService({
    async getCurrentUser() {
      throw new Error('Discord user lookup failed');
    }
  });

  const result = await service.healthCheck({ accessToken: 'access-token' });

  assert.equal(result.healthy, false);
  assert.equal(result.status, 'failed');
  assert.equal(result.message, 'Discord user lookup failed');
});
