import test from 'node:test';
import assert from 'node:assert/strict';

import { TwitchOAuthService } from '../../src/oauth/twitch/twitch-oauth-service.js';
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
        scope: ['user:read:email'],
        token_type: 'bearer'
      };
    },
    async refreshAccessToken() {
      return {
        access_token: 'new-access-token',
        expires_in: 3600,
        scope: ['user:read:email'],
        token_type: 'bearer'
      };
    },
    async getCurrentUser() {
      return {
        id: 'twitch-user-1',
        login: 'streamerlogin',
        display_name: 'StreamerDisplay',
        email: 'streamer@example.test',
        profile_image_url: 'https://example.test/twitch.png',
        broadcaster_type: 'affiliate'
      };
    },
    async validateAccessToken() {
      return {
        user_id: 'twitch-user-1',
        login: 'streamerlogin',
        scopes: ['user:read:email']
      };
    },
    ...apiClientOverrides
  };

  const service = new TwitchOAuthService({
    apiClient,
    config: createConfig({
      TWITCH_CLIENT_ID: 'twitch-client-id',
      TWITCH_CLIENT_SECRET: 'twitch-client-secret',
      TWITCH_REDIRECT_URI: 'https://credential.example.test/oauth/twitch/callback'
    })
  });

  return { service, apiClient };
}

test('TwitchOAuthService creates authorization URL for Twitch OAuth2 flow', () => {
  const { service } = createService();

  const authorizationUrl = service.getAuthorizationUrl({ state: 'state-123' });
  const url = new URL(authorizationUrl);

  assert.equal(url.origin + url.pathname, 'https://id.twitch.tv/oauth2/authorize');
  assert.equal(url.searchParams.get('client_id'), 'twitch-client-id');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://credential.example.test/oauth/twitch/callback');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('scope'), 'user:read:email');
  assert.equal(url.searchParams.get('state'), 'state-123');
});

test('TwitchOAuthService authenticates code and returns OAuthResult', async () => {
  const calls = [];
  const { service } = createService({
    async exchangeCodeForToken(payload) {
      calls.push(['exchange', payload]);
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        scope: ['user:read:email'],
        token_type: 'bearer'
      };
    },
    async getCurrentUser(payload) {
      calls.push(['user', payload]);
      return {
        id: 'twitch-user-1',
        login: 'streamerlogin',
        display_name: 'StreamerDisplay',
        email: 'streamer@example.test'
      };
    }
  });

  const result = await service.authenticate({ code: 'auth-code' });

  assert.ok(result instanceof OAuthResult);
  assert.equal(result.provider, 'twitch');
  assert.equal(result.providerId, 'twitch:twitch-user-1');
  assert.equal(result.accountId, 'twitch-user-1');
  assert.equal(result.accountName, 'StreamerDisplay');
  assert.equal(result.accessToken, 'access-token');
  assert.equal(result.refreshToken, 'refresh-token');
  assert.deepEqual(result.scopes, ['user:read:email']);
  assert.equal(result.metadata.login, 'streamerlogin');
  assert.deepEqual(calls, [
    ['exchange', {
      code: 'auth-code',
      redirectUri: 'https://credential.example.test/oauth/twitch/callback'
    }],
    ['user', { accessToken: 'access-token' }]
  ]);
});

test('TwitchOAuthService refresh keeps existing refresh token when Twitch does not return a new one', async () => {
  const { service } = createService();

  const result = await service.refresh({ refreshToken: 'existing-refresh-token' });

  assert.equal(result.accessToken, 'new-access-token');
  assert.equal(result.refreshToken, 'existing-refresh-token');
});

test('TwitchOAuthService healthCheck reports failed provider API calls without throwing', async () => {
  const { service } = createService({
    async validateAccessToken() {
      throw new Error('Twitch token validation failed');
    }
  });

  const result = await service.healthCheck({ accessToken: 'access-token' });

  assert.equal(result.healthy, false);
  assert.equal(result.status, 'failed');
  assert.equal(result.message, 'Twitch token validation failed');
});
