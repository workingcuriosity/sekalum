import test from 'node:test';
import assert from 'node:assert/strict';

import { InstagramOAuthService } from '../../src/oauth/instagram/instagram-oauth-service.js';
import { OAuthResult } from '../../src/models/oauth-result.js';

function createConfig(env = {}) {
  return {
    get(key, fallback = null) {
      return env[key] ?? fallback;
    },
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
        scope: 'instagram_business_basic',
        token_type: 'bearer',
        user_id: 'instagram-user-1'
      };
    },
    async refreshAccessToken() {
      return {
        access_token: 'new-access-token',
        expires_in: 3600,
        scope: 'instagram_business_basic',
        token_type: 'bearer'
      };
    },
    async getCurrentUser() {
      return {
        id: 'instagram-user-1',
        username: 'instagram_user',
        account_type: 'BUSINESS'
      };
    },
    ...apiClientOverrides
  };

  return new InstagramOAuthService({
    apiClient,
    config: createConfig({
      INSTAGRAM_CLIENT_ID: 'instagram-client-id',
      INSTAGRAM_CLIENT_SECRET: 'instagram-client-secret',
      INSTAGRAM_REDIRECT_URI: 'https://credential.example.test/oauth/instagram/callback'
    })
  });
}

test('InstagramOAuthService creates authorization URL for Instagram OAuth2 flow', () => {
  const service = createService();
  const url = service.getAuthorizationUrl({ state: 'state-1' });
  const parsed = new URL(url);

  assert.equal(parsed.origin, 'https://www.instagram.com');
  assert.equal(parsed.pathname, '/oauth/authorize');
  assert.equal(parsed.searchParams.get('client_id'), 'instagram-client-id');
  assert.equal(parsed.searchParams.get('redirect_uri'), 'https://credential.example.test/oauth/instagram/callback');
  assert.equal(parsed.searchParams.get('response_type'), 'code');
  assert.equal(parsed.searchParams.get('scope'), 'instagram_business_basic');
  assert.equal(parsed.searchParams.get('state'), 'state-1');
});

test('InstagramOAuthService authenticates code and returns OAuthResult', async () => {
  const calls = [];
  const service = createService({
    async exchangeCodeForToken(payload) {
      calls.push(['exchange', payload]);
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        scope: 'instagram_business_basic',
        token_type: 'bearer',
        user_id: 'instagram-user-1'
      };
    },
    async getCurrentUser(payload) {
      calls.push(['user', payload]);
      return {
        id: 'instagram-user-1',
        username: 'instagram_user',
        account_type: 'BUSINESS'
      };
    }
  });

  const result = await service.authenticate({ code: 'auth-code' });

  assert.ok(result instanceof OAuthResult);
  assert.equal(result.provider, 'instagram');
  assert.equal(result.providerId, 'instagram:instagram-user-1');
  assert.equal(result.accountId, 'instagram-user-1');
  assert.equal(result.accountName, 'instagram_user');
  assert.equal(result.accessToken, 'access-token');
  assert.equal(result.refreshToken, 'refresh-token');
  assert.deepEqual(result.scopes, ['instagram_business_basic']);
  assert.equal(result.metadata.accountType, 'BUSINESS');
  assert.deepEqual(calls, [
    ['exchange', {
      code: 'auth-code',
      redirectUri: 'https://credential.example.test/oauth/instagram/callback'
    }],
    ['user', { accessToken: 'access-token' }]
  ]);
});

test('InstagramOAuthService refresh keeps existing refresh token when Instagram does not return a new one', async () => {
  const service = createService();

  const result = await service.refresh({ refreshToken: 'existing-refresh-token' });

  assert.equal(result.accessToken, 'new-access-token');
  assert.equal(result.refreshToken, 'existing-refresh-token');
});

test('InstagramOAuthService healthCheck reports failed provider API calls without throwing', async () => {
  const service = createService({
    async getCurrentUser() {
      throw new Error('Instagram user lookup failed');
    }
  });

  const result = await service.healthCheck({ accessToken: 'access-token' });

  assert.equal(result.healthy, false);
  assert.equal(result.status, 'failed');
  assert.equal(result.message, 'Instagram user lookup failed');
});
