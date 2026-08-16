import test from 'node:test';
import assert from 'node:assert/strict';

import { FacebookOAuthService } from '../../src/oauth/facebook/facebook-oauth-service.js';
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
        scope: 'public_profile,email',
        token_type: 'bearer'
      };
    },
    async refreshAccessToken() {
      return {
        access_token: 'new-access-token',
        expires_in: 3600,
        scope: 'public_profile,email',
        token_type: 'bearer'
      };
    },
    async getCurrentUser() {
      return {
        id: 'facebook-user-1',
        name: 'Facebook User',
        email: 'facebook@example.test',
        picture: {
          data: {
            url: 'https://example.test/facebook.png'
          }
        }
      };
    },
    ...apiClientOverrides
  };

  return new FacebookOAuthService({
    apiClient,
    config: createConfig({
      FACEBOOK_CLIENT_ID: 'facebook-client-id',
      FACEBOOK_CLIENT_SECRET: 'facebook-client-secret',
      FACEBOOK_REDIRECT_URI: 'https://credential.example.test/oauth/facebook/callback'
    })
  });
}

test('FacebookOAuthService creates authorization URL for Facebook OAuth2 flow', () => {
  const service = createService();
  const url = service.getAuthorizationUrl({ state: 'state-1' });
  const parsed = new URL(url);

  assert.equal(parsed.origin, 'https://www.facebook.com');
  assert.equal(parsed.pathname, '/v20.0/dialog/oauth');
  assert.equal(parsed.searchParams.get('client_id'), 'facebook-client-id');
  assert.equal(parsed.searchParams.get('redirect_uri'), 'https://credential.example.test/oauth/facebook/callback');
  assert.equal(parsed.searchParams.get('response_type'), 'code');
  assert.equal(parsed.searchParams.get('scope'), 'public_profile,email');
  assert.equal(parsed.searchParams.get('state'), 'state-1');
});

test('FacebookOAuthService authenticates code and returns OAuthResult', async () => {
  const calls = [];
  const service = createService({
    async exchangeCodeForToken(payload) {
      calls.push(['exchange', payload]);
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        scope: 'public_profile,email',
        token_type: 'bearer'
      };
    },
    async getCurrentUser(payload) {
      calls.push(['user', payload]);
      return {
        id: 'facebook-user-1',
        name: 'Facebook User',
        email: 'facebook@example.test'
      };
    }
  });

  const result = await service.authenticate({ code: 'auth-code' });

  assert.ok(result instanceof OAuthResult);
  assert.equal(result.provider, 'facebook');
  assert.equal(result.providerId, 'facebook:facebook-user-1');
  assert.equal(result.accountId, 'facebook-user-1');
  assert.equal(result.accountName, 'Facebook User');
  assert.equal(result.accessToken, 'access-token');
  assert.equal(result.refreshToken, 'refresh-token');
  assert.deepEqual(result.scopes, ['public_profile', 'email']);
  assert.equal(result.metadata.email, 'facebook@example.test');
  assert.deepEqual(calls, [
    ['exchange', {
      code: 'auth-code',
      redirectUri: 'https://credential.example.test/oauth/facebook/callback'
    }],
    ['user', { accessToken: 'access-token' }]
  ]);
});

test('FacebookOAuthService refresh keeps existing refresh token when Facebook does not return a new one', async () => {
  const service = createService();

  const result = await service.refresh({ refreshToken: 'existing-refresh-token' });

  assert.equal(result.accessToken, 'new-access-token');
  assert.equal(result.refreshToken, 'existing-refresh-token');
});

test('FacebookOAuthService healthCheck reports failed provider API calls without throwing', async () => {
  const service = createService({
    async getCurrentUser() {
      throw new Error('Facebook user lookup failed');
    }
  });

  const result = await service.healthCheck({ accessToken: 'access-token' });

  assert.equal(result.healthy, false);
  assert.equal(result.status, 'failed');
  assert.equal(result.message, 'Facebook user lookup failed');
});
