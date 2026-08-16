import test from 'node:test';
import assert from 'node:assert/strict';

import { GoogleOAuthService } from '../../src/oauth/google/google-oauth-service.js';
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
        scope: 'openid email profile',
        token_type: 'Bearer'
      };
    },
    async refreshAccessToken() {
      return {
        access_token: 'new-access-token',
        expires_in: 3600,
        scope: 'openid email profile',
        token_type: 'Bearer'
      };
    },
    async getCurrentUser() {
      return {
        sub: 'google-user-1',
        email: 'user@example.test',
        email_verified: true,
        name: 'Google User',
        picture: 'https://example.test/avatar.png'
      };
    },
    ...apiClientOverrides
  };

  const service = new GoogleOAuthService({
    apiClient,
    config: createConfig({
      GOOGLE_CLIENT_ID: 'google-client-id',
      GOOGLE_CLIENT_SECRET: 'google-client-secret',
      GOOGLE_REDIRECT_URI: 'https://credential.example.test/oauth/google/callback'
    })
  });

  return { service, apiClient };
}

test('GoogleOAuthService creates authorization URL for offline OAuth2 flow', () => {
  const { service } = createService();

  const authorizationUrl = service.getAuthorizationUrl({ state: 'state-123' });
  const url = new URL(authorizationUrl);

  assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(url.searchParams.get('client_id'), 'google-client-id');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://credential.example.test/oauth/google/callback');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('scope'), 'openid email profile');
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('prompt'), 'consent');
  assert.equal(url.searchParams.get('state'), 'state-123');
});

test('GoogleOAuthService authenticates code and returns OAuthResult', async () => {
  const calls = [];
  const { service } = createService({
    async exchangeCodeForToken(payload) {
      calls.push(['exchange', payload]);
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        scope: 'openid email profile',
        token_type: 'Bearer'
      };
    },
    async getCurrentUser(payload) {
      calls.push(['user', payload]);
      return {
        sub: 'google-user-1',
        email: 'user@example.test',
        email_verified: true,
        name: 'Google User'
      };
    }
  });

  const result = await service.authenticate({ code: 'auth-code' });

  assert.ok(result instanceof OAuthResult);
  assert.equal(result.provider, 'google');
  assert.equal(result.providerId, 'google:google-user-1');
  assert.equal(result.accountId, 'google-user-1');
  assert.equal(result.accountName, 'user@example.test');
  assert.equal(result.accessToken, 'access-token');
  assert.equal(result.refreshToken, 'refresh-token');
  assert.deepEqual(result.scopes, ['openid', 'email', 'profile']);
  assert.equal(result.metadata.email, 'user@example.test');
  assert.deepEqual(calls, [
    ['exchange', {
      code: 'auth-code',
      redirectUri: 'https://credential.example.test/oauth/google/callback'
    }],
    ['user', { accessToken: 'access-token' }]
  ]);
});

test('GoogleOAuthService refresh keeps existing refresh token when Google does not return a new one', async () => {
  const { service } = createService();

  const result = await service.refresh({ refreshToken: 'existing-refresh-token' });

  assert.equal(result.accessToken, 'new-access-token');
  assert.equal(result.refreshToken, 'existing-refresh-token');
});

test('GoogleOAuthService healthCheck reports failed provider API calls without throwing', async () => {
  const { service } = createService({
    async getCurrentUser() {
      throw new Error('Google userinfo failed');
    }
  });

  const result = await service.healthCheck({ accessToken: 'access-token' });

  assert.equal(result.healthy, false);
  assert.equal(result.status, 'failed');
  assert.equal(result.message, 'Google userinfo failed');
});
