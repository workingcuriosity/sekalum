import test from 'node:test';
import assert from 'node:assert/strict';

import { XOAuthService } from '../../src/oauth/x/x-oauth-service.js';
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
        expires_in: 7200,
        scope: 'users.read offline.access',
        token_type: 'bearer'
      };
    },
    async refreshAccessToken() {
      return {
        access_token: 'new-access-token',
        expires_in: 7200,
        scope: 'users.read offline.access',
        token_type: 'bearer'
      };
    },
    async getCurrentUser() {
      return {
        id: '42',
        name: 'X User',
        username: 'xuser',
        verified: false,
        profile_image_url: 'https://example.test/x.png'
      };
    },
    ...apiClientOverrides
  };

  return new XOAuthService({
    apiClient,
    config: createConfig({
      X_CLIENT_ID: 'x-client-id',
      X_CLIENT_SECRET: 'x-client-secret',
      X_REDIRECT_URI: 'https://credential.example.test/oauth/x/callback'
    })
  });
}

test('XOAuthService creates authorization URL with required PKCE parameters', () => {
  const service = createService();
  const url = service.getAuthorizationUrl({
    state: 'state-1',
    codeChallenge: 'challenge-1',
    codeChallengeMethod: 'S256'
  });

  const parsed = new URL(url);

  assert.equal(parsed.origin, 'https://twitter.com');
  assert.equal(parsed.pathname, '/i/oauth2/authorize');
  assert.equal(parsed.searchParams.get('client_id'), 'x-client-id');
  assert.equal(parsed.searchParams.get('redirect_uri'), 'https://credential.example.test/oauth/x/callback');
  assert.equal(parsed.searchParams.get('response_type'), 'code');
  assert.equal(parsed.searchParams.get('scope'), 'users.read offline.access');
  assert.equal(parsed.searchParams.get('code_challenge'), 'challenge-1');
  assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(parsed.searchParams.get('state'), 'state-1');
});

test('XOAuthService rejects authorization URL creation without PKCE challenge', () => {
  const service = createService();

  assert.throws(
    () => service.getAuthorizationUrl({ state: 'state-1' }),
    /PKCE code_challenge/
  );
});

test('XOAuthService authenticates code and returns OAuthResult', async () => {
  const calls = [];
  const service = createService({
    async exchangeCodeForToken(payload) {
      calls.push(payload);
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 7200,
        scope: 'users.read offline.access',
        token_type: 'bearer'
      };
    }
  });

  const result = await service.authenticate({
    code: 'auth-code',
    codeVerifier: 'verifier-1'
  });

  assert.ok(result instanceof OAuthResult);
  assert.equal(result.provider, 'x');
  assert.equal(result.providerId, 'x:42');
  assert.equal(result.accountName, 'xuser');
  assert.equal(result.accessToken, 'access-token');
  assert.equal(result.refreshToken, 'refresh-token');
  assert.deepEqual(result.scopes, ['users.read', 'offline.access']);
  assert.deepEqual(calls, [{
    code: 'auth-code',
    redirectUri: 'https://credential.example.test/oauth/x/callback',
    codeVerifier: 'verifier-1'
  }]);
});

test('XOAuthService rejects callback without PKCE verifier', async () => {
  const service = createService();

  await assert.rejects(
    () => service.authenticate({ code: 'auth-code' }),
    /PKCE code_verifier/
  );
});

test('XOAuthService refresh keeps existing refresh token when X does not return a new one', async () => {
  const service = createService();

  const result = await service.refresh({ refreshToken: 'existing-refresh-token' });

  assert.equal(result.accessToken, 'new-access-token');
  assert.equal(result.refreshToken, 'existing-refresh-token');
});

test('XOAuthService healthCheck reports failed provider calls without throwing', async () => {
  const failed = await createService({
    async getCurrentUser() {
      throw new Error('X API unavailable');
    }
  }).healthCheck({ accessToken: 'access-token' });

  assert.equal(failed.healthy, false);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.message, 'X API unavailable');
});
