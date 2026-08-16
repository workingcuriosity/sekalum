import test from 'node:test';
import assert from 'node:assert/strict';

import { KickOAuthService } from '../../src/oauth/kick/kick-oauth-service.js';
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
        scope: 'user:read channel:read',
        token_type: 'bearer'
      };
    },
    async refreshAccessToken() {
      return {
        access_token: 'new-access-token',
        expires_in: 3600,
        scope: 'user:read channel:read',
        token_type: 'bearer'
      };
    },
    async getCurrentUser() {
      return {
        user_id: 123,
        username: 'kickstreamer',
        name: 'Kick Streamer',
        email: 'kick@example.test',
        profile_picture: 'https://example.test/kick.png'
      };
    },
    async introspectToken() {
      return {
        data: {
          active: true,
          client_id: 'kick-client-id',
          token_type: 'user',
          scope: 'user:read channel:read'
        }
      };
    },
    ...apiClientOverrides
  };

  return new KickOAuthService({
    apiClient,
    config: createConfig({
      KICK_CLIENT_ID: 'kick-client-id',
      KICK_CLIENT_SECRET: 'kick-client-secret',
      KICK_REDIRECT_URI: 'https://credential.example.test/oauth/kick/callback'
    })
  });
}

test('KickOAuthService creates authorization URL with required PKCE parameters', () => {
  const service = createService();
  const url = service.getAuthorizationUrl({
    state: 'state-1',
    codeChallenge: 'challenge-1',
    codeChallengeMethod: 'S256'
  });

  const parsed = new URL(url);

  assert.equal(parsed.origin, 'https://id.kick.com');
  assert.equal(parsed.pathname, '/oauth/authorize');
  assert.equal(parsed.searchParams.get('client_id'), 'kick-client-id');
  assert.equal(parsed.searchParams.get('redirect_uri'), 'https://credential.example.test/oauth/kick/callback');
  assert.equal(parsed.searchParams.get('response_type'), 'code');
  assert.equal(parsed.searchParams.get('scope'), 'user:read channel:read');
  assert.equal(parsed.searchParams.get('code_challenge'), 'challenge-1');
  assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(parsed.searchParams.get('state'), 'state-1');
});

test('KickOAuthService rejects authorization URL creation without PKCE challenge', () => {
  const service = createService();

  assert.throws(
    () => service.getAuthorizationUrl({ state: 'state-1' }),
    /PKCE code_challenge/
  );
});

test('KickOAuthService authenticates code and returns OAuthResult', async () => {
  const calls = [];
  const service = createService({
    async exchangeCodeForToken(payload) {
      calls.push(payload);
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        scope: 'user:read channel:read',
        token_type: 'bearer'
      };
    }
  });

  const result = await service.authenticate({
    code: 'auth-code',
    codeVerifier: 'verifier-1'
  });

  assert.ok(result instanceof OAuthResult);
  assert.equal(result.provider, 'kick');
  assert.equal(result.providerId, 'kick:123');
  assert.equal(result.accountName, 'kickstreamer');
  assert.equal(result.accessToken, 'access-token');
  assert.equal(result.refreshToken, 'refresh-token');
  assert.deepEqual(result.scopes, ['user:read', 'channel:read']);
  assert.deepEqual(calls, [{
    code: 'auth-code',
    redirectUri: 'https://credential.example.test/oauth/kick/callback',
    codeVerifier: 'verifier-1'
  }]);
});

test('KickOAuthService rejects callback without PKCE verifier', async () => {
  const service = createService();

  await assert.rejects(
    () => service.authenticate({ code: 'auth-code' }),
    /PKCE code_verifier/
  );
});

test('KickOAuthService refresh keeps existing refresh token when Kick does not return a new one', async () => {
  const service = createService();

  const result = await service.refresh({ refreshToken: 'existing-refresh-token' });

  assert.equal(result.accessToken, 'new-access-token');
  assert.equal(result.refreshToken, 'existing-refresh-token');
});

test('KickOAuthService healthCheck reports inactive and failed provider calls without throwing', async () => {
  const inactive = await createService({
    async introspectToken() {
      return { data: { active: false } };
    }
  }).healthCheck({ accessToken: 'access-token' });

  assert.equal(inactive.healthy, false);
  assert.equal(inactive.status, 'failed');

  const failed = await createService({
    async introspectToken() {
      throw new Error('Kick API unavailable');
    }
  }).healthCheck({ accessToken: 'access-token' });

  assert.equal(failed.healthy, false);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.message, 'Kick API unavailable');
});
