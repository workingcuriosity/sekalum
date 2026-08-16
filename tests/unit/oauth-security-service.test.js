import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { OAuthSecurityService } from '../../src/oauth/oauth-security-service.js';
import { OAuthSecurityRequirements } from '../../src/models/oauth-security-requirements.js';

test('OAuthSecurityService creates generic state context without provider-specific logic', () => {
  const service = new OAuthSecurityService({ ttlMs: 1000 });
  const context = service.createAuthorizationContext({ provider: 'kick' });

  assert.equal(context.provider, 'kick');
  assert.ok(context.state);
  assert.equal(context.codeVerifier, null);
  assert.equal(context.codeChallenge, null);
});

test('OAuthSecurityService creates PKCE verifier and S256 challenge when required', () => {
  const service = new OAuthSecurityService({ ttlMs: 1000 });
  const context = service.createAuthorizationContext({
    provider: 'kick',
    requirements: new OAuthSecurityRequirements({ pkce: 'required' })
  });

  const expectedChallenge = crypto
    .createHash('sha256')
    .update(context.codeVerifier)
    .digest('base64url');

  assert.ok(context.state);
  assert.ok(context.codeVerifier.length >= 43);
  assert.equal(context.codeChallenge, expectedChallenge);
  assert.equal(context.codeChallengeMethod, 'S256');
});

test('OAuthSecurityService consumes callback context exactly once', () => {
  const service = new OAuthSecurityService({ ttlMs: 1000 });
  const created = service.createAuthorizationContext({ provider: 'twitch' });

  const consumed = service.consumeCallbackContext({
    provider: 'twitch',
    state: created.state
  });

  assert.equal(consumed.state, created.state);
  assert.throws(
    () => service.consumeCallbackContext({ provider: 'twitch', state: created.state }),
    /unknown or expired/
  );
});

test('OAuthSecurityService rejects provider mismatch and expired context', () => {
  const service = new OAuthSecurityService({ ttlMs: 1 });
  const created = service.createAuthorizationContext({ provider: 'google', now: 1000 });

  assert.throws(
    () => service.consumeCallbackContext({ provider: 'twitch', state: created.state, now: 1000 }),
    /provider mismatch/
  );

  const expired = service.createAuthorizationContext({ provider: 'google', now: 1000 });
  assert.throws(
    () => service.consumeCallbackContext({ provider: 'google', state: expired.state, now: 1002 }),
    /expired/
  );
});
