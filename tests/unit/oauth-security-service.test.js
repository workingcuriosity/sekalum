import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { OAuthSecurityService } from '../../src/oauth/oauth-security-service.js';
import { OAuthSecurityRequirements } from '../../src/models/oauth-security-requirements.js';
import { ProviderProfile } from '../../src/models/provider-definition.js';

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

test('OAuthSecurityService rejects callback after provider profile drift', () => {
  const service = new OAuthSecurityService({ ttlMs: 1000 });
  const original = new ProviderProfile({ providerKey: 'google', version: '1.0.0', contract: { endpoint: 'v1' } });
  const changed = new ProviderProfile({ providerKey: 'google', version: '2.0.0', contract: { endpoint: 'v2' } });
  const created = service.createAuthorizationContext({ provider: 'google', providerProfile: original });

  assert.throws(
    () => service.consumeCallbackContext({ provider: 'google', state: created.state, providerProfile: changed }),
    (error) => error.code === 'OAUTH_STATE_INVALID' && /profile mismatch/.test(error.message)
  );
});

test('OAuthSecurityService binds callbacks to the initiating actor before one-shot consumption', () => {
  const service = new OAuthSecurityService({ ttlMs: 1000 });
  const created = service.createAuthorizationContext({ provider: 'google', actorUserId: 'actor-a' });

  assert.throws(
    () => service.consumeCallbackContext({
      provider: 'google',
      state: created.state,
      expectedActorUserId: 'actor-b'
    }),
    /actor mismatch/
  );
  assert.equal(service.contexts.has(created.state), true);

  const consumed = service.consumeCallbackContext({
    provider: 'google',
    state: created.state,
    expectedActorUserId: 'actor-a'
  });
  assert.equal(consumed.state, created.state);
});

test('OAuthSecurityService purges only expired contexts without extending their lifetime', () => {
  const service = new OAuthSecurityService({ ttlMs: 1000 });
  const live = service.createAuthorizationContext({ provider: 'google', now: 1500 });
  const expired = service.createAuthorizationContext({ provider: 'google', now: 1000 });

  const purged = service.purgeExpiredContexts(2001);
  assert.equal(purged.length, 1);
  assert.equal(purged[0].expiresAt.getTime(), 2000);
  assert.equal(service.contexts.has(live.state), true);
  assert.equal(service.contexts.has(expired.state), false);
});

test('OAuthSecurityService evicts expired state on its scheduled cleanup without another OAuth request', () => {
  let now = 1_000;
  let cleanup = null;
  const service = new OAuthSecurityService({
    ttlMs: 10,
    now: () => now,
    schedule(task) { cleanup = task; return null; }
  });
  const created = service.createAuthorizationContext({ provider: 'google' });
  now = 1_011;
  cleanup();
  assert.equal(service.contexts.has(created.state), false);
});

test('OAuthSecurityService bounds state globally and per initiating actor', () => {
  const service = new OAuthSecurityService({
    maxContexts: 2,
    maxContextsPerActor: 1,
    schedule() { return null; }
  });
  service.createAuthorizationContext({ provider: 'google', actorUserId: 'actor-a' });
  assert.throws(
    () => service.createAuthorizationContext({ provider: 'google', actorUserId: 'actor-a' }),
    /actor capacity exceeded/
  );
  service.createAuthorizationContext({ provider: 'google', actorUserId: 'actor-b' });
  assert.throws(
    () => service.createAuthorizationContext({ provider: 'google', actorUserId: 'actor-c' }),
    /capacity exceeded/
  );
});

test('OAuthSecurityService retains no provider-configuration secrets in its state map', () => {
  const service = new OAuthSecurityService({ schedule() { return null; } });
  const context = service.createAuthorizationContext({
    provider: 'google',
    providerConfiguration: { clientId: 'client-id', clientSecret: 'test-client-secret' }
  });
  assert.equal(JSON.stringify(context).includes('test-client-secret'), false);
  assert.equal(JSON.stringify([...service.contexts.values()]).includes('test-client-secret'), false);
});
