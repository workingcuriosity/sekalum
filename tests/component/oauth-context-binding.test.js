import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { LifecycleState } from '../../src/models/lifecycle-state.js';
import { OAuthResult } from '../../src/models/oauth-result.js';
import { OAuthSecurityService } from '../../src/oauth/oauth-security-service.js';
import { OAuthClientBindingIdentity, OAuthCredentialBinding, OAUTH_PROVIDER_EVIDENCE_POLICIES, compareOAuthContextEvidence } from '../../src/models/oauth-context-binding.js';
import { CredentialManager } from '../../src/managers/credential-manager.js';
import { ProviderResult } from '../../src/models/provider-result.js';

const profile = { providerKey: 'google', version: '1.0.0', digest: 'profile-digest' };

function clientBinding(overrides = {}) {
  return OAuthClientBindingIdentity.from({
    providerKey: 'google', providerProfile: profile, credentialMethodKey: 'oauth2',
    providerConfigurationId: 'config-1', clientId: 'client-1',
    redirectUri: 'https://sekalum.example/oauth/google/callback',
    publicOrigin: 'https://sekalum.example', ...overrides
  });
}

function credentialBinding(overrides = {}) {
  return new OAuthCredentialBinding({
    providerKey: 'google', providerProfile: profile, credentialMethodKey: 'oauth2',
    providerConfigurationId: 'config-1', clientBindingFingerprint: clientBinding().clientBindingFingerprint,
    accountId: 'account-1', grantedScopes: ['email'], ...overrides
  });
}

function oauthResult(overrides = {}) {
  return new OAuthResult({
    providerId: 'google:account-1', provider: 'google', accountId: 'account-1', accessToken: 'test-access-token',
    scopes: ['email'], ...overrides
  });
}

test('OAuth-Context Binding client fingerprints are deterministic and secret-free', () => {
  const first = clientBinding();
  const second = clientBinding({ clientId: 'client-1' });
  assert.equal(first.clientBindingFingerprint, second.clientBindingFingerprint);
  assert.notEqual(first.clientBindingFingerprint, clientBinding({ clientId: 'client-2' }).clientBindingFingerprint);
  assert.equal(JSON.stringify(first.toJSON()).includes('client-1'), false);
  assert.equal(JSON.stringify(first.toJSON()).includes('clientSecret'), false);
});

test('OAuth-Context Binding transaction stores one-time context and current client identity', () => {
  const service = new OAuthSecurityService({ ttlMs: 1000 });
  const created = service.createAuthorizationContext({
    provider: 'google', providerProfile: profile, credentialMethodKey: 'oauth2',
    providerConfigurationId: 'config-1', clientId: 'client-1',
    publicOrigin: 'https://sekalum.example', redirectUri: 'https://sekalum.example/oauth/google/callback',
    scopes: ['email']
  });
  assert.ok(created.clientBindingFingerprint);
  assert.deepEqual(created.requestedScopes, ['email']);
  assert.equal(service.contexts.has(created.state), true);
  service.consumeCallbackContext({ provider: 'google', state: created.state, providerProfile: profile });
  assert.equal(service.contexts.has(created.state), false);
});

test('all eight built-in OAuth providers expose an explicit evidence policy', () => {
  for (const provider of ['x', 'kick', 'twitch', 'google', 'discord', 'threads', 'facebook', 'instagram']) {
    const policy = OAUTH_PROVIDER_EVIDENCE_POLICIES[provider];
    assert.ok(policy, `${provider} policy is present`);
    assert.equal(policy.STATE.requirement, 'REQUIRED');
    assert.equal(policy.ACCOUNT.requirement, 'REQUIRED');
    assert.equal(policy.CLIENT.requirement, 'REQUIRED');
    assert.equal(policy.SCOPES.requirement, 'REQUIRED');
  }
});

test('OAUTH-ATTACK-002: required evidence unavailable blocks', () => {
  const binding = { ...credentialBinding().toJSON(), providerProfile: profile, clientBindingFingerprint: null };
  const result = compareOAuthContextEvidence({
    providerKey: 'google', binding, oauthResult: { provider: 'google', accountId: 'account-1' }
  });
  assert.equal(result.pass, false);
  assert.equal(result.failures[0].code, 'OAUTH_EVIDENCE_UNAVAILABLE');
});

test('OAUTH-ATTACK-003: client or redirect substitution blocks', () => {
  const binding = { ...credentialBinding().toJSON(), providerProfile: profile };
  const result = compareOAuthContextEvidence({
    providerKey: 'google', binding,
    currentBinding: { ...binding, clientBindingFingerprint: 'f'.repeat(64) }, oauthResult: oauthResult()
  });
  assert.equal(result.pass, false);
  assert.equal(result.failures.some((error) => error.code === 'OAUTH_CLIENT_MISMATCH'), true);
});

test('OAUTH-ATTACK-004: requested, granted and required scopes remain separate', () => {
  const binding = { ...credentialBinding().toJSON(), providerProfile: profile, requestedScopes: ['email'], requiredScopes: ['profile'] };
  const result = compareOAuthContextEvidence({ providerKey: 'google', binding, oauthResult: oauthResult() });
  assert.equal(result.pass, false);
  assert.equal(result.failures.some((error) => error.code === 'OAUTH_SCOPE_MISMATCH'), true);
});

test('OAUTH-ATTACK-005: account substitution blocks', () => {
  const binding = { ...credentialBinding().toJSON(), providerProfile: profile };
  const result = compareOAuthContextEvidence({ providerKey: 'google', binding, oauthResult: oauthResult({ accountId: 'account-2' }) });
  assert.equal(result.pass, false);
  assert.equal(result.failures.some((error) => error.code === 'OAUTH_ACCOUNT_MISMATCH'), true);
});

test('OAUTH-ATTACK-006: existing Credential binding mismatch causes zero writes', async () => {
  const existing = new Credential({
    credentialId: 'google-existing', providerKey: 'google', credentialMethodKey: 'oauth2', externalReference: 'account-1',
    lifecycleState: LifecycleState.ACTIVE, oauthCredentialBinding: credentialBinding({ clientBindingFingerprint: 'a'.repeat(64) }),
    secrets: [{ name: 'accessToken', value: 'old-access' }]
  });
  let writes = 0;
  const manager = new CredentialManager({
    credentialStore: {
      async loadByExternalReference() { return existing; },
      async save() { writes += 1; }
    }, providerManager: { getProvider() { return { credentialMethods: [], providerProfile: profile }; } }
  });
  await assert.rejects(() => manager.importCredential(new OAuthResult({
    providerId: 'google:account-1', provider: 'google', accountId: 'account-1', accessToken: 'new-access',
    contextBinding: credentialBinding().toJSON(), metadata: { providerProfile: profile, credentialMethodKey: 'oauth2' }
  })), (error) => error.code === 'OAUTH_CREDENTIAL_BINDING_MISMATCH');
  assert.equal(writes, 0);
});

test('OAUTH-ATTACK-007: refresh account rebind is rejected before write', async () => {
  const binding = credentialBinding();
  const credential = new Credential({
    credentialId: 'google-refresh', providerKey: 'google', credentialMethodKey: 'oauth2', externalReference: 'account-1',
    lifecycleState: LifecycleState.ACTIVE, oauthCredentialBinding: binding, secrets: [{ name: 'accessToken', value: 'old' }, { name: 'refreshToken', value: 'refresh' }]
  });
  let writes = 0;
  const manager = new CredentialManager({
    credentialStore: { async save() { writes += 1; } },
    providerManager: {
      async refreshCredential() { return ProviderResult.success(oauthResult({ accountId: 'account-2' })); }
    }
  });
  const result = await manager.refresh(credential);
  assert.equal(result.success, false);
  assert.equal(result.error.code, 'OAUTH_ACCOUNT_MISMATCH');
  assert.equal(writes, 0);
});

test('OAUTH-ATTACK-008: browser input cannot override server binding', () => {
  const binding = { ...credentialBinding().toJSON(), providerProfile: profile };
  const result = compareOAuthContextEvidence({
    providerKey: 'google', binding, oauthResult: oauthResult({ metadata: { continueAnyway: true } })
  });
  assert.equal(result.pass, true);
  assert.equal(JSON.stringify(result.evidence).includes('continueAnyway'), false);
});

test('OAUTH-ATTACK-009: stale PASS cannot be replayed after restart', () => {
  const service = new OAuthSecurityService();
  const created = service.createAuthorizationContext({ provider: 'google', providerProfile: profile, credentialMethodKey: 'oauth2' });
  const restarted = new OAuthSecurityService();
  assert.throws(() => restarted.consumeCallbackContext({ provider: 'google', state: created.state, providerProfile: profile }), /unknown or expired/);
});

test('OAUTH-ATTACK-010: bindings and evidence never contain secret or raw response material', () => {
  const binding = credentialBinding().toJSON();
  const admission = compareOAuthContextEvidence({ providerKey: 'google', binding: { ...binding, providerProfile: profile }, oauthResult: oauthResult() });
  const serialized = JSON.stringify({ binding, evidence: admission.evidence });
  assert.equal(serialized.includes('test-access-token'), false);
  assert.equal(serialized.includes('refreshToken'), false);
  assert.equal(serialized.includes('clientSecret'), false);
});
