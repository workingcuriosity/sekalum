import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { CredentialSecret } from '../../src/models/credential-secret.js';
import { LifecycleState } from '../../src/models/lifecycle-state.js';
import { LifecycleAction } from '../../src/models/lifecycle-action.js';

test('Credential stores multiple secrets as one fachliche Einheit', () => {
  const credential = new Credential({
    providerKey: 'threads',
    externalReference: 'account-1',
    secrets: [
      { name: 'accessToken', value: 'access' },
      { name: 'refreshToken', value: 'refresh' }
    ],
    metadata: {
      scopes: ['threads.basic'],
      tags: ['oauth']
    }
  });

  assert.equal(credential.providerKey, 'threads');
  assert.equal(credential.externalReference, 'account-1');
  assert.equal(credential.lifecycleState, LifecycleState.REGISTERED);
  assert.equal(credential.secrets.length, 2);
  assert.equal(credential.secrets[0] instanceof CredentialSecret, true);
  assert.deepEqual(credential.metadata.scopes, ['threads.basic']);
  assert.equal(Object.isFrozen(credential), true);
});

test('Credential creates and preserves a stable public credentialKey', () => {
  const credential = new Credential({ credentialId: 'credential-1', providerKey: 'threads' });
  const restored = Credential.from(credential.toJSON());

  assert.match(credential.credentialKey, /^[0-9a-f-]{36}$/);
  assert.equal(restored.credentialKey, credential.credentialKey);
});

test('Credential rejects invalid public credentialKey values', () => {
  for (const credentialKey of [undefined, null, '', '   ', 42, {}, []]) {
    assert.throws(
      () => new Credential({ credentialId: 'credential-1', credentialKey, providerKey: 'threads' }),
      /Credential: 'credentialKey' is required/
    );
  }
});

test('Credential rejects invalid lifecycle states', () => {
  assert.throws(() => new Credential({
    providerKey: 'threads',
    lifecycleState: 'refreshing',
    secrets: [{ name: 'accessToken', value: 'access' }]
  }), /invalid lifecycleState/);
});

test('Lifecycle actions are separated from lifecycle states', () => {
  assert.equal(LifecycleState.ACTIVE, 'active');
  assert.equal(LifecycleAction.REFRESH, 'refresh');
  assert.equal(Object.values(LifecycleState).includes(LifecycleAction.REFRESH), false);
});
