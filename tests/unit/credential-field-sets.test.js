import test from 'node:test';
import assert from 'node:assert/strict';

import {
  connectionCredentialFields,
  oauthCredentialFields
} from '../../src/providers/credential-field-sets.js';

test('OAuth field sets preserve the provider default scopes', () => {
  const fields = oauthCredentialFields({ defaultScopes: ['openid', 'email'] });

  assert.deepEqual(fields.map((field) => field.key), [
    'displayName', 'description', 'clientId', 'clientSecret', 'redirectUri', 'scopes', 'accessToken', 'refreshToken'
  ]);
  assert.deepEqual(fields[5].defaultValue, ['openid', 'email']);
  assert.equal(fields[5].type, 'oauth-scope');
  assert.equal(fields[2].section, 'providerConfiguration');
  assert.equal(fields[3].secret, true);
  assert.equal(fields[3].defaultValue, undefined);
  assert.equal(fields[4].type, 'url');
  assert.equal(fields[4].visible, false);
  assert.equal(fields[4].userConfigurable, false);
  assert.equal(fields[4].systemManaged, true);
  assert.equal(fields[4].readonly, true);
  for (const field of fields.slice(6)) {
    assert.equal(field.type, 'password');
    assert.equal(field.secret, true);
    assert.equal(field.visible, false);
    assert.equal(field.userConfigurable, false);
    assert.equal(field.systemManaged, true);
    assert.equal(field.readonly, true);
    assert.equal(field.section, 'oauthRuntime');
  }
});

test('connection field sets expose only values accepted by connection providers', () => {
  const fields = connectionCredentialFields({ defaultPort: 22 });

  assert.deepEqual(fields.map((field) => field.key), [
    'displayName', 'description', 'host', 'port', 'username', 'password'
  ]);
  assert.equal(fields.find((field) => field.key === 'port').defaultValue, 22);
  assert.equal(fields.find((field) => field.key === 'password').secret, true);
});
