import test from 'node:test';
import assert from 'node:assert/strict';

import { bootstrap } from '../../src/bootstrap.js';

const OAUTH_PROVIDERS = ['discord', 'facebook', 'google', 'instagram', 'kick', 'threads', 'twitch', 'x'];

test('every built-in OAuth provider exposes metadata-driven application configuration', async () => {
  const application = await bootstrap();
  const providers = application.providerManager.listProviders();

  for (const key of OAUTH_PROVIDERS) {
    const provider = providers.find((entry) => entry.key === key);
    assert.ok(provider, `${key} must be registered on a fresh installation`);
    assert.match(provider.authType, /^oauth2(?:\.1)?$/);
    assert.notEqual(provider.authType, 'unknown');

    const fields = provider.providerConfigurationFields;
    assert.deepEqual(fields.filter((field) => field.required).map((field) => field.key).includes('clientId'), true);
    assert.deepEqual(fields.filter((field) => field.required).map((field) => field.key).includes('redirectUri'), true);
    assert.equal(fields.find((field) => field.key === 'clientSecret')?.secret, true);
    assert.equal(fields.find((field) => field.key === 'clientSecret')?.defaultValue, null);
    const redirectUri = fields.find((field) => field.key === 'redirectUri');
    assert.equal(redirectUri.visible, false);
    assert.equal(redirectUri.userConfigurable, false);
    assert.equal(redirectUri.systemManaged, true);
    assert.equal(redirectUri.readonly, true);
    assert.match(provider.oauthTechnical.authorizationEndpoint, /^https:\/\//);
  }

  const xSecret = providers.find((entry) => entry.key === 'x')
    .providerConfigurationFields.find((field) => field.key === 'clientSecret');
  assert.equal(xSecret.required, false);
});

test('every built-in provider exposes complete renderer metadata', async () => {
  const application = await bootstrap();
  const providers = application.providerManager.listProviders();

  for (const provider of providers) {
    assert.ok(provider.displayName, `${provider.key} requires a display name`);
    assert.ok(provider.description, `${provider.key} requires a description`);
    assert.ok(provider.authType, `${provider.key} requires an authentication type`);
    assert.ok(Array.isArray(provider.capabilities), `${provider.key} requires capabilities`);
    for (const field of provider.credentialFields) {
      assert.ok(field.key, `${provider.key} contains a field without a key`);
      assert.ok(field.label, `${provider.key}.${field.key} requires a label`);
      assert.ok(field.description, `${provider.key}.${field.key} requires a description`);
      assert.ok(field.type, `${provider.key}.${field.key} requires a type`);
      assert.equal(typeof field.required, 'boolean');
      assert.equal(typeof field.visible, 'boolean');
      assert.equal(typeof field.userConfigurable, 'boolean');
      assert.equal(typeof field.systemManaged, 'boolean');
    }
  }
});
