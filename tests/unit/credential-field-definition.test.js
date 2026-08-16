import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialFieldDefinition } from '../../src/models/credential-field-definition.js';

const field = (overrides = {}) => new CredentialFieldDefinition({
  key: 'clientId',
  label: 'Client ID',
  section: 'providerConfiguration',
  ...overrides
});

test('CredentialFieldDefinition defaults Runtime-Public to deny', () => {
  const definition = field();

  assert.equal(definition.runtimePublic, false);
});

test('CredentialFieldDefinition accepts Runtime-Public provider configuration fields', () => {
  const definition = field({ runtimePublic: true });

  assert.equal(definition.runtimePublic, true);
});

test('CredentialFieldDefinition rejects Runtime-Public secret fields', () => {
  assert.throws(
    () => field({ secret: true, runtimePublic: true }),
    /secret fields must not be Runtime-Public/
  );
});

test('CredentialFieldDefinition rejects Runtime-Public fields outside providerConfiguration', () => {
  assert.throws(
    () => field({ section: 'accountCredentials', runtimePublic: true }),
    /runtimePublic fields must use the providerConfiguration section/
  );
});

test('CredentialFieldDefinition rejects unknown Runtime-Public classifications', () => {
  assert.throws(
    () => field({ runtimePublic: 'yes' }),
    /runtimePublic must be a boolean/
  );
});

test('CredentialFieldDefinition rejects internal fields marked Runtime-Public', () => {
  assert.throws(
    () => field({ key: 'providerConfigurationId', runtimePublic: true }),
    /internal fields must not be Runtime-Public/
  );
});
