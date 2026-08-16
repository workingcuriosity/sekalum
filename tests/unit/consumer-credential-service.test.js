import test from 'node:test';
import assert from 'node:assert/strict';

import { ConsumerCredentialService } from '../../src/services/consumer-credential-service.js';
import { Credential } from '../../src/models/credential.js';

function setup({ lifecycleState = 'active', grantNames = ['apiKey', 'secondaryKey'], credentialMethodKey = 'api-key', credentialManager = null, runtimePublicProjectionService = null, findGrantResult = undefined } = {}) {
  const secretValue = 'consumer-test-secret';
  const credential = new Credential({
    credentialId: 'credential-1', providerKey: 'example', credentialMethodKey, lifecycleState,
    secrets: [{ name: 'apiKey', value: secretValue }, { name: 'secondaryKey', value: 'second-secret' }]
  });
  const audit = [];
  const findGrantCalls = [];
  const service = new ConsumerCredentialService({
    credentialStore: { async load(id) { if (id !== credential.credentialId) { const e = new Error('missing'); e.code = 'NOT_FOUND'; throw e; } return credential; } },
    consumerGrantService: {
      async findGrant(input) {
        findGrantCalls.push(input);
        return findGrantResult === undefined
          ? { consumerId: input.consumerId, credentialId: credential.credentialId, providerKey: credential.providerKey, secretNames: grantNames }
          : findGrantResult;
      },
      async listGrants() { return [{ credentialId: credential.credentialId, providerKey: credential.providerKey }]; }
    },
    credentialManager,
    runtimePublicProjectionService,
    providerRegistry: { get() { return {
      getCredentialMethod(key) {
        if (key !== 'api-key') return null;
        return { credentialFields: [{ key: 'apiKey', secret: true }, { key: 'secondaryKey', secret: true }, { key: 'name', secret: false }] };
      },
      getProviderMethodBinding(key) { return key === 'api-key' ? { methodKey: key } : null; }
    }; } },
    auditLogService: { async record(entry) { audit.push(entry); } }
  });
  return { service, audit, secretValue, findGrantCalls };
}

test('consumer resolves only explicitly requested and granted secret fields', async () => {
  const { service, audit, secretValue } = setup();
  const result = await service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] });
  assert.deepEqual(result.secrets, { apiKey: secretValue });
  assert.equal(result.providerKey, 'example');
  assert.equal(result.credentialMethodKey, undefined);
  assert.equal(result.credentialKey, 'credential-1');
  assert.deepEqual(Object.keys(result).sort(), ['credentialKey', 'lifecycleState', 'providerKey', 'secrets']);
  assert.equal(audit[0].result, 'success');
  assert.equal(JSON.stringify(audit[0]).includes(secretValue), false);
});

test('consumer derives its secret contract from the selected credential method, not provider fields', async () => {
  const { service } = setup({ grantNames: ['name'] });
  await assert.rejects(
    () => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['name'] }),
    { code: 'CONSUMER_ACCESS_DENIED' }
  );

  const missingMethod = setup({ credentialMethodKey: null });
  await assert.rejects(
    () => missingMethod.service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] }),
    { code: 'CONSUMER_ACCESS_DENIED' }
  );
});

test('consumer denies ungranted fields and non-active credentials without auditing secrets', async () => {
  const { service, audit, secretValue } = setup({ grantNames: ['apiKey'] });
  await assert.rejects(() => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['secondaryKey'] }), { code: 'SECRET_NOT_GRANTED' });
  assert.equal(audit[0].result, 'failure');
  assert.equal(JSON.stringify(audit[0]).includes(secretValue), false);

  const inactive = setup({ lifecycleState: 'revoked' });
  await assert.rejects(() => inactive.service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] }), { code: 'CREDENTIAL_NOT_CONSUMABLE' });
});

test('consumer resolves a credential after the existing manager refreshes it when due', async () => {
  const { service, secretValue } = setup({
    credentialManager: {
      async refreshIfDue(credential) {
        assert.equal(credential.credentialId, 'credential-1');
        return new Credential({
          ...credential.toJSON(),
          secrets: [{ name: 'apiKey', value: `${secretValue}-refreshed` }, { name: 'secondaryKey', value: 'second-secret' }]
        });
      }
    }
  });

  const result = await service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] });

  assert.deepEqual(result.secrets, { apiKey: `${secretValue}-refreshed` });
});

test('consumer rejects malformed requests and unknown credentials', async () => {
  const { service } = setup();
  await assert.rejects(() => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: [] }), { code: 'INVALID_SECRET_REQUEST' });
  await assert.rejects(() => service.resolve({ consumerId: 'consumer-a', credentialKey: 'missing', secretNames: ['apiKey'] }), { code: 'CREDENTIAL_NOT_FOUND' });
});

test('consumer discovery adds a non-empty Runtime-Public projection without changing existing fields', async () => {
  const { service } = setup({
    runtimePublicProjectionService: {
      async project() { return { runtimePublic: { clientId: 'public-client' } }; }
    }
  });

  const result = await service.discover({ consumerId: 'consumer-a' });
  assert.deepEqual(result.credentials[0].runtimePublic, { clientId: 'public-client' });
  assert.deepEqual(Object.keys(result.credentials[0]).sort(), ['credentialKey', 'fields', 'metadata', 'runtimePublic']);
});

test('consumer discovery omits an empty Runtime-Public projection', async () => {
  const { service } = setup({
    runtimePublicProjectionService: {
      async project() { return null; }
    }
  });

  const result = await service.discover({ consumerId: 'consumer-a' });
  assert.equal(Object.hasOwn(result.credentials[0], 'runtimePublic'), false);
});

test('consumer discovery fails closed when the matching grant is missing', async () => {
  const { service } = setup({
    findGrantResult: null,
    runtimePublicProjectionService: { async project() { return { runtimePublic: { clientId: 'must-not-leak' } }; } }
  });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
});

test('consumer discovery fails closed when the verified grant is bound to another credential', async () => {
  const { service } = setup({
    findGrantResult: { credentialId: 'other-credential', providerKey: 'example', secretNames: ['apiKey'] },
    runtimePublicProjectionService: { async project() { return { runtimePublic: { clientId: 'must-not-leak' } }; } }
  });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
});

test('consumer discovery fails closed for a grant belonging to another consumer', async () => {
  const { service } = setup({
    findGrantResult: { consumerId: 'consumer-b', credentialId: 'credential-1', providerKey: 'example', secretNames: ['apiKey'] },
    runtimePublicProjectionService: { async project() { return { runtimePublic: { clientId: 'must-not-leak' } }; } }
  });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
});

test('consumer discovery fails closed for an inactive credential', async () => {
  const { service } = setup({
    lifecycleState: 'revoked',
    runtimePublicProjectionService: { async project() { return { runtimePublic: { clientId: 'must-not-leak' } }; } }
  });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
});
