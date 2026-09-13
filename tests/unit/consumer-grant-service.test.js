import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { ConsumerGrantService } from '../../src/services/consumer-grant-service.js';

function createService({ consumers = ['consumer-1'], credentials = null, store = null } = {}) {
  const credentialRecords = credentials ?? new Map([
    ['credential-1', new Credential({
      credentialId: 'credential-1',
      providerKey: 'threads',
      credentialMethodKey: 'oauth2',
      lifecycleState: 'active',
      secrets: [{ name: 'accessToken', value: 'secret' }, { name: 'refreshToken', value: 'refresh' }]
    })]
  ]);

  return new ConsumerGrantService({
    store,
    apiTokenService: {
      async getToken(consumerId) {
        if (consumers.includes(consumerId)) return { id: consumerId };
        const error = new Error('missing consumer');
        error.code = 'NOT_FOUND';
        throw error;
      }
    },
    credentialStore: {
      async load(credentialId) {
        const credential = credentialRecords.get(credentialId);
        if (credential) return credential;
        const error = new Error('missing credential');
        error.code = 'NOT_FOUND';
        throw error;
      }
    },
    providerRegistry: {
      get(providerKey) {
        if (providerKey !== 'threads') throw new Error('missing provider');
        return {
          getCredentialMethod(methodKey) {
            return methodKey === 'oauth2'
              ? { credentialFields: [{ key: 'accessToken', secret: true }, { key: 'refreshToken', secret: true }, { key: 'clientId', secret: false }] }
              : null;
          },
          getProviderMethodBinding(methodKey) { return methodKey === 'oauth2' ? { methodKey } : null; }
        };
      }
    }
  });
}

function createDerivedService({ derivedFields = ['runtimeToken'] } = {}) {
  const credential = new Credential({
    credentialId: 'credential-derived-1',
    providerKey: 'threads',
    credentialMethodKey: 'service-account',
    lifecycleState: 'active',
    secrets: [{ name: 'signingIdentity', value: 'durable-identity' }]
  });
  return new ConsumerGrantService({
    apiTokenService: { async getToken(consumerId) { return { id: consumerId }; } },
    credentialStore: { async load(credentialId) { return credentialId === credential.credentialId ? credential : null; } },
    providerRegistry: {
      get() {
        return {
          runtimeDerivation: {
            supportsRuntimeDerivation: true,
            derivationMethod: 'service-account-exchange-v1',
            requiredDurableInputs: ['signingIdentity'],
            supportedAudiences: [],
            supportedScopes: [],
            derivedFields,
            expirySource: 'provider',
            cachePolicy: 'NO_CACHE',
            refreshThresholdMs: 0
          },
          getCredentialMethod(methodKey) {
            return methodKey === 'service-account'
              ? { credentialFields: [{ key: 'signingIdentity', secret: true }, { key: 'runtimeToken', secret: true, materialization: 'derived' }] }
              : null;
          },
          getProviderMethodBinding(methodKey) { return methodKey === 'service-account' ? { methodKey } : null; }
        };
      }
    }
  });
}

test('ConsumerGrantService accepts grants only for an existing injectable consumer and secret contract', async () => {
  const service = createService();
  const grant = await service.createGrant({
    consumerId: 'consumer-1', credentialId: 'credential-1', providerKey: 'threads', secretNames: ['accessToken']
  });

  assert.equal(grant.consumerId, 'consumer-1');
  assert.deepEqual(grant.secretNames, ['accessToken']);
});

test('ConsumerGrantService rejects unknown consumers, credential/provider mismatches, and non-secret fields', async () => {
  const service = createService();
  const base = { consumerId: 'consumer-1', credentialId: 'credential-1', providerKey: 'threads', secretNames: ['accessToken'] };

  await assert.rejects(
    service.createGrant({ ...base, consumerId: 'missing-consumer' }),
    (error) => error.code === 'CONSUMER_NOT_FOUND' && error.statusCode === 404
  );
  await assert.rejects(
    service.createGrant({ ...base, providerKey: 'openai' }),
    (error) => error.code === 'CONSUMER_GRANT_PROVIDER_MISMATCH' && error.statusCode === 400
  );
  await assert.rejects(
    service.createGrant({ ...base, secretNames: ['clientId'] }),
    (error) => error.code === 'CONSUMER_GRANT_SECRET_INVALID' && error.statusCode === 400
  );
  await assert.rejects(
    service.createGrant({ ...base, secretNames: ['refreshToken', 'unknown'] }),
    (error) => error.code === 'CONSUMER_GRANT_SECRET_INVALID' && error.statusCode === 400
  );
  assert.deepEqual(await service.listGrants(), [], 'failed bindings are never persisted');
});

test('ConsumerGrantService lists filtered grants and updates fields after revalidation', async () => {
  const service = createService();
  const created = await service.createGrant({
    consumerId: 'consumer-1', credentialId: 'credential-1', providerKey: 'threads', secretNames: ['accessToken']
  });

  const listed = await service.listGrants({ consumerId: 'consumer-1' });
  assert.equal(listed.length, 1);
  const updated = await service.updateGrant(created.grantId, { secretNames: ['refreshToken'] });
  assert.equal(updated.grantId, created.grantId);
  assert.equal(updated.createdAt.toISOString(), created.createdAt.toISOString());
  assert.deepEqual(updated.secretNames, ['refreshToken']);

  await assert.rejects(
    service.updateGrant('missing-grant', { secretNames: ['accessToken'] }),
    (error) => error.code === 'NOT_FOUND' && error.statusCode === 404
  );

  await assert.rejects(
    service.updateGrant(created.grantId, { providerKey: 'openai' }),
    (error) => error.code === 'CONSUMER_GRANT_PROVIDER_MISMATCH' && error.statusCode === 400
  );
  const preserved = await service.findGrant({ consumerId: 'consumer-1', credentialId: 'credential-1', providerKey: 'threads' });
  assert.deepEqual(preserved.secretNames, ['refreshToken'], 'failed updates preserve the authorized binding');
});

test('ConsumerGrantService permits derived fields only when the live derivation contract declares them', async () => {
  const service = createDerivedService();
  const created = await service.createGrant({
    consumerId: 'consumer-1', credentialId: 'credential-derived-1', providerKey: 'threads', secretNames: ['signingIdentity']
  });
  const updated = await service.updateGrant(created.grantId, { secretNames: ['runtimeToken'] });
  assert.deepEqual(updated.secretNames, ['runtimeToken']);

  const undeclared = createDerivedService({ derivedFields: [] });
  await assert.rejects(
    undeclared.createGrant({
      consumerId: 'consumer-1', credentialId: 'credential-derived-1', providerKey: 'threads', secretNames: ['runtimeToken']
    }),
    (error) => error.code === 'CONSUMER_GRANT_SECRET_INVALID' && error.statusCode === 400
  );
  assert.deepEqual(await undeclared.listGrants(), []);
});

test('ConsumerGrantService serializes concurrent create, update and delete read-modify-write operations', async () => {
  let data = { grants: [] };
  const store = {
    async load() {
      const snapshot = structuredClone(data);
      await new Promise((resolve) => setTimeout(resolve, 5));
      return snapshot;
    },
    async save(value) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      data = structuredClone(value);
    }
  };
  const credentials = new Map([
    ['credential-1', new Credential({ credentialId: 'credential-1', providerKey: 'threads', credentialMethodKey: 'oauth2', lifecycleState: 'active', secrets: [{ name: 'accessToken', value: 'one' }, { name: 'refreshToken', value: 'one-refresh' }] })],
    ['credential-2', new Credential({ credentialId: 'credential-2', providerKey: 'threads', credentialMethodKey: 'oauth2', lifecycleState: 'active', secrets: [{ name: 'accessToken', value: 'two' }, { name: 'refreshToken', value: 'two-refresh' }] })]
  ]);
  const service = createService({ credentials, store });
  const first = await service.createGrant({
    consumerId: 'consumer-1', credentialId: 'credential-1', providerKey: 'threads', secretNames: ['accessToken']
  });

  await Promise.all([
    service.createGrant({ consumerId: 'consumer-1', credentialId: 'credential-2', providerKey: 'threads', secretNames: ['accessToken'] }),
    service.updateGrant(first.grantId, { secretNames: ['refreshToken'] }),
    service.deleteGrant(first.grantId)
  ]);

  assert.deepEqual(
    (await service.listGrants()).map((grant) => ({ credentialId: grant.credentialId, secretNames: grant.secretNames })),
    [{ credentialId: 'credential-2', secretNames: ['accessToken'] }]
  );
});

test('ConsumerGrantService releases its mutation queue after a failed persisted write', async () => {
  let data = { grants: [] };
  let failNextSave = true;
  const store = {
    async load() { return structuredClone(data); },
    async save(value) {
      if (failNextSave) {
        failNextSave = false;
        throw new Error('simulated write failure');
      }
      data = structuredClone(value);
    }
  };
  const service = createService({ store });
  await assert.rejects(
    service.createGrant({ consumerId: 'consumer-1', credentialId: 'credential-1', providerKey: 'threads', secretNames: ['accessToken'] }),
    /simulated write failure/
  );
  await service.createGrant({ consumerId: 'consumer-1', credentialId: 'credential-1', providerKey: 'threads', secretNames: ['refreshToken'] });

  assert.deepEqual((await service.listGrants()).map((grant) => grant.secretNames), [['refreshToken']]);
});
