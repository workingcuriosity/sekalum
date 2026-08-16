import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { ConsumerGrantService } from '../../src/services/consumer-grant-service.js';

function createService({ consumers = ['consumer-1'], credentials = null } = {}) {
  const credentialRecords = credentials ?? new Map([
    ['credential-1', new Credential({
      credentialId: 'credential-1',
      providerKey: 'threads',
      credentialMethodKey: 'oauth2',
      secrets: [{ name: 'accessToken', value: 'secret' }, { name: 'refreshToken', value: 'refresh' }]
    })]
  ]);

  return new ConsumerGrantService({
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
});
