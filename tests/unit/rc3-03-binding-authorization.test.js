import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { ConsumerGrantService } from '../../src/services/consumer-grant-service.js';
import { ConsumerGrantController } from '../../src/controllers/consumer-grant-controller.js';

function fixture({ withAuthority = true } = {}) {
  const grants = { revision: 0, grants: [] };
  const credential = new Credential({
    credentialId: 'binding-credential', providerKey: 'threads', credentialMethodKey: 'oauth2', lifecycleState: 'active',
    secrets: [{ name: 'accessToken', value: 'opaque-test-secret' }]
  });
  const service = new ConsumerGrantService({
    store: {
      async load() { return structuredClone(grants); },
      async save(next) { grants.revision += 1; grants.grants = structuredClone(next.grants); }
    },
    ...(withAuthority ? { apiTokenService: { async getToken(id) { if (id === 'consumer-1') return { id }; throw Object.assign(new Error('missing'), { code: 'NOT_FOUND' }); } } } : {}),
    credentialStore: { async load(id) { return id === credential.credentialId ? credential : Object.assign(new Error('missing'), { code: 'NOT_FOUND' }); } },
    providerRegistry: { get() { return { getCredentialMethod: () => ({ credentialFields: [{ key: 'accessToken', secret: true }] }), getProviderMethodBinding: () => ({ methodKey: 'oauth2' }) }; } }
  });
  return { service, grants };
}

test('RC3-03 binding boundary rejects missing Consumer authority without mutation', async () => {
  const { service, grants } = fixture({ withAuthority: false });
  await assert.rejects(() => service.createGrant({ consumerId: 'consumer-1', credentialId: 'binding-credential', providerKey: 'threads', secretNames: ['accessToken'] }), { code: 'CONSUMER_AUTHORITY_UNAVAILABLE' });
  assert.deepEqual(grants.grants, []);
  assert.equal(grants.revision, 0);
});

test('RC3-03 binding boundary revalidates fixed identity and never permits rebinding on update', async () => {
  const { service, grants } = fixture();
  const created = await service.createGrant({ consumerId: 'consumer-1', credentialId: 'binding-credential', providerKey: 'threads', secretNames: ['accessToken'] });
  await assert.rejects(
    () => service.updateGrant(created.grantId, { consumerId: 'other-consumer', secretNames: ['accessToken'] }),
    (error) => {
      assert.equal(error.code, 'CONSUMER_GRANT_BINDING_IMMUTABLE');
      assert.equal(error.details.binding.decision, 'BLOCKED');
      return true;
    }
  );
  assert.equal(grants.grants[0].consumerId, 'consumer-1');
  const check = await service.validateBinding({ consumerId: 'consumer-1', credentialId: 'binding-credential', providerKey: 'threads', secretNames: ['accessToken'] }, { pathId: 'BIND-GRANT-UPDATE', grantId: created.grantId });
  assert.equal(check.decision, 'CAN_BE_SAVED');
  assert.equal(check.referenceOwner, 'Core');
  assert.equal(Object.hasOwn(check, 'secret'), false);
});

test('RC3-03 rejected binding leaves persisted state and revision unchanged', async () => {
  const { service, grants } = fixture();
  await assert.rejects(() => service.createGrant({ consumerId: 'consumer-1', credentialId: 'binding-credential', providerKey: 'threads', secretNames: ['not-in-contract'] }), { code: 'CONSUMER_GRANT_SECRET_INVALID' });
  assert.deepEqual(grants.grants, []);
  assert.equal(grants.revision, 0);
});

test('RC3-03 stale Reference Check cannot authorize a later commit', async () => {
  const { service, grants } = fixture();
  const metadata = { credentialId: 'binding-credential', providerKey: 'threads', credentialMethodKey: 'oauth2', credentialGeneration: 'generation-1', lifecycleState: 'active', secretNames: ['accessToken'], secretInventory: [{ name: 'accessToken', hasValue: true }] };
  const staleStore = {
    async load() { return structuredClone(grants); },
    async save(next) { grants.revision += 1; grants.grants = structuredClone(next.grants); }
  };
  const staleService = new ConsumerGrantService({
    store: staleStore,
    apiTokenService: { async getToken(id) { return { id }; } },
    credentialStore: { async loadMetadata() { return metadata; } },
    providerRegistry: { get() { return { getCredentialMethod: () => ({ credentialFields: [{ key: 'accessToken', secret: true }] }), getProviderMethodBinding: () => ({ methodKey: 'oauth2' }) }; } }
  });
  const check = await staleService.validateBinding({ consumerId: 'consumer-1', credentialId: metadata.credentialId, credentialGeneration: 'generation-1', providerKey: 'threads', secretNames: ['accessToken'] });
  assert.equal(check.decision, 'CAN_BE_SAVED');
  metadata.credentialGeneration = 'generation-2';
  await assert.rejects(() => staleService.createGrant({ consumerId: 'consumer-1', credentialId: metadata.credentialId, credentialGeneration: 'generation-1', providerKey: 'threads', secretNames: ['accessToken'] }), { code: 'CONSUMER_GRANT_GENERATION_MISMATCH' });
  assert.deepEqual(grants.grants, []);
});

test('RC3-03 commit revalidates the binding at the store commit boundary', async () => {
  const grants = { revision: 0, grants: [] };
  const metadata = {
    credentialId: 'binding-credential', providerKey: 'threads', credentialMethodKey: 'oauth2',
    credentialGeneration: 'generation-1', lifecycleState: 'active', secretNames: ['accessToken'],
    secretInventory: [{ name: 'accessToken', hasValue: true }]
  };
  const service = new ConsumerGrantService({
    store: {
      async load() { return structuredClone(grants); },
      async save(next, { beforeCommit } = {}) {
        metadata.credentialGeneration = 'generation-2';
        await beforeCommit?.();
        grants.revision += 1;
        grants.grants = structuredClone(next.grants);
      }
    },
    apiTokenService: { async getToken(id) { return { id }; } },
    credentialStore: { async loadMetadata() { return metadata; } },
    providerRegistry: { get() { return { getCredentialMethod: () => ({ credentialFields: [{ key: 'accessToken', secret: true }] }), getProviderMethodBinding: () => ({ methodKey: 'oauth2' }) }; } }
  });

  await assert.rejects(
    () => service.createGrant({ consumerId: 'consumer-1', credentialId: metadata.credentialId, credentialGeneration: 'generation-1', providerKey: 'threads', secretNames: ['accessToken'] }),
    (error) => {
      assert.equal(error.code, 'CONSUMER_GRANT_GENERATION_MISMATCH');
      assert.equal(error.details.binding.decision, 'BLOCKED');
      assert.equal(error.details.binding.pathId, 'BIND-GRANT-CREATE');
      return true;
    }
  );
  assert.deepEqual(grants.grants, []);
  assert.equal(grants.revision, 0);
});

test('RC3-03 controller returns structured, secret-free binding denials', async () => {
  const { service } = fixture({ withAuthority: false });
  const controller = new ConsumerGrantController({ consumerGrantService: service });
  let body; let status;
  await controller.create({ body: { consumerId: 'consumer-1', credentialId: 'binding-credential', providerKey: 'threads', secretNames: ['accessToken'] }, auth: { userId: 'admin' } }, {
    status(value) { status = value; return this; },
    json(value) { body = value; }
  });
  assert.equal(status, 409);
  assert.equal(body.error.code, 'CONSUMER_AUTHORITY_UNAVAILABLE');
  assert.equal(body.error.binding.decision, 'BLOCKED');
  assert.equal(JSON.stringify(body).includes('opaque-test-secret'), false);
});
