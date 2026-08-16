import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeSecretNames, sameGrantConfiguration, synchronizeGrant } from '../../public/admin/grant-synchronization.js';

const config = (overrides = {}) => ({ consumerId: 'consumer-a', credentialId: 'credential-a', providerKey: 'threads', secretNames: ['accessToken'], ...overrides });
const grant = (overrides = {}) => ({ grantId: 'grant-a', ...config(), ...overrides });

test('grant synchronization compares secret names as a normalized set', () => {
  assert.deepEqual(normalizeSecretNames([' refreshToken ', 'accessToken', 'accessToken', '']), ['accessToken', 'refreshToken']);
  assert.equal(sameGrantConfiguration(grant({ secretNames: ['refreshToken', 'accessToken'] }), config({ secretNames: ['accessToken', 'refreshToken'] })), true);
});

test('grant synchronization updates changed fields before Resolve and leaves the old state untouched on PUT failure', async () => {
  const calls = [];
  const saved = grant();
  const next = config({ secretNames: ['refreshToken'] });
  const api = async (path, options = {}) => {
    calls.push({ path, options });
    if (options.method === 'PUT') return { data: grant({ secretNames: ['refreshToken'] }) };
    throw new Error(`unexpected ${path}`);
  };
  const synchronized = await synchronizeGrant({ api, savedGrant: saved, configuration: next });
  assert.deepEqual(synchronized.secretNames, ['refreshToken']);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.method, 'PUT');

  await assert.rejects(() => synchronizeGrant({ api: async () => { const error = new Error('PUT failed'); error.code = 'REQUEST_FAILED'; throw error; }, savedGrant: saved, configuration: next }));
  assert.deepEqual(saved.secretNames, ['accessToken']);
});

test('grant synchronization creates a separate consumer binding and recovers a duplicate through PUT', async () => {
  const calls = [];
  let listCalls = 0;
  const api = async (path, options = {}) => {
    calls.push({ path, options });
    if (path.startsWith('/api/v1/management/consumer-grants?')) {
      listCalls += 1;
      return { data: listCalls === 1 ? [] : [grant({ grantId: 'grant-b', consumerId: 'consumer-b', secretNames: ['accessToken'] })] };
    }
    if (path === '/api/v1/management/consumer-grants') { const error = new Error('duplicate'); error.code = 'CONSUMER_GRANT_DUPLICATE'; throw error; }
    if (options.method === 'PUT') return { data: grant({ grantId: 'grant-b', consumerId: 'consumer-b', secretNames: ['refreshToken'] }) };
    throw new Error(`unexpected ${path}`);
  };
  const synchronized = await synchronizeGrant({ api, savedGrant: null, configuration: config({ consumerId: 'consumer-b', secretNames: ['refreshToken'] }) });
  assert.equal(synchronized.consumerId, 'consumer-b');
  assert.deepEqual(synchronized.secretNames, ['refreshToken']);
  assert.equal(calls.filter(({ options }) => options.method === 'PUT').length, 1);
  assert.deepEqual(calls.filter(({ options }) => options.method === 'POST').length, 1);
});

test('grant synchronization does not update a matching binding when only secret order changed', async () => {
  const calls = [];
  const saved = grant({ secretNames: ['refreshToken', 'accessToken'] });
  const synchronized = await synchronizeGrant({ api: async (...args) => { calls.push(args); }, savedGrant: saved, configuration: config({ secretNames: ['accessToken', 'refreshToken'] }) });
  assert.deepEqual(synchronized.secretNames, ['accessToken', 'refreshToken']);
  assert.equal(calls.length, 0);
});
