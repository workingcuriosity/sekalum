import test from 'node:test';
import assert from 'node:assert/strict';

import { runGrantDiagnosisAttempt, runGrantResolveAttempt } from '../../public/admin/grant-attempt.js';

const configuration = (name) => ({ grantId: `grant-${name}`, consumerId: `consumer-${name}`, credentialId: 'credential', providerKey: 'threads', secretNames: [`secret-${name}`] });
const deferred = () => { let resolve; let reject; const promise = new Promise((onResolve, onReject) => { resolve = onResolve; reject = onReject; }); return { promise, resolve, reject }; };

function attemptHarness() {
  let generation = 1;
  const state = { savedGrant: null, verification: null, token: 'token-a', message: null, completed: false };
  const run = (input) => runGrantResolveAttempt({
    isCurrentAttempt: () => input.generation === generation,
    commitSavedGrant: (grant) => { state.savedGrant = grant; },
    commitVerification: (verification) => { state.verification = verification; },
    consumeToken: () => { state.token = null; },
    ...input
  });
  return { state, run, setGeneration: (value) => { generation = value; } };
}

test('older delayed grant result cannot overwrite the later successful attempt', async () => {
  const harness = attemptHarness(); const slow = deferred();
  const older = harness.run({ generation: 1, configuration: configuration('a'), consumerToken: 'token-a', synchronizeGrant: () => slow.promise, verifyResolve: async ({ configuration: grant }) => grant });
  harness.setGeneration(2);
  const newer = await harness.run({ generation: 2, configuration: configuration('b'), consumerToken: 'token-b', synchronizeGrant: async (value) => value, verifyResolve: async ({ configuration: grant }) => grant });
  harness.state.completed = newer.status === 'success'; harness.state.message = 'success-b';
  slow.resolve(configuration('a'));
  assert.equal((await older).status, 'stale');
  assert.equal(harness.state.savedGrant.consumerId, 'consumer-b');
  assert.equal(harness.state.verification.consumerId, 'consumer-b');
  assert.equal(harness.state.completed, true);
  assert.equal(harness.state.message, 'success-b');
});

test('a repeated submit invalidates the earlier submit even without a configuration change', async () => {
  const harness = attemptHarness(); const slow = deferred();
  const older = harness.run({ generation: 1, configuration: configuration('a'), consumerToken: 'token-a', synchronizeGrant: () => slow.promise, verifyResolve: async ({ configuration: grant }) => grant });
  harness.setGeneration(2);
  const newer = await harness.run({ generation: 2, configuration: configuration('a'), consumerToken: 'token-b', synchronizeGrant: async (value) => value, verifyResolve: async ({ configuration: grant }) => grant });
  slow.resolve(configuration('a'));
  assert.equal((await older).status, 'stale');
  assert.equal(newer.status, 'success');
  assert.equal(harness.state.verification.consumerId, 'consumer-a');
});

test('a late grant failure cannot replace the message of a current success', async () => {
  const harness = attemptHarness(); const slow = deferred();
  const older = harness.run({ generation: 1, configuration: configuration('a'), consumerToken: 'token-a', synchronizeGrant: () => slow.promise, verifyResolve: async ({ configuration: grant }) => grant });
  harness.setGeneration(2);
  const newer = await harness.run({ generation: 2, configuration: configuration('a'), consumerToken: 'token-b', synchronizeGrant: async (value) => value, verifyResolve: async ({ configuration: grant }) => grant });
  harness.state.message = newer.status === 'success' ? 'success-b' : null;
  slow.reject(new Error('late save failure'));
  assert.equal((await older).status, 'stale');
  assert.equal(harness.state.verification.consumerId, 'consumer-a');
  assert.equal(harness.state.message, 'success-b');
});

test('a stale diagnosis cannot replace a newer resolve success', async () => {
  let generation = 1; const slow = deferred();
  const diagnosis = runGrantDiagnosisAttempt({ isCurrentAttempt: () => generation === 1, diagnoseGrant: () => slow.promise });
  generation = 2;
  const harness = attemptHarness(); harness.setGeneration(2);
  const resolve = await harness.run({ generation: 2, configuration: configuration('b'), consumerToken: 'token-b', synchronizeGrant: async (value) => value, verifyResolve: async ({ configuration: grant }) => grant });
  slow.resolve({ data: { code: 'RESOLVE_SUCCESS' } });
  assert.equal((await diagnosis).status, 'stale');
  assert.equal(resolve.status, 'success');
  assert.equal(harness.state.verification.consumerId, 'consumer-b');
});

test('a stale resolve after a consumer change cannot replace the later successful consumer verification', async () => {
  const harness = attemptHarness(); const slow = deferred();
  const older = harness.run({ generation: 1, configuration: configuration('a'), consumerToken: 'token-a', synchronizeGrant: async (value) => value, verifyResolve: () => slow.promise });
  harness.setGeneration(2); harness.state.token = 'token-b';
  const newer = await harness.run({ generation: 2, configuration: configuration('b'), consumerToken: 'token-b', synchronizeGrant: async (value) => value, verifyResolve: async ({ configuration: grant }) => grant });
  slow.resolve(configuration('a'));
  assert.equal((await older).status, 'stale');
  assert.equal(newer.status, 'success');
  assert.equal(harness.state.verification.consumerId, 'consumer-b');
});

test('a stale attempt cannot consume a replacement token entered after invalidation', async () => {
  const harness = attemptHarness(); const slow = deferred();
  const older = harness.run({ generation: 1, configuration: configuration('a'), consumerToken: 'token-a', synchronizeGrant: async (value) => value, verifyResolve: () => slow.promise });
  harness.setGeneration(2); harness.state.token = 'token-b';
  slow.resolve(configuration('a'));
  assert.equal((await older).status, 'stale');
  assert.equal(harness.state.token, 'token-b');
});

test('current save failure preserves the previous saved grant and prevents Resolve', async () => {
  const harness = attemptHarness(); harness.state.savedGrant = configuration('old'); let resolveCalls = 0;
  const outcome = await harness.run({ generation: 1, configuration: configuration('new'), consumerToken: 'token', synchronizeGrant: async () => { throw new Error('PUT failed'); }, verifyResolve: async () => { resolveCalls += 1; } });
  assert.equal(outcome.status, 'error'); assert.equal(outcome.phase, 'save');
  assert.equal(harness.state.savedGrant.consumerId, 'consumer-old'); assert.equal(resolveCalls, 0);
});

test('current success commits one matching grant and verification snapshot', async () => {
  const harness = attemptHarness(); const current = configuration('current');
  const outcome = await harness.run({ generation: 1, configuration: current, consumerToken: 'token', synchronizeGrant: async (value) => value, verifyResolve: async ({ configuration: grant }) => grant });
  assert.equal(outcome.status, 'success');
  assert.deepEqual(harness.state.savedGrant, harness.state.verification);
  harness.state.flowState = outcome.status === 'success' ? 'INTEGRATION_COMPLETE' : 'ERROR';
  assert.equal(harness.state.flowState, 'INTEGRATION_COMPLETE');
});
