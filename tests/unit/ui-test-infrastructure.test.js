import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanupFixtures, createFixtureState, resetFixtures, seedFixtures } from '../../scripts/ui-test-fixtures.mjs';
import { evidenceRecord, redactEvidence } from '../../scripts/ui-evidence-tools.mjs';

test('UI fixture seed and reset use only the dedicated test namespace', async () => {
  try {
    const state = await seedFixtures();
    assert.equal(state.fixture_namespace, 'credential-hub-ui-test');
    assert.match(state.admin.id, /^ui-test-/);
    await resetFixtures();
  } finally {
    await cleanupFixtures();
  }
});

test('evidence redaction removes tokens, authorization headers, cookies and secret-like fields', () => {
  const redacted = redactEvidence({ authorization: 'Bearer very-secret-token', cookie: 'session=abc', apiKey: 'key-value', nested: { refreshToken: 'refresh-value' }, message: 'access_token=visible-value Bearer visible-bearer' });
  assert.deepEqual(redacted, { authorization: '[REDACTED]', cookie: '[REDACTED]', apiKey: '[REDACTED]', nested: { refreshToken: '[REDACTED]' }, message: 'access_token=[REDACTED] Bearer [REDACTED]' });
  assert.doesNotMatch(JSON.stringify(evidenceRecord({ test_id: 'UI-REDACTION', result: 'PASSED', details: { token: 'never-leak' } })), /never-leak/);
});

test('fixture objects are deterministic and clearly non-production', () => {
  const state = createFixtureState();
  assert.equal(state.credential.credentialKey, 'ui-test-credential-key');
  assert.equal(state.grant.consumerId, state.consumer.id);
});
