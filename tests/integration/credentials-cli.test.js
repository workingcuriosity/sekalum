import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const cliScript = path.resolve('src/cli/run-credentials.js');
const testWorkingDirectory = mkdtempSync(path.join(os.tmpdir(), 'credential-hub-cli-'));
const testEncryptionKey = '12345678901234567890123456789012';

test.after(() => {
  rmSync(testWorkingDirectory, { recursive: true, force: true });
});

function runCredentials(args, input = undefined, environment = {}) {
  const {
    TOKEN_ENCRYPTION_KEYS: _ignoredEncryptionKeys,
    TOKEN_ENCRYPTION_KEY_VERSION: _ignoredEncryptionKeyVersion,
    ...testEnvironment
  } = process.env;

  return spawnSync(process.execPath, [cliScript, ...args], {
    cwd: testWorkingDirectory,
    encoding: 'utf8',
    env: {
      ...testEnvironment,
      TOKEN_ENCRYPTION_KEY: testEncryptionKey,
      ...environment,
    },
    input,
    timeout: 10000,
  });
}

function parseOutput(result) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  const jsonStart = output.lastIndexOf('\n{');

  if (jsonStart >= 0) {
    return JSON.parse(output.slice(jsonStart + 1));
  }

  return JSON.parse(output);
}

function uniqueCredentialId(prefix) {
  return `discord:${prefix}-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}

function credentialPayload(credentialId) {
  const accountId = credentialId.split(':')[1];

  return {
    credentialId,
    providerKey: 'discord',
    credentialMethodKey: 'webhook',
    externalReference: accountId,
    secrets: [
      { name: 'webhookUrl', value: `https://discord.example.test/webhooks/${accountId}` }
    ],
    metadata: {
      displayName: 'CLI Test Webhook'
    }
  };
}

function cleanupCredential(credentialId) {
  runCredentials(['delete', credentialId]);
}

test('CLI credentials list returns success response', () => {
  const result = runCredentials(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /"success": true/);
  assert.match(result.stdout, /"data": \[/);
});

test('CLI credentials test environment ignores inherited key-rotation configuration', () => {
  const previousKeys = process.env.TOKEN_ENCRYPTION_KEYS;
  const previousVersion = process.env.TOKEN_ENCRYPTION_KEY_VERSION;

  process.env.TOKEN_ENCRYPTION_KEYS = '{invalid-json';
  process.env.TOKEN_ENCRYPTION_KEY_VERSION = '2';

  try {
    const result = runCredentials(['list']);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    if (previousKeys === undefined) {
      delete process.env.TOKEN_ENCRYPTION_KEYS;
    } else {
      process.env.TOKEN_ENCRYPTION_KEYS = previousKeys;
    }

    if (previousVersion === undefined) {
      delete process.env.TOKEN_ENCRYPTION_KEY_VERSION;
    } else {
      process.env.TOKEN_ENCRYPTION_KEY_VERSION = previousVersion;
    }
  }
});

test('CLI credentials get returns not found for unknown credential', () => {
  const result = runCredentials(['get', 'threads:unknown-account']);

  assert.equal(result.status, 1, result.stdout || result.stderr);
  assert.match(result.stderr, /"success": false/);
  assert.match(result.stderr, /"code": "NOT_FOUND"/);
});

test('CLI credentials create returns created credential', () => {
  const credentialId = uniqueCredentialId('cli-create');
  const payload = credentialPayload(credentialId);

  const result = runCredentials([
    'create',
    '--stdin'
  ], JSON.stringify(payload));

  cleanupCredential(credentialId);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal(response.data.providerKey, 'discord');
  assert.equal(response.data.credentialMethodKey, 'webhook');
  assert.equal('secrets' in response.data, false);
});

test('CLI credentials create accepts an explicit credential method option', () => {
  const credentialId = uniqueCredentialId('cli-method-option');
  const payload = credentialPayload(credentialId);
  delete payload.credentialMethodKey;
  const result = runCredentials(
    ['create', '--stdin', '--credential-method', 'webhook'],
    JSON.stringify(payload),
  );
  cleanupCredential(credentialId);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(parseOutput(result).data.credentialMethodKey, 'webhook');
});

test('CLI credentials create rejects invalid JSON payload', () => {
  const result = runCredentials(['create', '--stdin'], '{invalid-json');

  assert.equal(result.status, 1, result.stdout || result.stderr);
  assert.match(result.stderr, /"success": false/);
  assert.match(result.stderr, /"code": "CLI_ERROR"/);
});

test('CLI credentials malformed secret input does not echo the secret', () => {
  const sentinel = 'PKG01_SENTINEL_SECRET_MALFORMED';
  const result = runCredentials(
    ['create', '--stdin'],
    `{"secrets":[{"name":"apiKey","value":"${sentinel}"}]`,
  );

  assert.equal(result.status, 1);
  assert.doesNotMatch(result.stdout, new RegExp(sentinel));
  assert.doesNotMatch(result.stderr, new RegExp(sentinel));
});

test('CLI credentials rejects positional secret payloads without echoing them', () => {
  const sentinel = 'PKG01_SENTINEL_SECRET_ARGV';
  const payload = credentialPayload(uniqueCredentialId('argv-rejected'));
  payload.secrets[0].value = sentinel;

  const result = runCredentials(['create', JSON.stringify(payload)]);
  const updateResult = runCredentials([
    'update',
    payload.credentialId,
    JSON.stringify({ secrets: payload.secrets })
  ]);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /"code": "CLI_INPUT_REQUIRED"/);
  assert.equal(updateResult.status, 1);
  assert.match(updateResult.stderr, /"code": "CLI_INPUT_REQUIRED"/);
  assert.doesNotMatch(result.stdout, new RegExp(sentinel));
  assert.doesNotMatch(result.stderr, new RegExp(sentinel));
});

test('CLI credentials create via stdin keeps the sentinel out of argv and output', () => {
  const credentialId = uniqueCredentialId('stdin-secret');
  const sentinel = 'PKG01_SENTINEL_SECRET_STDIN';
  const payload = credentialPayload(credentialId);
  payload.secrets[0].value = sentinel;

  const result = runCredentials(['create', '--stdin'], JSON.stringify(payload));
  const updatedSentinel = 'PKG01_SENTINEL_SECRET_STDIN_UPDATED';
  const updateResult = runCredentials(
    ['update', credentialId, '--stdin'],
    JSON.stringify({ secrets: [{ name: 'webhookUrl', value: updatedSentinel }] }),
  );

  const getResult = runCredentials(['get', credentialId]);
  const listResult = runCredentials(['list']);
  const deleteResult = runCredentials(['delete', credentialId]);

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(updateResult.status, 0, updateResult.stderr || updateResult.stdout);
  assert.doesNotMatch(result.stdout, new RegExp(sentinel));
  assert.doesNotMatch(result.stderr, new RegExp(sentinel));
  assert.doesNotMatch(updateResult.stdout, new RegExp(updatedSentinel));
  assert.doesNotMatch(updateResult.stderr, new RegExp(updatedSentinel));
  assert.equal(getResult.status, 0, getResult.stderr || getResult.stdout);
  assert.equal(listResult.status, 0, listResult.stderr || listResult.stdout);
  assert.equal(deleteResult.status, 0, deleteResult.stderr || deleteResult.stdout);
  assert.doesNotMatch(getResult.stdout, new RegExp(sentinel));
  assert.doesNotMatch(listResult.stdout, new RegExp(sentinel));
  assert.doesNotMatch(deleteResult.stdout, new RegExp(sentinel));
  const response = parseOutput(result);
  assert.equal(response.success, true);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal('secrets' in response.data, false);
  assert.deepEqual(response.data.secretNames, ['webhookUrl']);
});

test('CLI credentials accepts a larger stdin payload without echoing it', () => {
  const credentialId = uniqueCredentialId('stdin-large');
  const payload = credentialPayload(credentialId);
  payload.metadata.description = 'x'.repeat(32 * 1024);
  payload.secrets[0].value = 'PKG01_SENTINEL_SECRET_LARGE';

  const result = runCredentials(['create', '--stdin'], JSON.stringify(payload));
  const deleteResult = runCredentials(['delete', credentialId]);

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(deleteResult.status, 0, deleteResult.stderr || deleteResult.stdout);
  assert.doesNotMatch(result.stdout, /PKG01_SENTINEL_SECRET_LARGE/);
  assert.doesNotMatch(result.stderr, /PKG01_SENTINEL_SECRET_LARGE/);
});

test('CLI credentials rejects empty stdin', () => {
  const result = runCredentials(['create', '--stdin'], '');

  assert.equal(result.status, 1);
  assert.match(result.stderr, /"code": "CLI_ERROR"/);
});

test('CLI credentials requires stdin for create and update', () => {
  const credentialId = uniqueCredentialId('input-required');
  const create = runCredentials(['create']);
  const update = runCredentials(['update', credentialId, '--credential-method', 'webhook']);

  assert.equal(create.status, 1);
  assert.match(create.stderr, /"code": "CLI_INPUT_REQUIRED"/);
  assert.equal(update.status, 1);
  assert.match(update.stderr, /"code": "CLI_INPUT_REQUIRED"/);
});

test('CLI credentials update returns updated credential', () => {
  const credentialId = uniqueCredentialId('cli-update');

  const createResult = runCredentials([
    'create',
    '--stdin'
  ], JSON.stringify(credentialPayload(credentialId)));

  assert.equal(createResult.status, 0, createResult.stderr || createResult.stdout);

  const updateResult = runCredentials([
    'update',
    credentialId,
    '--stdin'
  ], JSON.stringify({
      metadata: {
        accountName: 'Updated from CLI'
      }
    }));

  cleanupCredential(credentialId);

  assert.equal(updateResult.status, 0, updateResult.stderr || updateResult.stdout);

  const response = parseOutput(updateResult);
  assert.equal(response.success, true);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal(response.data.version, 2);
});

test('CLI credentials update rejects immutable binding changes without persistence', () => {
  const credentialId = uniqueCredentialId('cli-binding-guard');
  const createResult = runCredentials(['create', '--stdin'], JSON.stringify(credentialPayload(credentialId)));
  assert.equal(createResult.status, 0, createResult.stderr || createResult.stdout);

  const updateResult = runCredentials(
    ['update', credentialId, '--stdin'],
    JSON.stringify({
      externalReference: `${credentialId}-rebound`,
      metadata: { displayName: 'must-not-persist' }
    })
  );
  const getResult = runCredentials(['get', credentialId]);
  cleanupCredential(credentialId);

  assert.equal(updateResult.status, 1, updateResult.stdout || updateResult.stderr);
  const updateResponse = parseOutput(updateResult);
  assert.equal(updateResponse.success, false);
  assert.equal(updateResponse.error.code, 'CREDENTIAL_LIFECYCLE_CONFLICT');
  assert.doesNotMatch(updateResponse.error.message, /rebound/);
  assert.equal(getResult.status, 0, getResult.stderr || getResult.stdout);
  assert.equal(parseOutput(getResult).data.externalReference, credentialId.split(':')[1]);
});

test('CLI credentials delete removes a credential', () => {
  const credentialId = uniqueCredentialId('cli-delete');

  const createResult = runCredentials([
    'create',
    '--stdin'
  ], JSON.stringify(credentialPayload(credentialId)));

  assert.equal(createResult.status, 0, createResult.stderr || createResult.stdout);

  const deleteResult = runCredentials(['delete', credentialId]);

  assert.equal(deleteResult.status, 0, deleteResult.stderr || deleteResult.stdout);

  const response = parseOutput(deleteResult);
  assert.equal(response.success, true);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal(response.data.lifecycleState, 'deleted');

  const getResult = runCredentials(['get', credentialId]);
  assert.equal(getResult.status, 1, getResult.stdout || getResult.stderr);
  assert.match(getResult.stderr, /"code": "NOT_FOUND"/);
});

test('CLI credentials validate executes lifecycle action', () => {
  const credentialId = uniqueCredentialId('cli-validate');
  runCredentials(['create', '--stdin'], JSON.stringify(credentialPayload(credentialId)));

  const result = runCredentials(['validate', credentialId]);

  cleanupCredential(credentialId);

  const response = parseOutput(result);

  if (response.success) {
  assert.equal(result.status, 0);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal('secrets' in response.data, false);
  } else {
  assert.equal(result.status, 1);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'LIFECYCLE_ACTION_FAILED');
}
});

test('CLI credentials refresh executes lifecycle action', () => {
  const credentialId = uniqueCredentialId('cli-refresh');
  runCredentials(['create', '--stdin'], JSON.stringify(credentialPayload(credentialId)));

  const result = runCredentials(['refresh', credentialId]);

  cleanupCredential(credentialId);

  const response = parseOutput(result);

  if (response.success) {
  assert.equal(result.status, 0);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal('secrets' in response.data, false);
  } else {
  assert.equal(result.status, 1);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'LIFECYCLE_ACTION_FAILED');
}
});

test('CLI credentials revoke executes lifecycle action', () => {
  const credentialId = uniqueCredentialId('cli-revoke');
  runCredentials(['create', '--stdin'], JSON.stringify(credentialPayload(credentialId)));

  const result = runCredentials(['revoke', credentialId]);

  cleanupCredential(credentialId);

  const response = parseOutput(result);

  if (response.success) {
  assert.equal(result.status, 0);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal('secrets' in response.data, false);
  } else {
  assert.equal(result.status, 1);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'LIFECYCLE_ACTION_FAILED');
}
});

test('CLI credentials health-check executes lifecycle action', () => {
  const credentialId = uniqueCredentialId('cli-health');
  runCredentials(['create', '--stdin'], JSON.stringify(credentialPayload(credentialId)));

  const result = runCredentials(['health-check', credentialId]);

  cleanupCredential(credentialId);

  const response = parseOutput(result);

  if (response.success) {
  assert.equal(result.status, 0);
  assert.equal(response.data.status, 'ok');
  assert.equal('message' in response.data, false);
  } else {
  assert.equal(result.status, 1);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'LIFECYCLE_ACTION_FAILED');
}
});

test('CLI lifecycle returns NOT_FOUND for unknown credential', () => {
  for (const action of ['validate', 'refresh', 'revoke', 'health-check']) {
    const result = runCredentials([action, 'threads:unknown-account']);

    assert.equal(result.status, 1);

    const response = parseOutput(result);
    assert.equal(response.success, false);
    assert.equal(response.error.code, 'NOT_FOUND');
  }
});
