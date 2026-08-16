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

function runCredentials(args) {
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
    },
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

  const result = runCredentials([
    'create',
    JSON.stringify(credentialPayload(credentialId))
  ]);

  cleanupCredential(credentialId);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal(response.data.providerKey, 'discord');
  assert.equal(response.data.credentialMethodKey, 'webhook');
});

test('CLI credentials create accepts an explicit credential method option', () => {
  const credentialId = uniqueCredentialId('cli-method-option');
  const payload = credentialPayload(credentialId);
  delete payload.credentialMethodKey;
  const result = runCredentials(['create', JSON.stringify(payload), '--credential-method', 'webhook']);
  cleanupCredential(credentialId);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(parseOutput(result).data.credentialMethodKey, 'webhook');
});

test('CLI credentials create rejects invalid JSON payload', () => {
  const result = runCredentials(['create', '{invalid-json']);

  assert.equal(result.status, 1, result.stdout || result.stderr);
  assert.match(result.stderr, /"success": false/);
  assert.match(result.stderr, /"code": "CLI_ERROR"/);
});

test('CLI credentials update returns updated credential', () => {
  const credentialId = uniqueCredentialId('cli-update');

  const createResult = runCredentials([
    'create',
    JSON.stringify(credentialPayload(credentialId))
  ]);

  assert.equal(createResult.status, 0, createResult.stderr || createResult.stdout);

  const updateResult = runCredentials([
    'update',
    credentialId,
    JSON.stringify({
      metadata: {
        accountName: 'Updated from CLI'
      }
    })
  ]);

  cleanupCredential(credentialId);

  assert.equal(updateResult.status, 0, updateResult.stderr || updateResult.stdout);

  const response = parseOutput(updateResult);
  assert.equal(response.success, true);
  assert.equal(response.data.credentialId, credentialId);
  assert.equal(response.data.version, 2);
});

test('CLI credentials delete removes a credential', () => {
  const credentialId = uniqueCredentialId('cli-delete');

  const createResult = runCredentials([
    'create',
    JSON.stringify(credentialPayload(credentialId))
  ]);

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
  runCredentials(['create', JSON.stringify(credentialPayload(credentialId))]);

  const result = runCredentials(['validate', credentialId]);

  cleanupCredential(credentialId);

  const response = parseOutput(result);

if (response.success) {
  assert.equal(result.status, 0);
  assert.equal(response.data.credentialId, credentialId);
} else {
  assert.equal(result.status, 1);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'LIFECYCLE_ACTION_FAILED');
}
});

test('CLI credentials refresh executes lifecycle action', () => {
  const credentialId = uniqueCredentialId('cli-refresh');
  runCredentials(['create', JSON.stringify(credentialPayload(credentialId))]);

  const result = runCredentials(['refresh', credentialId]);

  cleanupCredential(credentialId);

  const response = parseOutput(result);

if (response.success) {
  assert.equal(result.status, 0);
  assert.equal(response.data.credentialId, credentialId);
} else {
  assert.equal(result.status, 1);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'LIFECYCLE_ACTION_FAILED');
}
});

test('CLI credentials revoke executes lifecycle action', () => {
  const credentialId = uniqueCredentialId('cli-revoke');
  runCredentials(['create', JSON.stringify(credentialPayload(credentialId))]);

  const result = runCredentials(['revoke', credentialId]);

  cleanupCredential(credentialId);

  const response = parseOutput(result);

if (response.success) {
  assert.equal(result.status, 0);
  assert.equal(response.data.credentialId, credentialId);
} else {
  assert.equal(result.status, 1);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'LIFECYCLE_ACTION_FAILED');
}
});

test('CLI credentials health-check executes lifecycle action', () => {
  const credentialId = uniqueCredentialId('cli-health');
  runCredentials(['create', JSON.stringify(credentialPayload(credentialId))]);

  const result = runCredentials(['health-check', credentialId]);

  cleanupCredential(credentialId);

  const response = parseOutput(result);

if (response.success) {
  assert.equal(result.status, 0);
  assert.equal(response.data.credentialId, credentialId);
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
