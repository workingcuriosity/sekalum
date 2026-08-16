import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';
import { CredentialManager } from '../../src/managers/credential-manager.js';
import { CredentialStore } from '../../src/storage/credential-store.js';
import { CredentialCollectionStoreAdapter } from '../../src/storage/credential-collection-store-adapter.js';
import { EncryptedJsonStore } from '../../src/storage/encrypted-json-store.js';
import { JsonStore } from '../../src/storage/json-store.js';
import { connectionCredentialFields } from '../../src/providers/credential-field-sets.js';

const openAiFields = [
  { key: 'displayName', label: 'Display name', type: 'text', required: true, secret: false },
  { key: 'apiKey', label: 'API key', type: 'api-key', required: true, secret: true, validation: { minLength: 20 } }
];

function config() {
  return {
    get(key, fallback = null) { if (key === 'BASE_PATH') return '/'; if (key === 'TOKEN_ENCRYPTION_KEY_VERSION') return 1; return fallback; },
    require(key) { if (key === 'TOKEN_ENCRYPTION_KEY') return '0123456789abcdef0123456789abcdef'; throw new Error(`Missing ${key}`); }
  };
}

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}` }));
  });
}

test('credential creation persists API-key and connection credentials and returns them to the Dashboard API', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-hub-flow-'));
  const secureStore = new EncryptedJsonStore({ jsonStore: new JsonStore(), config: config() });
  const credentialStore = new CredentialStore({ storageAdapter: new CredentialCollectionStoreAdapter({ jsonStore: secureStore, basePath: directory }) });
  const providerMap = {
    openai: { key: 'openai', displayName: 'OpenAI API Key', capabilities: ['validation'], credentialFields: openAiFields },
    ftp: { key: 'ftp', displayName: 'FTP Credentials', capabilities: ['validation'], credentialFields: connectionCredentialFields({ defaultPort: 21 }) },
    sftp: { key: 'sftp', displayName: 'SFTP Credentials', capabilities: ['validation'], credentialFields: connectionCredentialFields({ defaultPort: 22 }) }
  };
  const providerManager = {
    getProvider(key) { if (providerMap[key]) return providerMap[key]; const error = new Error('not found'); error.code = 'NOT_FOUND'; throw error; },
    listProviders() { return Object.values(providerMap); }
  };
  const manager = new CredentialManager({ credentialStore, providerManager });
  const httpServer = new OAuthCallbackServer({
    providerManager,
    importTokenCommand: {},
    credentialManager: manager,
    config: config(),
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  const cases = [
    { providerKey: 'openai', externalReference: 'openai-main', metadata: { displayName: 'OpenAI Main', type: 'api-key' }, secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }] },
    { providerKey: 'ftp', externalReference: 'ftp-main', metadata: { displayName: 'FTP Main', type: 'connection', custom: { port: 21 } }, secrets: [{ name: 'host', value: 'ftp.example.com' }, { name: 'username', value: 'example-user' }, { name: 'password', value: 'example-password' }] },
    { providerKey: 'sftp', externalReference: 'sftp-main', metadata: { displayName: 'SFTP Main', type: 'connection', custom: { port: 22 } }, secrets: [{ name: 'host', value: 'sftp.example.com' }, { name: 'username', value: 'example-user' }, { name: 'password', value: 'example-password' }] }
  ];

  try {
    for (const credential of cases) {
      const response = await fetch(`${baseUrl}/api/v1/credentials`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(credential) });
      const body = await response.json();
      assert.equal(response.status, 201, JSON.stringify(body));
      assert.equal(body.success, true);
      assert.equal(body.data.providerKey, credential.providerKey);
      assert.equal('secrets' in body.data, false);
      assert.ok(body.data.secretInventory.every((secret) => secret.valueMasked === '********'));
    }

    const dashboardResponse = await fetch(`${baseUrl}/api/v1/credentials`);
    const dashboardBody = await dashboardResponse.json();
    assert.deepEqual(dashboardBody.data.map((credential) => credential.providerKey).sort(), ['ftp', 'openai', 'sftp']);
    assert.equal(JSON.stringify(dashboardBody).includes('sk-example'), false);
    assert.equal(JSON.stringify(dashboardBody).includes('example-password'), false);

    const raw = await fs.readFile(path.join(directory, 'credentials.json'), 'utf8');
    assert.match(raw, /credential-hub-encrypted-json/);
    assert.doesNotMatch(raw, /sk-example|example-password|ftp\.example\.com/);
  } finally {
    server.close();
  }
});
