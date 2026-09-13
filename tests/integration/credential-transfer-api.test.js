import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';
import { listenOAuthCallbackServer } from '../support/oauth-callback-test-server.js';

function credential(data) {
  return {
    toJSON() {
      return {
        credentialId: data.credentialId,
        providerKey: data.providerKey,
        externalReference: data.externalReference ?? null,
        lifecycleState: data.lifecycleState ?? 'active',
        secrets: data.secrets ?? [{ name: 'apiKey', type: 'string', value: 'secret', required: true }],
        metadata: data.metadata ?? { displayName: data.credentialId },
        createdAt: data.createdAt ?? '2026-07-09T00:00:00.000Z',
        updatedAt: data.updatedAt ?? '2026-07-09T00:00:00.000Z',
        version: data.version ?? 1
      };
    }
  };
}

function createCredentialManager(credentials) {
  return {
    async listCredentials() {
      return credentials;
    },
    async getCredential(credentialId) {
      return credentials.find((item) => item.toJSON().credentialId === credentialId) ?? null;
    },
    async register(input) {
      const item = credential(input);
      credentials.push(item);
      return item;
    },
    async updateCredential(credentialId, updates) {
      const index = credentials.findIndex((item) => item.toJSON().credentialId === credentialId);
      if (index < 0) throw new Error('Credential not found');
      const current = credentials[index].toJSON();
      credentials[index] = credential({
        ...current,
        ...updates,
        credentialId,
        metadata: { ...(current.metadata ?? {}), ...(updates.metadata ?? {}) },
        version: current.version + 1
      });
      return credentials[index];
    },
    async importCredentialBatch(operations, { onCommitted = null } = {}) {
      const snapshot = [...credentials];
      try {
        for (const operation of operations) {
          if (operation.action === 'create') {
            credentials.push(credential(operation.credential));
            continue;
          }
          const index = credentials.findIndex((item) => item.toJSON().credentialId === operation.targetCredentialId);
          if (index < 0) throw new Error('Credential not found');
          const current = credentials[index].toJSON();
          credentials[index] = credential({
            ...current,
            ...operation.credential,
            credentialId: operation.targetCredentialId,
            version: current.version + 1
          });
        }
        await onCommitted?.({ credentials: [...credentials], operations });
        return { credentials: [...credentials], operations };
      } catch (error) {
        credentials.splice(0, credentials.length, ...snapshot);
        throw error;
      }
    }
  };
}

function createServer(credentials, providerDefinitions = {}) {
  return new OAuthCallbackServer({
    providerManager: {
      getProvider(providerKey) {
        return providerDefinitions[providerKey] ?? { key: providerKey, displayName: providerKey, capabilities: [] };
      }
    },
    importTokenCommand: {},
    credentialManager: createCredentialManager(credentials),
    config: { get() { return 0; } },
    logger: { success() {}, error() {}, info() {} }
  });
}

test('HTTP credential transfer export endpoint returns encrypted transfer payload', async () => {
  const httpServer = createServer([
    credential({ credentialId: 'cred-openai', providerKey: 'openai', externalReference: 'prod' })
  ]);
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credentialIds: ['cred-openai'], encryptionPassword: 'correct horse battery staple' })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.encrypted, true);
    assert.equal(body.data.payload.encrypted, true);
    assert.equal(body.data.payload.format, 'credential-hub-credential-transfer');
    assert.match(body.data.filename, /credential-hub-credentials-.*\.encrypted\.json/);
    assert.equal(body.data.payload.credentials, undefined);
    assert.equal(typeof body.data.content, 'string');
  } finally {
    server.close();
  }
});

test('HTTP credential transfer export rejects a weak password sent directly to the API', async () => {
  const httpServer = createServer([
    credential({ credentialId: 'cred-openai', providerKey: 'openai', externalReference: 'prod' })
  ]);
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credentialIds: ['cred-openai'], encryptionPassword: 'weak' })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.success, false);
    assert.match(body.error.message, /at least 8 characters/);
    assert.equal(body.error.message.includes('weak'), false);
  } finally {
    server.close();
  }
});

test('HTTP credential transfer import preview and import endpoints use transfer service', async () => {
  const credentials = [
    credential({ credentialId: 'cred-existing', providerKey: 'openai', externalReference: 'prod' }),
    credential({ credentialId: 'cred-new', providerKey: 'discord', externalReference: 'bot' })
  ];
  const sourceServer = createServer(credentials);
  const source = await listenOAuthCallbackServer(sourceServer);

  let transfer;
  try {
    const exportResponse = await fetch(`${source.baseUrl}/api/v1/credentials/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ all: true, encryptionPassword: 'safe export password' })
    });
    transfer = (await exportResponse.json()).data.payload;
  } finally {
    source.server.close();
  }

  const targetCredentials = [
    credential({ credentialId: 'cred-existing', providerKey: 'openai', externalReference: 'prod' })
  ];
  const targetServer = createServer(targetCredentials);
  const target = await listenOAuthCallbackServer(targetServer);

  try {
    const previewResponse = await fetch(`${target.baseUrl}/api/v1/credentials/import/preview`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ transfer, encryptionPassword: 'safe export password' })
    });
    const preview = await previewResponse.json();

    assert.equal(previewResponse.status, 200);
    assert.equal(preview.success, true);
    assert.equal(preview.data.summary.total, 2);
    assert.equal(preview.data.summary.conflicts, 1);
    assert.equal(preview.data.summary.create, 1);

    const importResponse = await fetch(`${target.baseUrl}/api/v1/credentials/import`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ transfer, encryptionPassword: 'safe export password', conflictStrategy: 'skip' })
    });
    const imported = await importResponse.json();

    assert.equal(importResponse.status, 200);
    assert.equal(imported.success, true);
    assert.equal(imported.data.summary.requested, 2);
    assert.equal(imported.data.summary.skipped, 1);
    assert.equal(imported.data.summary.created, 1);
    assert.equal(targetCredentials.length, 2);
  } finally {
    target.server.close();
  }
});

test('HTTP credential transfer preview endpoint validates request body', async () => {
  const httpServer = createServer([]);
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/import/preview`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.success, false);
    assert.equal(body.error.code, 'BAD_REQUEST');
    assert.equal(body.error.message, 'transfer payload is required');
  } finally {
    server.close();
  }
});

test('HTTP credential transfer endpoints accept CSV imports for migration', async () => {
  const credentials = [];
  const httpServer = createServer(credentials);
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);
  const csv = [
    'providerKey,externalReference,displayName,apiKey',
    'openai,prod,OpenAI Production,sk-live-123'
  ].join('\n');

  try {
    const previewResponse = await fetch(`${baseUrl}/api/v1/credentials/import/preview`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sourceFormat: 'csv', content: csv })
    });
    const preview = await previewResponse.json();

    assert.equal(previewResponse.status, 200);
    assert.equal(preview.success, true);
    assert.equal(preview.data.sourceFormat, 'csv');
    assert.equal(preview.data.summary.total, 1);
    assert.equal(preview.data.summary.create, 1);

    const importResponse = await fetch(`${baseUrl}/api/v1/credentials/import`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sourceFormat: 'csv', content: csv, conflictStrategy: 'skip' })
    });
    const imported = await importResponse.json();

    assert.equal(importResponse.status, 200);
    assert.equal(imported.success, true);
    assert.equal(imported.data.sourceFormat, 'csv');
    assert.equal(imported.data.summary.created, 1);
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].toJSON().providerKey, 'openai');
    assert.equal(credentials[0].toJSON().secrets[0].value, 'sk-live-123');
  } finally {
    server.close();
  }
});

test('HTTP CSV import applies registered provider field aliases before storing a credential', async () => {
  const credentials = [];
  const httpServer = createServer(credentials, {
    openai: {
      key: 'openai',
      displayName: 'OpenAI',
      capabilities: [],
      credentialFields: [
        { key: 'apiKey', csvAliases: ['api_key'], secret: true },
        { key: 'organizationId', csvAliases: ['organization'], secret: false }
      ]
    }
  });
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);
  const csv = [
    'providerKey,externalReference,api_key,organization',
    'openai,prod,sk-live-123,org-example'
  ].join('\n');

  try {
    const response = await fetch(`${baseUrl}/api/v1/credentials/import`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sourceFormat: 'csv', content: csv })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    const stored = credentials[0].toJSON();
    assert.deepEqual(stored.secrets.map((secret) => secret.name), ['apiKey']);
    assert.equal(stored.secrets[0].value, 'sk-live-123');
    assert.equal(stored.metadata.custom.organizationId, 'org-example');
  } finally {
    server.close();
  }
});
