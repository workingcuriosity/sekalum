import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialTransferService } from '../../src/services/credential-transfer-service.js';
import { Credential } from '../../src/models/credential.js';

function createCredential(overrides = {}) {
  return Credential.from({
    credentialId: 'cred-1',
    providerKey: 'openai',
    externalReference: 'prod',
    lifecycleState: 'registered',
    secrets: [{ name: 'apiKey', value: 'secret-openai-key' }],
    metadata: { displayName: 'OpenAI Production', tags: ['ai'], custom: { type: 'api-key' } },
    createdAt: '2026-07-09T08:00:00.000Z',
    updatedAt: '2026-07-09T08:00:00.000Z',
    version: 1,
    ...overrides
  });
}

function createCredentialManager(initialCredentials = []) {
  const credentials = [...initialCredentials];

  return {
    credentials,
    async listCredentials() {
      return credentials;
    },
    async getCredential(credentialId) {
      return credentials.find((credential) => credential.credentialId === credentialId) ?? null;
    },
    async register(input) {
      const credential = Credential.from(input);
      credentials.push(credential);
      return credential;
    },
    async updateCredential(credentialId, updates) {
      const index = credentials.findIndex((credential) => credential.credentialId === credentialId);
      assert.notEqual(index, -1);
      const existing = credentials[index];
      const updated = Credential.from({
        ...existing.toJSON(),
        ...updates,
        credentialId: existing.credentialId,
        metadata: {
          ...existing.metadata.toJSON(),
          ...(updates.metadata ?? {})
        },
        updatedAt: '2026-07-09T09:00:00.000Z',
        version: existing.version + 1
      });
      credentials[index] = updated;
      return updated;
    }
  };
}

function createAuditLog() {
  const entries = [];
  return {
    entries,
    async record(entry) {
      entries.push(entry);
      return entry;
    }
  };
}

test('CredentialTransferService exports selected credentials in transfer format', async () => {
  const credential = createCredential();
  const auditLogService = createAuditLog();
  const service = new CredentialTransferService({
    credentialManager: createCredentialManager([credential]),
    auditLogService,
    clock: () => new Date('2026-07-09T10:00:00.000Z')
  });

  const result = await service.exportCredentials({ credentialIds: ['cred-1'] }, { userId: 'admin' });
  const payload = JSON.parse(result.content);

  assert.equal(result.filename, 'credential-hub-credentials-2026-07-09T10-00-00-000Z.json');
  assert.equal(payload.format, 'credential-hub-credential-transfer');
  assert.equal(payload.schemaVersion, 1);
  assert.equal(payload.metadata.credentialCount, 1);
  assert.equal(payload.credentials[0].secrets[0].value, 'secret-openai-key');
  assert.equal(auditLogService.entries[0].action, 'credential-export.created');
  assert.equal(auditLogService.entries[0].result, 'success');
});

test('CredentialTransferService previews import conflicts without writing credentials', async () => {
  const existing = createCredential({ credentialId: 'existing-1' });
  const manager = createCredentialManager([existing]);
  const service = new CredentialTransferService({ credentialManager: manager });
  const transfer = {
    format: 'credential-hub-credential-transfer',
    schemaVersion: 1,
    generatedAt: '2026-07-09T10:00:00.000Z',
    metadata: { credentialCount: 1 },
    credentials: [createCredential({ credentialId: 'incoming-1' }).toJSON()]
  };

  const preview = await service.previewImport(transfer);

  assert.equal(preview.summary.total, 1);
  assert.equal(preview.summary.conflicts, 1);
  assert.equal(preview.items[0].conflict.type, 'providerExternalReference');
  assert.equal(manager.credentials.length, 1);
});

test('CredentialTransferService imports new credentials and skips conflicts by default', async () => {
  const existing = createCredential({ credentialId: 'cred-1' });
  const manager = createCredentialManager([existing]);
  const service = new CredentialTransferService({ credentialManager: manager });
  const transfer = {
    format: 'credential-hub-credential-transfer',
    schemaVersion: 1,
    generatedAt: '2026-07-09T10:00:00.000Z',
    metadata: { credentialCount: 2 },
    credentials: [
      createCredential({ credentialId: 'cred-1' }).toJSON(),
      createCredential({ credentialId: 'cred-2', externalReference: 'dev', metadata: { displayName: 'OpenAI Dev' } }).toJSON()
    ]
  };

  const result = await service.importCredentials(JSON.stringify(transfer));

  assert.equal(result.summary.created, 1);
  assert.equal(result.summary.skipped, 1);
  assert.equal(manager.credentials.length, 2);
  assert.equal(manager.credentials.find((credential) => credential.credentialId === 'cred-2').externalReference, 'dev');
});

test('CredentialTransferService overwrites conflicting credentials when requested', async () => {
  const existing = createCredential({
    credentialId: 'existing-1',
    secrets: [{ name: 'apiKey', value: 'old-secret' }]
  });
  const manager = createCredentialManager([existing]);
  const service = new CredentialTransferService({ credentialManager: manager });
  const transfer = {
    format: 'credential-hub-credential-transfer',
    schemaVersion: 1,
    generatedAt: '2026-07-09T10:00:00.000Z',
    metadata: { credentialCount: 1 },
    credentials: [createCredential({ credentialId: 'incoming-1', secrets: [{ name: 'apiKey', value: 'new-secret' }] }).toJSON()]
  };

  const result = await service.importCredentials(transfer, { conflictStrategy: 'overwrite' });

  assert.equal(result.summary.overwritten, 1);
  assert.equal(manager.credentials.length, 1);
  assert.equal(manager.credentials[0].credentialId, 'existing-1');
  assert.equal(manager.credentials[0].secrets[0].value, 'new-secret');
});

test('CredentialTransferService renames conflicting credentials when requested', async () => {
  const existing = createCredential({ credentialId: 'existing-1' });
  const manager = createCredentialManager([existing]);
  const service = new CredentialTransferService({
    credentialManager: manager,
    clock: () => new Date('2026-07-09T10:00:00.000Z'),
    idGenerator: () => 'renamed-1'
  });
  const transfer = {
    format: 'credential-hub-credential-transfer',
    schemaVersion: 1,
    generatedAt: '2026-07-09T10:00:00.000Z',
    metadata: { credentialCount: 1 },
    credentials: [createCredential({ credentialId: 'incoming-1' }).toJSON()]
  };

  const result = await service.importCredentials(transfer, { conflictStrategy: 'rename' });

  assert.equal(result.summary.renamed, 1);
  assert.equal(manager.credentials.length, 2);
  assert.equal(manager.credentials[1].credentialId, 'renamed-1');
  assert.equal(manager.credentials[1].externalReference, 'prod-imported-2026-07-09T10-00-00-000Z');
});

test('CredentialTransferService rejects invalid transfer payloads and conflict strategies', async () => {
  const service = new CredentialTransferService({ credentialManager: createCredentialManager() });

  await assert.rejects(() => service.previewImport({ format: 'wrong', schemaVersion: 1, credentials: [] }), /transfer payload format/);
  await assert.rejects(() => service.importCredentials({ format: 'credential-hub-credential-transfer', schemaVersion: 1, credentials: [] }, { conflictStrategy: 'merge' }), /conflictStrategy must be one of/);
  await assert.rejects(() => service.exportCredentials({ credentialIds: [] }), /credentialIds must contain/);
});

test('CredentialTransferService exports encrypted transfer envelopes when a password is supplied', async () => {
  const credential = createCredential();
  const service = new CredentialTransferService({
    credentialManager: createCredentialManager([credential]),
    clock: () => new Date('2026-07-09T10:00:00.000Z')
  });

  const result = await service.exportCredentials({ credentialIds: ['cred-1'], password: 'safe export password' });
  const envelope = JSON.parse(result.content);

  assert.equal(result.encrypted, true);
  assert.equal(result.filename, 'credential-hub-credentials-2026-07-09T10-00-00-000Z.encrypted.json');
  assert.equal(envelope.format, 'credential-hub-credential-transfer');
  assert.equal(envelope.encrypted, true);
  assert.equal(envelope.encryption.algorithm, 'aes-256-gcm');
  assert.equal(envelope.encryption.kdf, 'pbkdf2');
  assert.equal(envelope.encryption.digest, 'sha256');
  assert.ok(envelope.encryption.iterations >= 100000);
  assert.ok(envelope.ciphertext);
  assert.equal(envelope.credentials, undefined);
  assert.equal(result.content.includes('secret-openai-key'), false);
});

test('CredentialTransferService previews encrypted transfers with the correct password', async () => {
  const credential = createCredential();
  const service = new CredentialTransferService({
    credentialManager: createCredentialManager([credential]),
    clock: () => new Date('2026-07-09T10:00:00.000Z')
  });
  const encryptedExport = await service.exportCredentials({ credentialIds: ['cred-1'], password: 'safe export password' });
  const importService = new CredentialTransferService({ credentialManager: createCredentialManager() });

  const preview = await importService.previewImport(encryptedExport.content, { password: 'safe export password' });

  assert.equal(preview.summary.total, 1);
  assert.equal(preview.summary.create, 1);
});

test('CredentialTransferService imports encrypted transfers with the correct password', async () => {
  const credential = createCredential();
  const service = new CredentialTransferService({
    credentialManager: createCredentialManager([credential]),
    clock: () => new Date('2026-07-09T10:00:00.000Z')
  });
  const encryptedExport = await service.exportCredentials({ credentialIds: ['cred-1'], password: 'safe export password' });
  const manager = createCredentialManager();
  const importService = new CredentialTransferService({ credentialManager: manager });

  const result = await importService.importCredentials(encryptedExport.content, { password: 'safe export password' });

  assert.equal(result.summary.created, 1);
  assert.equal(manager.credentials.length, 1);
  assert.equal(manager.credentials[0].secrets[0].value, 'secret-openai-key');
});

test('CredentialTransferService rejects encrypted transfers with missing, wrong, or tampered password data', async () => {
  const credential = createCredential();
  const service = new CredentialTransferService({
    credentialManager: createCredentialManager([credential]),
    clock: () => new Date('2026-07-09T10:00:00.000Z')
  });
  const encryptedExport = await service.exportCredentials({ credentialIds: ['cred-1'], password: 'safe export password' });
  const importService = new CredentialTransferService({ credentialManager: createCredentialManager() });

  await assert.rejects(() => importService.previewImport(encryptedExport.content), /requires an import password/);
  await assert.rejects(() => importService.previewImport(encryptedExport.content, { password: 'wrong password' }), /could not be decrypted/);

  const tampered = JSON.parse(encryptedExport.content);
  tampered.ciphertext = tampered.ciphertext.replace(/.$/, tampered.ciphertext.endsWith('A') ? 'B' : 'A');
  await assert.rejects(() => importService.previewImport(tampered, { password: 'safe export password' }), /could not be decrypted/);
});

test('CredentialTransferService previews CSV credential imports with dynamic secret columns', async () => {
  const service = new CredentialTransferService({
    credentialManager: createCredentialManager(),
    clock: () => new Date('2026-07-09T10:00:00.000Z'),
    idGenerator: () => 'csv-cred-1'
  });
  const csv = [
    'providerKey,externalReference,displayName,secret.apiKey,tags,description',
    'openai,prod,OpenAI Production,sk-live-123,ai;prod,Imported from n8n inventory'
  ].join('\n');

  const preview = await service.previewCsvImport(csv);

  assert.equal(preview.sourceFormat, 'csv');
  assert.equal(preview.summary.total, 1);
  assert.equal(preview.summary.create, 1);
  assert.equal(preview.items[0].providerKey, 'openai');
  assert.equal(preview.items[0].displayName, 'OpenAI Production');
  assert.deepEqual(preview.csv.headers, ['providerKey', 'externalReference', 'displayName', 'secret.apiKey', 'tags', 'description']);
});

test('CredentialTransferService imports CSV credentials through the existing conflict workflow', async () => {
  const manager = createCredentialManager([
    createCredential({ credentialId: 'existing-1', providerKey: 'openai', externalReference: 'prod' })
  ]);
  const service = new CredentialTransferService({
    credentialManager: manager,
    clock: () => new Date('2026-07-09T10:00:00.000Z'),
    idGenerator: () => 'csv-cred-1'
  });
  const csv = [
    'providerKey,externalReference,displayName,apiKey',
    'openai,prod,OpenAI Production,new-secret',
    'discord,bot,Discord Bot,discord-secret'
  ].join('\n');

  const result = await service.importCsvCredentials(csv, { conflictStrategy: 'skip' });

  assert.equal(result.sourceFormat, 'csv');
  assert.equal(result.summary.requested, 2);
  assert.equal(result.summary.skipped, 1);
  assert.equal(result.summary.created, 1);
  assert.equal(manager.credentials.length, 2);
  assert.equal(manager.credentials[1].providerKey, 'discord');
  assert.equal(manager.credentials[1].secrets[0].name, 'apiKey');
  assert.equal(manager.credentials[1].secrets[0].value, 'discord-secret');
});

test('CredentialTransferService maps provider CSV aliases before preview and import', async () => {
  const manager = createCredentialManager();
  const service = new CredentialTransferService({
    credentialManager: manager,
    providerManager: {
      getProvider(providerKey) {
        assert.equal(providerKey, 'openai');
        return {
          key: 'openai',
          credentialMethods: [{
            key: 'api-key', credentialFields: [
              { key: 'displayName', csvAliases: ['credential_name'], secret: false },
              { key: 'apiKey', csvAliases: ['api_key'], secret: true },
              { key: 'organizationId', csvAliases: ['organization'], secret: false }
            ]
          }],
          providerMethodBindings: [{ methodKey: 'api-key' }]
        };
      }
    },
    clock: () => new Date('2026-07-09T10:00:00.000Z'),
    idGenerator: () => 'csv-alias-credential'
  });
  const csv = [
    'providerKey,credentialMethodKey,externalReference,credential_name,api_key,organization',
    'openai,api-key,production,OpenAI Production,secret-key,org-example'
  ].join('\n');

  const preview = await service.previewCsvImport(csv);
  assert.deepEqual(preview.csv.mappings, [{
    rowNumber: 2,
    providerKey: 'openai',
    fields: [
      { source: 'credential_name', target: 'displayName' },
      { source: 'api_key', target: 'apiKey' },
      { source: 'organization', target: 'organizationId' }
    ]
  }]);

  const result = await service.importCsvCredentials(csv);
  assert.equal(result.summary.created, 1);
  assert.deepEqual(manager.credentials[0].toJSON().secrets.map((secret) => secret.name), ['apiKey']);
  assert.equal(manager.credentials[0].toJSON().metadata.custom.organizationId, 'org-example');
});

test('CredentialTransferService rejects missing and unavailable credential methods for method-based CSV providers', async () => {
  const providerManager = {
    getProvider() {
      return {
        key: 'example',
        credentialMethods: [{ key: 'webhook', credentialFields: [{ key: 'signingSecret', secret: true, csvAliases: ['signature'] }] }],
        providerMethodBindings: [{ methodKey: 'webhook' }]
      };
    }
  };
  const service = new CredentialTransferService({ credentialManager: createCredentialManager(), providerManager });

  await assert.rejects(
    () => service.previewCsvImport('providerKey,externalReference,secret.signingSecret\nexample,main,secret'),
    /requires credentialMethodKey/
  );
  await assert.rejects(
    () => service.previewCsvImport('providerKey,credentialMethodKey,externalReference,secret.signingSecret\nexample,api-key,main,secret'),
    /is not available/
  );
});

test('CredentialTransferService rejects CSV imports with missing required headers or secrets', async () => {
  const service = new CredentialTransferService({ credentialManager: createCredentialManager() });

  await assert.rejects(() => service.previewCsvImport('providerKey,apiKey\nopenai,secret'), /requires header 'externalReference'/);
  await assert.rejects(() => service.previewCsvImport('providerKey,externalReference\nopenai,prod'), /requires at least one secret column/);
  await assert.rejects(() => service.previewCsvImport('providerKey,externalReference,apiKey\nopenai,prod,'), /requires at least one non-empty secret value/);
});

test('CredentialTransferService canonicalizes aliased secret columns and rejects ambiguous provider aliases', async () => {
  const canonicalProviderManager = {
    getProvider(providerKey) {
      if (providerKey === 'openai') {
        return {
          credentialFields: [
            { key: 'apiKey', csvAliases: ['api_key'], secret: true }
          ]
        };
      }
      return null;
    }
  };
  const manager = createCredentialManager();
  const service = new CredentialTransferService({ providerManager: canonicalProviderManager, credentialManager: manager });

  await service.importCsvCredentials([
    'providerKey,externalReference,api_key',
    'openai,prod,secret-key'
  ].join('\n'));
  assert.deepEqual(manager.credentials[0].toJSON().secrets.map((secret) => secret.name), ['apiKey']);

  const ambiguousService = new CredentialTransferService({
    credentialManager: createCredentialManager(),
    providerManager: {
      getProvider() {
        return {
          credentialFields: [
            { key: 'secondaryApiKey', csvAliases: ['shared_key'], secret: true },
            { key: 'primaryApiKey', csvAliases: ['shared_key'], secret: true }
          ]
        };
      }
    }
  });
  await assert.rejects(
    () => ambiguousService.previewCsvImport('providerKey,externalReference,shared_key\nopenai,other,secret'),
    /ambiguous field alias 'shared_key'/
  );
});

test('CredentialTransferService rejects CSV rows for an unknown provider when a provider registry is available', async () => {
  const service = new CredentialTransferService({
    credentialManager: createCredentialManager(),
    providerManager: { getProvider() { return null; } }
  });

  await assert.rejects(
    () => service.previewCsvImport('providerKey,externalReference,apiKey\nunknown,prod,secret'),
    /CSV provider 'unknown' is not registered/
  );
});
