import test from 'node:test';
import assert from 'node:assert/strict';

import { ConsumerCredentialService } from '../../src/services/consumer-credential-service.js';
import { resolveDiagnostic, ResolveDiagnosticCode } from '../../src/services/resolve-diagnostics.js';
import { Credential } from '../../src/models/credential.js';

function setup({ lifecycleState = 'active', grantNames = ['apiKey', 'secondaryKey'], credentialMethodKey = 'api-key', credentialManager = null, runtimePublicProjectionService = null, findGrantResult = undefined, expiresAt = null, metadata = {}, auditLogService = null, credentialStore = null } = {}) {
  const secretValue = 'consumer-test-secret';
  const credential = new Credential({
    credentialId: 'credential-1', providerKey: 'example', credentialMethodKey, lifecycleState,
    secrets: [{ name: 'apiKey', value: secretValue }, { name: 'secondaryKey', value: 'second-secret' }],
    metadata: { expiresAt, ...metadata }
  });
  let currentCredential = credential;
  const audit = [];
  const findGrantCalls = [];
  const service = new ConsumerCredentialService({
    credentialStore: credentialStore ?? { async load(id) { if (id !== currentCredential.credentialId) { const e = new Error('missing'); e.code = 'NOT_FOUND'; throw e; } return currentCredential; } },
    consumerGrantService: {
      async findGrant(input) {
        findGrantCalls.push(input);
        return findGrantResult === undefined
          ? { consumerId: input.consumerId, credentialId: credential.credentialId, providerKey: credential.providerKey, secretNames: grantNames }
          : findGrantResult;
      },
      async listGrants() { return [{ credentialId: credential.credentialId, providerKey: credential.providerKey }]; }
    },
    credentialManager: credentialManager ? {
      async refreshIfDue(value) {
        currentCredential = await credentialManager.refreshIfDue(value);
        return currentCredential;
      }
    } : null,
    runtimePublicProjectionService,
    providerRegistry: { get() { return {
      getCredentialMethod(key) {
        if (key !== 'api-key') return null;
        return { credentialFields: [{ key: 'apiKey', secret: true }, { key: 'secondaryKey', secret: true }, { key: 'name', secret: false }] };
      },
      getProviderMethodBinding(key) { return key === 'api-key' ? { methodKey: key } : null; }
    }; } },
    auditLogService: auditLogService ?? { async record(entry) { audit.push(entry); } }
  });
  return { service, audit, secretValue, findGrantCalls };
}

test('consumer success audit is emitted only after the final authorization and lifecycle check', async () => {
  const events = [];
  const audit = [];
  const { service } = setup({
    credentialStore: {
      async load(id) {
        events.push(`credential-load:${id}`);
        return new Credential({
          credentialId: 'credential-1', providerKey: 'example', credentialMethodKey: 'api-key', lifecycleState: 'active',
          secrets: [{ name: 'apiKey', value: 'consumer-test-secret' }]
        });
      }
    },
    auditLogService: { async record(entry) { events.push(`audit:${entry.result}`); audit.push(entry); } }
  });
  const originalFindGrant = service.consumerGrantService.findGrant;
  service.consumerGrantService.findGrant = async (input) => {
    events.push('grant-check');
    return originalFindGrant(input);
  };

  await service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] });
  assert.equal(events.at(-1), 'audit:success');
  assert.equal(events.filter((event) => event === 'audit:success').length, 1);
  assert.ok(events.lastIndexOf('grant-check') < events.lastIndexOf('audit:success'));
  assert.equal(audit[0].result, 'success');
});

test('consumer final lifecycle failure produces no success audit', async () => {
  let loads = 0;
  const active = new Credential({
    credentialId: 'credential-1', providerKey: 'example', credentialMethodKey: 'api-key', lifecycleState: 'active',
    secrets: [{ name: 'apiKey', value: 'consumer-test-secret' }]
  });
  const revoked = new Credential({ ...active.toJSON(), lifecycleState: 'revoked' });
  const { service, audit } = setup({
    credentialStore: {
      async load() { loads += 1; return loads === 1 ? active : revoked; }
    }
  });

  await assert.rejects(
    () => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] }),
    { code: 'CREDENTIAL_NOT_CONSUMABLE' }
  );
  assert.equal(audit.some((entry) => entry.result === 'success'), false);
  assert.equal(audit.filter((entry) => entry.result === 'failure').length, 1);
});

test('consumer audit persistence failure fails closed without delivering or exposing secrets', async () => {
  const audit = [];
  const secret = 'consumer-audit-failure-secret';
  const { service } = setup({
    auditLogService: {
      async record(entry) {
        if (entry.result === 'success') throw new Error(`audit store unavailable: ${secret}`);
        audit.push(entry);
      }
    }
  });

  await assert.rejects(
    () => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] }),
    (error) => {
      assert.equal(error.code, 'INTERNAL_ERROR');
      assert.equal(error.message, 'Credential resolution could not be completed');
      assert.doesNotMatch(error.message, new RegExp(secret));
      return true;
    }
  );
  assert.equal(audit.some((entry) => entry.result === 'success'), false);
  assert.equal(JSON.stringify(audit).includes(secret), false);
});

test('consumer resolves only explicitly requested and granted secret fields', async () => {
  const { service, audit, secretValue } = setup();
  const result = await service.resolve({ consumerId: 'consumer-a', apiTokenId: 'token-a', credentialKey: 'credential-1', secretNames: ['apiKey'] });
  assert.deepEqual(result.secrets, { apiKey: secretValue });
  assert.equal(result.providerKey, 'example');
  assert.equal(result.credentialMethodKey, undefined);
  assert.equal(result.credentialKey, 'credential-1');
  assert.deepEqual(Object.keys(result).sort(), ['credentialKey', 'lifecycleState', 'providerKey', 'secrets']);
  assert.equal(audit[0].result, 'success');
  assert.equal(audit[0].actorType, 'consumer');
  assert.equal(audit[0].userId, null);
  assert.equal(audit[0].consumerId, 'consumer-a');
  assert.equal(audit[0].apiTokenId, 'token-a');
  assert.equal(JSON.stringify(audit[0]).includes(secretValue), false);
});

test('consumer derives its secret contract from the selected credential method, not provider fields', async () => {
  const { service } = setup({ grantNames: ['name'] });
  await assert.rejects(
    () => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['name'] }),
    { code: 'CONSUMER_ACCESS_DENIED' }
  );

  const missingMethod = setup({ credentialMethodKey: null });
  await assert.rejects(
    () => missingMethod.service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] }),
    { code: 'CONSUMER_ACCESS_DENIED' }
  );
});

test('consumer denies ungranted fields and non-active credentials without auditing secrets', async () => {
  const { service, audit, secretValue } = setup({ grantNames: ['apiKey'] });
  await assert.rejects(() => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['secondaryKey'] }), { code: 'SECRET_NOT_GRANTED' });
  assert.equal(audit[0].result, 'failure');
  assert.equal(JSON.stringify(audit[0]).includes(secretValue), false);

  const inactive = setup({ lifecycleState: 'revoked' });
  await assert.rejects(() => inactive.service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] }), { code: 'CREDENTIAL_NOT_CONSUMABLE' });
});

test('consumer resolves a credential after the existing manager refreshes it when due', async () => {
  const { service, secretValue } = setup({
    credentialManager: {
      async refreshIfDue(credential) {
        assert.equal(credential.credentialId, 'credential-1');
        return new Credential({
          ...credential.toJSON(),
          secrets: [{ name: 'apiKey', value: `${secretValue}-refreshed` }, { name: 'secondaryKey', value: 'second-secret' }]
        });
      }
    }
  });

  const result = await service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] });

  assert.deepEqual(result.secrets, { apiKey: `${secretValue}-refreshed` });
});

test('consumer rejects malformed requests and unknown credentials', async () => {
  const { service } = setup();
  await assert.rejects(() => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: [] }), { code: 'INVALID_SECRET_REQUEST' });
  await assert.rejects(() => service.resolve({ consumerId: 'consumer-a', credentialKey: 'missing', secretNames: ['apiKey'] }), { code: 'CREDENTIAL_NOT_FOUND' });
});

test('consumer normalizes every inaccessible pre-grant diagnostic to one public contract', () => {
  const publicErrors = [
    ResolveDiagnosticCode.CREDENTIAL_NOT_FOUND,
    ResolveDiagnosticCode.CREDENTIAL_NOT_CONSUMABLE,
    ResolveDiagnosticCode.CREDENTIAL_DISABLED,
    ResolveDiagnosticCode.GRANT_MISSING,
    ResolveDiagnosticCode.SECRET_NOT_GRANTED,
    'CONSUMER_ACCESS_DENIED'
  ].map((code) => resolveDiagnostic(code, { publicResponse: true }));

  assert.deepEqual(new Set(publicErrors.map((error) => JSON.stringify(error))), new Set([
    JSON.stringify({ code: ResolveDiagnosticCode.NOT_AVAILABLE, statusCode: 403, message: 'The requested credential is not available to this consumer' })
  ]));
});

test('consumer batch Resolve keeps inaccessible revoked and missing targets indistinguishable', async () => {
  const { service } = setup({ lifecycleState: 'revoked' });
  const result = await service.batchResolve({
    consumerId: 'consumer-a',
    requests: [
      { credentialKey: 'credential-1', secretNames: ['apiKey'] },
      { credentialKey: 'missing', secretNames: ['apiKey'] }
    ]
  });

  assert.deepEqual(result.results.map(({ error }) => error), [
    { code: ResolveDiagnosticCode.NOT_AVAILABLE, message: 'The requested credential is not available to this consumer' },
    { code: ResolveDiagnosticCode.NOT_AVAILABLE, message: 'The requested credential is not available to this consumer' }
  ]);
});

test('consumer batch Resolve isolates per-entry success and failure through the existing Resolve path', async () => {
  const { service, audit, secretValue } = setup({ grantNames: ['apiKey'] });
  const result = await service.batchResolve({
    consumerId: 'consumer-a',
    apiTokenId: 'token-a',
    requests: [
      { credentialKey: 'credential-1', secretNames: ['apiKey'] },
      { credentialKey: 'credential-1', secretNames: ['secondaryKey'] },
      { credentialKey: 'missing', secretNames: ['apiKey'] }
    ]
  });

  assert.deepEqual(result.summary, { total: 3, succeeded: 1, failed: 2 });
  assert.deepEqual(result.results[0].data.secrets, { apiKey: secretValue });
  assert.deepEqual(result.results.slice(1).map(({ success, error }) => ({ success, code: error.code })), [
    { success: false, code: 'RESOLVE_NOT_AVAILABLE' },
    { success: false, code: 'RESOLVE_NOT_AVAILABLE' }
  ]);
  assert.equal(JSON.stringify(result).includes('consumer-test-secret'), true);
  assert.equal(JSON.stringify(result.results.slice(1)).includes('consumer-test-secret'), false);
  assert.equal(audit.length, 3);
});

test('consumer batch Resolve validates the envelope and enforces a bounded request count', async () => {
  const { service } = setup();
  await assert.rejects(() => service.batchResolve({ consumerId: 'consumer-a', requests: [] }), { code: 'INVALID_BATCH_REQUEST' });
  await assert.rejects(() => service.batchResolve({ consumerId: 'consumer-a', requests: Array.from({ length: 21 }, () => ({ credentialKey: 'credential-1', secretNames: ['apiKey'] })) }), { code: 'INVALID_BATCH_REQUEST' });
});

test('consumer discovery adds a non-empty Runtime-Public projection without changing existing fields', async () => {
  const { service } = setup({
    runtimePublicProjectionService: {
      async project() { return { runtimePublic: { clientId: 'public-client' } }; }
    }
  });

  const result = await service.discover({ consumerId: 'consumer-a' });
  assert.deepEqual(result.credentials[0].runtimePublic, { clientId: 'public-client' });
  assert.deepEqual(Object.keys(result.credentials[0]).sort(), ['credentialKey', 'fields', 'metadata', 'runtimePublic']);
});

test('consumer discovery omits an empty Runtime-Public projection', async () => {
  const { service } = setup({
    runtimePublicProjectionService: {
      async project() { return null; }
    }
  });

  const result = await service.discover({ consumerId: 'consumer-a' });
  assert.equal(Object.hasOwn(result.credentials[0], 'runtimePublic'), false);
});

test('consumer discovery filters authorized public display names and tags case-insensitively', async () => {
  const { service } = setup({ metadata: { displayName: 'Production Key', tags: ['Primary', 'Finance'] } });

  assert.equal((await service.discover({ consumerId: 'consumer-a', filters: { displayName: ' production key ' } })).credentials.length, 1);
  assert.equal((await service.discover({ consumerId: 'consumer-a', filters: { tag: 'finance' } })).credentials.length, 1);
  assert.deepEqual((await service.discover({ consumerId: 'consumer-a', filters: { displayName: 'Production Key', tag: 'missing' } })).credentials, []);
  assert.deepEqual((await service.discover({ consumerId: 'consumer-a', filters: { displayName: '' } })).credentials[0].metadata, {
    displayName: 'Production Key', tags: ['Primary', 'Finance']
  });
});

test('consumer discovery filters only after grant authorization and rejects unknown or repeated filters', async () => {
  const unauthorized = setup({ metadata: { displayName: 'Production Key', tags: ['Primary'] }, findGrantResult: null });
  assert.deepEqual((await unauthorized.service.discover({ consumerId: 'consumer-a', filters: { displayName: 'Production Key' } })).credentials, []);

  const { service } = setup();
  await assert.rejects(() => service.discover({ consumerId: 'consumer-a', filters: { provider: 'example' } }), { code: 'INVALID_DISCOVERY_FILTER' });
  await assert.rejects(() => service.discover({ consumerId: 'consumer-a', filters: { tag: ['primary', 'secondary'] } }), { code: 'INVALID_DISCOVERY_FILTER' });
});

test('consumer discovery fails closed when the matching grant is missing', async () => {
  const { service } = setup({
    findGrantResult: null,
    runtimePublicProjectionService: { async project() { return { runtimePublic: { clientId: 'must-not-leak' } }; } }
  });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
});

test('consumer discovery fails closed when the verified grant is bound to another credential', async () => {
  const { service } = setup({
    findGrantResult: { credentialId: 'other-credential', providerKey: 'example', secretNames: ['apiKey'] },
    runtimePublicProjectionService: { async project() { return { runtimePublic: { clientId: 'must-not-leak' } }; } }
  });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
});

test('consumer discovery fails closed for a grant belonging to another consumer', async () => {
  const { service } = setup({
    findGrantResult: { consumerId: 'consumer-b', credentialId: 'credential-1', providerKey: 'example', secretNames: ['apiKey'] },
    runtimePublicProjectionService: { async project() { return { runtimePublic: { clientId: 'must-not-leak' } }; } }
  });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
});

test('consumer discovery fails closed for an inactive credential', async () => {
  const { service } = setup({
    lifecycleState: 'revoked',
    runtimePublicProjectionService: { async project() { return { runtimePublic: { clientId: 'must-not-leak' } }; } }
  });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
});

test('consumer discovery and resolve reject an expired access credential', async () => {
  const { service } = setup({ expiresAt: new Date(Date.now() - 1_000).toISOString() });

  assert.deepEqual((await service.discover({ consumerId: 'consumer-a' })).credentials, []);
  await assert.rejects(
    () => service.resolve({ consumerId: 'consumer-a', credentialKey: 'credential-1', secretNames: ['apiKey'] }),
    { code: 'CREDENTIAL_NOT_CONSUMABLE' }
  );
});
