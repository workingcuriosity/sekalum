import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AuthorizationIdentifierError,
  IdentifierDomain,
  compareIdentifiers,
  domainFor,
  validateIdentifier,
  validateNamedIdentifier
} from '../../src/security/authorization-identifier.js';
import { ApiToken } from '../../src/models/api-token.js';
import { Credential } from '../../src/models/credential.js';
import { CredentialMethod } from '../../src/models/credential-method.js';
import { CustomProviderService } from '../../src/services/custom-provider-service.js';

const expectInvalid = (fn, field) => {
  assert.throws(fn, (error) => {
    assert.equal(error instanceof AuthorizationIdentifierError, true);
    assert.equal(error.code, 'IDENTIFIER_INVALID');
    assert.match(error.message, new RegExp(field));
    return true;
  });
};

test('authorization identifier domains are explicit and unknown domains fail closed', () => {
  assert.equal(domainFor('providerKey'), IdentifierDomain.CANONICAL_TECHNICAL_KEY);
  assert.equal(domainFor('fieldKey'), IdentifierDomain.CASE_SENSITIVE_FIELD_KEY);
  assert.throws(() => domainFor('futureIdentifier'), { code: 'IDENTIFIER_DOMAIN_UNSUPPORTED' });
  assert.throws(() => validateIdentifier('UNKNOWN', 'value'), { code: 'IDENTIFIER_DOMAIN_UNSUPPORTED' });
});

test('technical provider and method keys require lowercase ASCII kebab case without repair', () => {
  assert.equal(validateNamedIdentifier('providerKey', 'github'), 'github');
  assert.equal(validateNamedIdentifier('credentialMethodKey', 'api-key'), 'api-key');
  for (const value of ['GitHub', ' github', 'github ', 'über', 'api_key', 'api:key']) {
    expectInvalid(() => validateNamedIdentifier('providerKey', value), 'providerKey');
  }
});

test('field, role and permission identifiers preserve exact case', () => {
  assert.equal(validateNamedIdentifier('fieldKey', 'accessToken'), 'accessToken');
  assert.equal(validateNamedIdentifier('roleKey', 'admin'), 'admin');
  assert.equal(validateNamedIdentifier('permissionScope', 'credentials:read'), 'credentials:read');
  expectInvalid(() => validateNamedIdentifier('fieldKey', 'AccessToken'), 'fieldKey');
  expectInvalid(() => validateNamedIdentifier('roleKey', 'Admin'), 'roleKey');
  expectInvalid(() => validateNamedIdentifier('permissionScope', 'Credentials:Read'), 'permissionScope');
});

test('opaque, provider-owned and path identifiers are exact and never trimmed or decoded', () => {
  assert.equal(validateNamedIdentifier('credentialId', 'Credential-A'), 'Credential-A');
  assert.equal(validateNamedIdentifier('externalReference', 'google:main/%2F'), 'google:main/%2F');
  assert.equal(validateNamedIdentifier('backupId', 'backup-2026-09-01'), 'backup-2026-09-01');
  expectInvalid(() => validateNamedIdentifier('credentialId', ' Credential-A'), 'credentialId');
  assert.equal(validateNamedIdentifier('externalReference', 'provider/ref'), 'provider/ref');
  expectInvalid(() => validateNamedIdentifier('backupId', 'backup%2Fsecret'), 'backupId');
});

test('comparison is exact and composite identities validate every named component', () => {
  assert.equal(compareIdentifiers('fieldKey', 'accessToken', 'accessToken'), true);
  expectInvalid(() => compareIdentifiers('fieldKey', 'accessToken', 'AccessToken'), 'CASE_SENSITIVE');
  expectInvalid(() => compareIdentifiers('roleKey', 'admin', 'owner'), 'roleKey');
  expectInvalid(() => compareIdentifiers('providerKey', 'GitHub', 'github'), 'CANONICAL');
});

test('Credential rejects invalid identity input before construction', () => {
  expectInvalid(() => new Credential({ credentialId: 'credential-1', providerKey: 'GitHub' }), 'providerKey');
  expectInvalid(() => new Credential({ credentialId: ' credential-1', providerKey: 'github' }), 'credentialId');
  expectInvalid(() => new Credential({ credentialId: 'credential-1', providerKey: 'github', credentialMethodKey: 'API-Key' }), 'credentialMethodKey');
});

test('ApiToken rejects non-canonical user and scope identities without mutation', () => {
  const base = {
    id: 'api-token-1', name: 'automation', tokenPrefix: 'cht_test', tokenHash: 'sha256:test',
    userId: 'automation-user', createdBy: 'admin-user', scopes: ['credentials:read']
  };
  expectInvalid(() => new ApiToken({ ...base, userId: ' automation-user' }), 'userId');
  expectInvalid(() => new ApiToken({ ...base, scopes: ['Credentials:Read'] }), 'permissionScope');
  const token = new ApiToken(base);
  assert.deepEqual(token.scopes, ['credentials:read']);
});

test('custom provider admission is production-shaped and does not persist rejected identifiers', async () => {
  const saved = [];
  const service = new CustomProviderService({
    store: {
      async list() { return saved; },
      async save(value) { saved.push(value); },
      async delete() { return false; }
    },
    providerRegistry: { has() { return false; }, register() {}, unregister() {} }
  });
  const input = {
    key: 'GitHub', displayName: 'GitHub', category: 'vcs', credentialFields: [{ key: 'token', label: 'Token', secret: true }],
    credentialMethods: [{ key: 'api-key', displayName: 'API key', credentialFields: [{ key: 'token', label: 'Token', secret: true }] }],
    providerMethodBindings: [{ methodKey: 'api-key' }]
  };
  await assert.rejects(() => service.create(input), { code: 'PROVIDER_DEFINITION_INVALID' });
  assert.equal(saved.length, 0);
});
