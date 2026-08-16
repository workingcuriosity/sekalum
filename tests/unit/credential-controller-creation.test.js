import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialController } from '../../src/controllers/credential-controller.js';

function responseRecorder() {
  return {
    statusCode: null,
    body: null,
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; }
  };
}

for (const failure of [
  ['CREDENTIAL_SECRET_MISSING', 400, 'credential.create.secretMissing'],
  ['CREDENTIAL_FIELD_INVALID', 400, 'credential.create.fieldInvalid'],
  ['CREDENTIAL_PROVIDER_UNKNOWN', 400, 'credential.create.providerUnknown'],
  ['CREDENTIAL_ENCRYPTION_FAILED', 500, 'credential.create.encryptionFailed'],
  ['CREDENTIAL_PERSISTENCE_FAILED', 500, 'credential.create.persistenceFailed'],
  ['CREDENTIAL_SECRET_VERSIONING_FAILED', 500, 'credential.create.secretVersioningFailed']
]) {
  test(`CredentialController returns a structured ${failure[0]} response`, async () => {
    const [code, statusCode, messageKey] = failure;
    const controller = new CredentialController({
      credentialManager: {
        async register() {
          const error = new Error('safe creation failure');
          error.code = code;
          error.statusCode = statusCode;
          error.messageKey = messageKey;
          throw error;
        }
      }
    });
    const res = responseRecorder();

    await controller.create({ body: { providerKey: 'openai' } }, res);

    assert.equal(res.statusCode, statusCode);
    assert.equal(res.body.success, false);
    assert.equal(res.body.code, code);
    assert.equal(res.body.messageKey, messageKey);
    assert.equal(res.body.message, 'safe creation failure');
    assert.deepEqual(res.body.error, { code, messageKey, message: 'safe creation failure', details: undefined });
  });
}

test('CredentialController hides raw exceptions behind CREDENTIAL_CREATE_FAILED', async () => {
  const controller = new CredentialController({ credentialManager: { async register() { throw new Error('raw database internals'); } } });
  const res = responseRecorder();

  await controller.create({ body: { providerKey: 'openai' } }, res);

  assert.equal(res.statusCode, 500);
  assert.equal(res.body.code, 'CREDENTIAL_CREATE_FAILED');
  assert.equal(res.body.error.message, 'Credential could not be created');
  assert.doesNotMatch(JSON.stringify(res.body), /database internals/);
});
