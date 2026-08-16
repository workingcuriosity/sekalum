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

test('CredentialController returns only the public connection-test result', async () => {
  const controller = new CredentialController({
    credentialManager: {
      async testConnection() {
        return {
          providerKey: 'openai',
          status: 'connected',
          messageKey: 'credential.connection.success',
          checkedAt: '2026-07-13T10:00:00.000Z',
          rawProviderResult: { apiKey: 'sk-never-return-this-secret' }
        };
      }
    }
  });
  const response = responseRecorder();

  await controller.testConnection({ body: { providerKey: 'openai' } }, response);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, {
    success: true,
    data: {
      providerKey: 'openai',
      status: 'connected',
      messageKey: 'credential.connection.success',
      checkedAt: '2026-07-13T10:00:00.000Z'
    }
  });
  assert.equal(JSON.stringify(response.body).includes('sk-never-return-this-secret'), false);
});

test('CredentialController preserves only stable public connection errors', async () => {
  const controller = new CredentialController({
    credentialManager: {
      async testConnection() {
        const error = new Error('Raw provider error with password very-secret');
        error.code = 'CREDENTIAL_CONNECTION_FAILED';
        error.statusCode = 422;
        error.messageKey = 'credential.connectionTest.failed';
        error.message = 'Credential connection test failed';
        throw error;
      }
    }
  });
  const response = responseRecorder();

  await controller.testConnection({ body: { providerKey: 'openai' } }, response);

  assert.equal(response.statusCode, 422);
  assert.equal(response.body.error.code, 'CREDENTIAL_CONNECTION_FAILED');
  assert.equal(response.body.error.messageKey, 'credential.connectionTest.failed');
  assert.equal(JSON.stringify(response.body).includes('very-secret'), false);
});
