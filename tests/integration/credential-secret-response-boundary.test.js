import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialController } from '../../src/controllers/credential-controller.js';
import { Credential } from '../../src/models/credential.js';

const SECRET_MARKER = 'RC3A-LIFECYCLE-SECRET-MARKER';

function createCredential() {
  return new Credential({
    credentialId: 'credential-secret-boundary',
    credentialKey: 'credential-secret-boundary-key',
    providerKey: 'openai',
    credentialMethodKey: 'api-key',
    lifecycleState: 'active',
    secrets: [
      { name: 'apiKey', value: SECRET_MARKER },
      { name: 'refreshToken', value: `${SECRET_MARKER}-refresh` }
    ],
    metadata: {
      displayName: 'Secret boundary test credential',
      custom: { internalSecret: SECRET_MARKER }
    }
  });
}

function lifecycleData(action, credential) {
  return {
    action,
    credential,
    provider: {
      accessToken: SECRET_MARKER,
      refreshToken: `${SECRET_MARKER}-refresh`,
      runtimeToken: `${SECRET_MARKER}-derived`,
      status: 'healthy'
    }
  };
}

function createController() {
  const credential = createCredential();
  const manager = {
    async getCredential() {
      return credential;
    },
    async executeBulkAction({ action, credentialIds }) {
      return {
        action,
        requested: credentialIds.length,
        succeeded: credentialIds.length,
        failed: 0,
        results: credentialIds.map((credentialId) => ({
          credentialId,
          success: true,
          data: action === 'delete'
            ? { credentialId, deleted: true, provider: { runtimeToken: SECRET_MARKER } }
            : {
              action,
              credential,
              provider: {
                accessToken: SECRET_MARKER,
                refreshToken: `${SECRET_MARKER}-refresh`,
                runtimeToken: `${SECRET_MARKER}-derived`,
                status: 'healthy'
              }
            }
        }))
      };
    },
    async validate() {
      return { success: true, data: lifecycleData('validate', credential) };
    },
    async refresh() {
      return { success: true, data: lifecycleData('refresh', credential) };
    },
    async revoke() {
      return { success: true, data: lifecycleData('revoke', credential) };
    },
    async healthCheck() {
      return { success: true, data: lifecycleData('health-check', credential) };
    }
  };

  return new CredentialController({ credentialManager: manager });
}

function responseRecorder() {
  const result = { status: null, body: null };
  return {
    result,
    status(code) {
      result.status = code;
      return this;
    },
    json(body) {
      result.body = body;
      return this;
    },
    send() {
      return this;
    }
  };
}

test('single lifecycle responses expose safe credential metadata only', async () => {
  const controller = createController();

  for (const action of ['validate', 'refresh', 'revoke', 'healthCheck']) {
    const recorder = responseRecorder();
    await controller[action]({ params: { credentialId: 'credential-secret-boundary' }, auth: { userId: 'admin' }, headers: {} }, recorder);

    assert.equal(recorder.result.status, 200);
    assert.equal(recorder.result.body.success, true);
    assert.equal(recorder.result.body.data.action, action === 'healthCheck' ? 'health-check' : action);
    assert.equal(recorder.result.body.data.credential.credentialId, 'credential-secret-boundary');
    assert.equal(recorder.result.body.data.credential.providerKey, 'openai');
    assert.equal(JSON.stringify(recorder.result.body).includes(SECRET_MARKER), false);
  }
});

test('direct credential lifecycle responses do not expose custom metadata', async () => {
  const credential = createCredential();
  const controller = new CredentialController({
    credentialManager: {
      async getCredential() {
        return credential;
      },
      async validate() {
        return { success: true, data: credential };
      }
    }
  });
  const recorder = responseRecorder();

  await controller.validate({ params: { credentialId: 'credential-secret-boundary' }, auth: { userId: 'admin' }, headers: {} }, recorder);

  assert.equal(recorder.result.status, 200);
  assert.equal(recorder.result.body.data.credentialId, 'credential-secret-boundary');
  assert.equal('custom' in recorder.result.body.data.metadata, false);
  assert.equal(JSON.stringify(recorder.result.body).includes(SECRET_MARKER), false);
});

test('bulk lifecycle responses expose safe per-entry results only', async () => {
  const controller = createController();

  for (const action of ['validate', 'refresh', 'revoke', 'health-check', 'delete']) {
    const recorder = responseRecorder();
    await controller.bulk({ body: { action, credentialIds: ['credential-secret-boundary'] } }, recorder);

    assert.equal(recorder.result.status, 200);
    assert.equal(recorder.result.body.success, true);
    assert.equal(recorder.result.body.data.results[0].success, true);
    assert.equal(recorder.result.body.data.results[0].credentialId, 'credential-secret-boundary');
    assert.equal(JSON.stringify(recorder.result.body).includes(SECRET_MARKER), false);
  }
});
