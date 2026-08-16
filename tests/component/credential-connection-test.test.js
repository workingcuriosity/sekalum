import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialManager } from '../../src/managers/credential-manager.js';
import { Credential } from '../../src/models/credential.js';
import { ProviderResult } from '../../src/models/provider-result.js';

const openAiFields = [
  { key: 'displayName', required: true, type: 'text' },
  { key: 'apiKey', required: true, secret: true, type: 'api-key', validation: { minLength: 20 } }
];

const ftpFields = [
  { key: 'displayName', required: true, type: 'text' },
  { key: 'host', required: true, secret: true, type: 'text' },
  { key: 'port', required: false, type: 'integer', validation: { minimum: 1, maximum: 65535 } },
  { key: 'username', required: true, secret: true, type: 'text' },
  { key: 'password', required: true, secret: true, type: 'password' }
];

function providerManager({ providerKey = 'openai', fields = openAiFields, capabilities = ['validation'], result = ProviderResult.success({}) } = {}) {
  return {
    getProvider(key) {
      if (key !== providerKey) throw new Error('provider not found');
      return { key, credentialFields: fields, capabilities };
    },
    async validateCredential(credential) {
      this.credential = credential;
      return result;
    },
    async healthCheckCredential(credential) {
      this.healthCredential = credential;
      return result;
    }
  };
}

function storedNetworkCredential(providerKey, host, { hostInMetadata = false } = {}) {
  return Credential.from({
    credentialId: `${providerKey}:stored-connection`,
    providerKey,
    metadata: {
      displayName: `${providerKey.toUpperCase()} stored connection`,
      custom: hostInMetadata ? { host } : {}
    },
    secrets: [
      ...(hostInMetadata ? [] : [{ name: 'host', value: host }]),
      { name: 'username', value: 'deploy' },
      { name: 'password', value: 'very-secret' }
    ]
  });
}

test('CredentialManager tests an ephemeral OpenAI credential without persisting or returning secrets', async () => {
  const store = {
    async save() {
      throw new Error('Connection tests must not persist credentials');
    }
  };
  const providers = providerManager();
  const manager = new CredentialManager({ credentialStore: store, providerManager: providers });

  const result = await manager.testConnection({
    credentialId: 'must-be-ignored',
    lifecycleState: 'active',
    providerKey: 'openai',
    metadata: { displayName: 'OpenAI Test' },
    secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }]
  });

  assert.equal(result.providerKey, 'openai');
  assert.equal(result.status, 'connected');
  assert.equal(result.messageKey, 'credential.connection.success');
  assert.match(result.checkedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(providers.credential.lifecycleState, 'registered');
  assert.notEqual(providers.credential.credentialId, 'must-be-ignored');
  assert.equal(providers.credential.secrets[0].value, 'sk-example-12345678901234567890');
  assert.equal(JSON.stringify(result).includes('sk-example'), false);
});

test('CredentialManager resolves FTP targets before provider execution and does not expose the target', async () => {
  const providers = providerManager({ providerKey: 'ftp', fields: ftpFields });
  const targetPolicy = {
    async resolveAllowedTarget(host) {
      assert.equal(host, 'ftp.example.test');
      return { host, address: '8.8.8.8' };
    }
  };
  const manager = new CredentialManager({ providerManager: providers, connectionTargetPolicy: targetPolicy });

  const result = await manager.testConnection({
    providerKey: 'ftp',
    metadata: { displayName: 'FTP Test', custom: { port: 21 } },
    secrets: [
      { name: 'host', value: 'ftp.example.test' },
      { name: 'username', value: 'deploy' },
      { name: 'password', value: 'very-secret' }
    ]
  });

  assert.equal(providers.credential.secrets.find((secret) => secret.name === 'host').value, '8.8.8.8');
  assert.equal(result.providerKey, 'ftp');
  assert.equal(result.status, 'connected');
  assert.equal(JSON.stringify(result).includes('ftp.example.test'), false);
  assert.equal(JSON.stringify(result).includes('very-secret'), false);
});

test('CredentialManager rejects unsupported providers before a provider operation', async () => {
  const providers = providerManager({ capabilities: ['health-check'] });
  const manager = new CredentialManager({ providerManager: providers });

  await assert.rejects(
    () => manager.testConnection({
      providerKey: 'openai',
      metadata: { displayName: 'OpenAI Test' },
      secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }]
    }),
    (error) => error.code === 'CREDENTIAL_CONNECTION_UNSUPPORTED'
      && error.messageKey === 'credential.connectionTest.unsupported'
  );
});

test('CredentialManager maps provider failures to safe public connection errors', async () => {
  const providers = providerManager({
    result: ProviderResult.failure({
      code: 'ECONNREFUSED',
      message: 'Connection to secret-host.internal failed with password very-secret'
    })
  });
  const manager = new CredentialManager({ providerManager: providers });

  await assert.rejects(
    () => manager.testConnection({
      providerKey: 'openai',
      metadata: { displayName: 'OpenAI Test' },
      secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }]
    }),
    (error) => error.code === 'CREDENTIAL_CONNECTION_REFUSED'
      && error.message === 'Credential connection was refused'
      && !error.message.includes('secret-host')
      && !error.message.includes('very-secret')
  );
});

test('CredentialManager maps authentication, permission, rate-limit, and timeout failures to stable codes', async () => {
  const cases = [
    [{ status: 401, message: 'provider rejected token' }, 'CREDENTIAL_CONNECTION_AUTHENTICATION_FAILED'],
    [{ status: 403, message: 'provider denied access' }, 'CREDENTIAL_CONNECTION_PERMISSION_DENIED'],
    [{ status: 429, message: 'rate limited' }, 'CREDENTIAL_CONNECTION_RATE_LIMITED'],
    [{ code: 'EHOSTUNREACH', message: 'host unreachable' }, 'CREDENTIAL_CONNECTION_HOST_UNREACHABLE'],
    [{ code: 'ETIMEDOUT', message: 'connection timed out' }, 'CREDENTIAL_CONNECTION_TIMEOUT']
  ];

  for (const [failure, expectedCode] of cases) {
    const manager = new CredentialManager({
      providerManager: providerManager({ result: ProviderResult.failure(failure) })
    });

    await assert.rejects(
      () => manager.testConnection({
        providerKey: 'openai',
        metadata: { displayName: 'OpenAI Test' },
        secrets: [{ name: 'apiKey', value: 'sk-example-12345678901234567890' }]
      }),
      (error) => error.code === expectedCode && error.details.field === 'apiKey'
    );
  }
});

test('CredentialManager activates only a successfully validated stored credential and records its check time', async () => {
  const stored = [];
  const store = {
    async save(credential) {
      stored.push(credential);
    }
  };
  const credential = {
    credentialId: 'credential-1',
    providerKey: 'openai',
    lifecycleState: 'registered',
    version: 1,
    metadata: { toJSON: () => ({ displayName: 'OpenAI Test', custom: {} }) },
    secrets: [],
    toJSON() {
      return {
        credentialId: this.credentialId,
        providerKey: this.providerKey,
        lifecycleState: this.lifecycleState,
        version: this.version,
        metadata: this.metadata.toJSON(),
        secrets: []
      };
    }
  };
  const manager = new CredentialManager({ credentialStore: store, providerManager: providerManager() });

  const success = await manager.validate(credential);
  assert.equal(success.success, true);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].lifecycleState, 'active');
  assert.match(stored[0].metadata.toJSON().custom.lastValidatedAt, /^\d{4}-\d{2}-\d{2}T/);

  const failingManager = new CredentialManager({
    credentialStore: store,
    providerManager: providerManager({ result: ProviderResult.failure({ status: 401, message: 'invalid key' }) })
  });
  const failure = await failingManager.validate(credential);
  assert.equal(failure.success, false);
  assert.equal(stored.length, 1);
});

test('CredentialManager blocks stored FTP validation before a provider connection is attempted', async () => {
  const providers = providerManager({ providerKey: 'ftp', fields: ftpFields });
  const targetPolicy = {
    async resolveAllowedTarget(host) {
      assert.equal(host, '127.0.0.1');
      const error = new Error('Connection target is not allowed');
      error.code = 'CREDENTIAL_CONNECTION_TARGET_BLOCKED';
      throw error;
    }
  };
  const manager = new CredentialManager({ providerManager: providers, connectionTargetPolicy: targetPolicy });

  const result = await manager.validate(storedNetworkCredential('ftp', '127.0.0.1'));

  assert.equal(result.success, false);
  assert.equal(result.error.code, 'CREDENTIAL_CONNECTION_TARGET_BLOCKED');
  assert.equal(providers.credential, undefined);
});

test('CredentialManager blocks stored SFTP health checks before a provider connection is attempted', async () => {
  const providers = providerManager({ providerKey: 'sftp', fields: ftpFields });
  const targetPolicy = {
    async resolveAllowedTarget(host) {
      assert.equal(host, '169.254.169.254');
      const error = new Error('Connection target is not allowed');
      error.code = 'CREDENTIAL_CONNECTION_TARGET_BLOCKED';
      throw error;
    }
  };
  const manager = new CredentialManager({ providerManager: providers, connectionTargetPolicy: targetPolicy });

  const result = await manager.healthCheck(storedNetworkCredential('sftp', '169.254.169.254', { hostInMetadata: true }));

  assert.equal(result.success, false);
  assert.equal(result.error.code, 'CREDENTIAL_CONNECTION_TARGET_BLOCKED');
  assert.equal(providers.healthCredential, undefined);
});

test('CredentialManager permits private targets only when the explicit configuration flag is enabled', async () => {
  const providers = providerManager({ providerKey: 'ftp', fields: ftpFields });
  const config = {
    get(key, fallback) {
      return key === 'CONNECTION_TEST_ALLOW_PRIVATE_NETWORKS' ? 'true' : fallback;
    }
  };
  const manager = new CredentialManager({ providerManager: providers, config });

  const result = await manager.validate(storedNetworkCredential('ftp', '192.168.1.20'));
  const checkedHost = providers.credential.secrets.find((secret) => secret.name === 'host');

  assert.equal(result.success, true);
  assert.equal(checkedHost.value, '192.168.1.20');
  assert.equal(providers.credential.metadata.toJSON().custom.connectionVerificationHost, '192.168.1.20');
});
