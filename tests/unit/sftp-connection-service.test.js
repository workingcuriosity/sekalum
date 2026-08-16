import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { SftpConnectionService } from '../../src/connections/sftp/sftp-connection-service.js';

function sftpCredential(overrides = {}) {
  return new Credential({
    credentialId: 'sftp:test',
    providerKey: 'sftp',
    secrets: [
      { name: 'host', value: 'sftp.example.test' },
      { name: 'port', value: '22' },
      { name: 'username', value: 'deploy' },
      { name: 'password', value: 'secret' }
    ],
    metadata: {
      custom: {},
      ...(overrides.metadata ?? {})
    },
    ...(overrides.credential ?? {})
  });
}

test('SftpConnectionService validates a username/password credential', async () => {
  const service = new SftpConnectionService({
    client: {
      async testConnection(options) {
        assert.deepEqual(options, {
          host: 'sftp.example.test',
          port: 22,
          username: 'deploy',
          password: 'secret',
          timeoutMs: undefined,
          verificationHost: 'sftp.example.test'
        });

        return { host: options.host, port: options.port };
      }
    }
  });

  const result = await service.validateCredential(sftpCredential());

  assert.equal(result.valid, true);
  assert.equal(result.protocol, 'sftp');
  assert.equal(result.host, 'sftp.example.test');
  assert.equal(result.port, 22);
});

test('SftpConnectionService healthCheck returns down instead of throwing on connection failure', async () => {
  const service = new SftpConnectionService({
    client: {
      async testConnection() {
        throw new Error('Authentication failed');
      }
    }
  });

  const result = await service.healthCheck(sftpCredential());

  assert.equal(result.healthy, false);
  assert.equal(result.status, 'down');
  assert.equal(result.protocol, 'sftp');
  assert.equal(result.message, 'Authentication failed');
});

test('SftpConnectionService rejects credentials without password', async () => {
  const service = new SftpConnectionService({
    client: {
      async testConnection() {
        throw new Error('should not connect');
      }
    }
  });

  const credential = new Credential({
    credentialId: 'sftp:missing-password',
    providerKey: 'sftp',
    secrets: [
      { name: 'host', value: 'sftp.example.test' },
      { name: 'username', value: 'deploy' }
    ]
  });

  await assert.rejects(
    () => service.validateCredential(credential),
    /SFTP credential requires password/
  );
});
