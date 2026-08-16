import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { FtpConnectionService } from '../../src/connections/ftp/ftp-connection-service.js';

function ftpCredential(overrides = {}) {
  return new Credential({
    credentialId: 'ftp:test',
    providerKey: 'ftp',
    secrets: [
      { name: 'host', value: 'ftp.example.test' },
      { name: 'port', value: '21' },
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

test('FtpConnectionService validates a username/password credential', async () => {
  const service = new FtpConnectionService({
    client: {
      async testConnection(options) {
        assert.deepEqual(options, {
          host: 'ftp.example.test',
          port: 21,
          username: 'deploy',
          password: 'secret',
          timeoutMs: undefined,
          verificationHost: 'ftp.example.test'
        });

        return { host: options.host, port: options.port };
      }
    }
  });

  const result = await service.validateCredential(ftpCredential());

  assert.equal(result.valid, true);
  assert.equal(result.protocol, 'ftp');
  assert.equal(result.host, 'ftp.example.test');
  assert.equal(result.port, 21);
});

test('FtpConnectionService healthCheck returns down instead of throwing on connection failure', async () => {
  const service = new FtpConnectionService({
    client: {
      async testConnection() {
        throw new Error('Authentication failed');
      }
    }
  });

  const result = await service.healthCheck(ftpCredential());

  assert.equal(result.healthy, false);
  assert.equal(result.status, 'down');
  assert.equal(result.protocol, 'ftp');
  assert.equal(result.message, 'Authentication failed');
});

test('FtpConnectionService rejects credentials without password', async () => {
  const service = new FtpConnectionService({
    client: {
      async testConnection() {
        throw new Error('should not connect');
      }
    }
  });

  const credential = new Credential({
    credentialId: 'ftp:missing-password',
    providerKey: 'ftp',
    secrets: [
      { name: 'host', value: 'ftp.example.test' },
      { name: 'username', value: 'deploy' }
    ]
  });

  await assert.rejects(
    () => service.validateCredential(credential),
    /FTP credential requires password/
  );
});
