import test from 'node:test';
import assert from 'node:assert/strict';

import { SftpClient } from '../../src/api/sftp/sftp-client.js';

test('SftpClient validates required connection options before connecting', async () => {
  const client = new SftpClient({
    connector: {
      async connect() {
        throw new Error('should not connect');
      }
    }
  });

  await assert.rejects(
    () => client.testConnection({ port: 22, username: 'user', password: 'secret' }),
    /SFTP host is required/
  );
});

test('SftpClient connects and disconnects through injected transport', async () => {
  let connected = false;
  let disconnected = false;

  const client = new SftpClient({
    connector: {
      async connect(options) {
        connected = true;
        assert.equal(options.host, 'example.test');
        assert.equal(options.hostKeyAlias, 'example.test');
        return {
          async disconnect() {
            disconnected = true;
          }
        };
      }
    }
  });

  const result = await client.testConnection({
    host: 'example.test',
    port: 22,
    username: 'deploy',
    password: 'secret'
  });

  assert.equal(connected, true);
  assert.equal(disconnected, true);
  assert.deepEqual(result, {
    connected: true,
    host: 'example.test',
    port: 22
  });
});

test('SftpClient preserves the host-key alias when connecting to a policy-pinned address', async () => {
  const client = new SftpClient({
    connector: {
      async connect(options) {
        assert.equal(options.host, '203.0.113.10');
        assert.equal(options.hostKeyAlias, 'sftp.example.test');
        return { async disconnect() {} };
      }
    }
  });

  await client.testConnection({
    host: '203.0.113.10',
    verificationHost: 'sftp.example.test',
    port: 22,
    username: 'deploy',
    password: 'secret'
  });
});
