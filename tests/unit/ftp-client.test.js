import test from 'node:test';
import assert from 'node:assert/strict';

import { FtpClient } from '../../src/api/ftp/ftp-client.js';

test('FtpClient validates required connection options before connecting', async () => {
  const client = new FtpClient({
    connector: {
      async connect() {
        throw new Error('should not connect');
      }
    }
  });

  await assert.rejects(
    () => client.testConnection({ port: 21, username: 'user', password: 'secret' }),
    /FTP host is required/
  );
});

test('FtpClient connects and disconnects through injected transport', async () => {
  let connected = false;
  let disconnected = false;

  const client = new FtpClient({
    connector: {
      async connect(options) {
        connected = true;
        assert.equal(options.host, 'ftp.example.test');
        assert.equal(options.servername, 'ftp.example.test');
        return {
          async disconnect() {
            disconnected = true;
          }
        };
      }
    }
  });

  const result = await client.testConnection({
    host: 'ftp.example.test',
    port: 21,
    username: 'deploy',
    password: 'secret'
  });

  assert.equal(connected, true);
  assert.equal(disconnected, true);
  assert.deepEqual(result, {
    connected: true,
    host: 'ftp.example.test',
    port: 21
  });
});

test('FtpClient preserves the verification host when connecting to a policy-pinned address', async () => {
  const client = new FtpClient({
    connector: {
      async connect(options) {
        assert.equal(options.host, '203.0.113.10');
        assert.equal(options.servername, 'ftp.example.test');
        return { async disconnect() {} };
      }
    }
  });

  await client.testConnection({
    host: '203.0.113.10',
    verificationHost: 'ftp.example.test',
    port: 21,
    username: 'deploy',
    password: 'secret'
  });
});
