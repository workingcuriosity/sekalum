import test from 'node:test';
import assert from 'node:assert/strict';

import { ConnectionTargetPolicy } from '../../src/services/connection-target-policy.js';

test('ConnectionTargetPolicy resolves a public hostname to a verified address', async () => {
  const policy = new ConnectionTargetPolicy({
    lookup: async (host, options) => {
      assert.equal(host, 'ftp.example.test');
      assert.deepEqual(options, { all: true, verbatim: true });
      return [{ address: '8.8.8.8', family: 4 }];
    }
  });

  const target = await policy.resolveAllowedTarget('ftp.example.test');

  assert.deepEqual(target, {
    host: 'ftp.example.test',
    address: '8.8.8.8'
  });
});

test('ConnectionTargetPolicy blocks loopback, link-local, and private targets by default', async () => {
  const policy = new ConnectionTargetPolicy({
    lookup: async () => [{ address: '127.0.0.1', family: 4 }]
  });

  for (const host of ['127.0.0.1', '169.254.169.254', '10.0.0.8', '192.168.1.10', '::1', 'fe80::1']) {
    await assert.rejects(
      () => policy.resolveAllowedTarget(host),
      (error) => error.code === 'CREDENTIAL_CONNECTION_TARGET_BLOCKED'
    );
  }

  await assert.rejects(
    () => policy.resolveAllowedTarget('internal.example.test'),
    (error) => error.code === 'CREDENTIAL_CONNECTION_TARGET_BLOCKED'
  );
});

test('ConnectionTargetPolicy rejects hostnames with any blocked resolved address', async () => {
  const policy = new ConnectionTargetPolicy({
    lookup: async () => [
      { address: '8.8.8.8', family: 4 },
      { address: '127.0.0.1', family: 4 }
    ]
  });

  await assert.rejects(
    () => policy.resolveAllowedTarget('mixed.example.test'),
    (error) => error.code === 'CREDENTIAL_CONNECTION_TARGET_BLOCKED'
  );
});

test('ConnectionTargetPolicy reports DNS failures without exposing resolver details', async () => {
  const policy = new ConnectionTargetPolicy({
    lookup: async () => {
      throw new Error('getaddrinfo ENOTFOUND private-host.internal');
    }
  });

  await assert.rejects(
    () => policy.resolveAllowedTarget('unknown.example.test'),
    (error) => error.code === 'CREDENTIAL_CONNECTION_DNS_FAILED'
      && error.messageKey === 'credential.connectionTest.dnsFailed'
      && error.message === 'Connection target could not be resolved'
      && !error.message.includes('private-host')
  );
});

test('ConnectionTargetPolicy permits configured private networks but never local-only targets', async () => {
  const policy = new ConnectionTargetPolicy({ allowPrivateNetworks: true });

  const privateTarget = await policy.resolveAllowedTarget('10.0.0.8');
  assert.equal(privateTarget.address, '10.0.0.8');

  await assert.rejects(
    () => policy.resolveAllowedTarget('127.0.0.1'),
    (error) => error.code === 'CREDENTIAL_CONNECTION_TARGET_BLOCKED'
  );
});
