import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import https from 'node:https';

import { EgressError, EgressPolicy } from '../../src/services/egress-policy.js';
import { HttpClient } from '../../src/api/http-client.js';
import { FtpClient } from '../../src/api/ftp/ftp-client.js';
import { SftpClient } from '../../src/api/sftp/sftp-client.js';

const HTTPS_CONTEXT = Object.freeze({
  pathId: 'HTTP-SHARED',
  purpose: 'PROVIDER_VALIDATION',
  providerKey: 'test-provider',
  protocol: 'https',
  credentialBearing: true
});

function policyFor(addresses, options = {}) {
  return new EgressPolicy({
    lookup: async () => addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })),
    ...options
  });
}

async function rejectsCode(action, code) {
  await assert.rejects(action, (error) => error?.code === code);
}

test('SSRF-ATTACK-002: IPv6 loopback, ULA, link-local, and hard-block addresses are denied', async () => {
  for (const address of ['::1', 'fc00::1', 'fe80::1', 'ff02::1', '127.0.0.1', '169.254.169.254']) {
    await rejectsCode(
      () => policyFor(['8.8.8.8']).admit(`https://${address.includes(':') ? `[${address}]` : address}/x`, HTTPS_CONTEXT),
      'EGRESS_TARGET_BLOCKED'
    );
  }
});

test('SSRF-ATTACK-003: mapped IPv6 addresses cannot bypass IPv4 classification', async () => {
  for (const address of ['::ffff:10.0.0.8', '0:0:0:0:0:ffff:c0a8:0101']) {
    await rejectsCode(
      () => policyFor(['8.8.8.8']).admit(`https://[${address}]/x`, HTTPS_CONTEXT),
      'EGRESS_TARGET_BLOCKED'
    );
  }
});

test('SSRF-ATTACK-004: NAT64 and unsupported translated IPv6 forms fail closed', async () => {
  await rejectsCode(
    () => policyFor(['64:ff9b::a00:8']).admit('https://[64:ff9b::a00:8]/x', HTTPS_CONTEXT),
    'EGRESS_TARGET_BLOCKED'
  );
  await rejectsCode(
    () => policyFor(['2002:c000:0201::1']).admit('https://[2002:c000:0201::1]/x', HTTPS_CONTEXT),
    'EGRESS_TARGET_BLOCKED'
  );
});

test('SSRF-ATTACK-005: mixed DNS answers fail closed before transport', async () => {
  await rejectsCode(
    () => policyFor(['8.8.8.8', '127.0.0.1']).admit('https://mixed.example.test/x', HTTPS_CONTEXT),
    'EGRESS_TARGET_BLOCKED'
  );
});

test('SSRF-ATTACK-006: DNS rebinding cannot change the admitted transport address', async () => {
  const originalRequest = https.request;
  const requests = [];
  let transportLookups = 0;
  let pooledAddress = null;
  const addresses = ['8.8.8.8', '1.1.1.1'];
  let admissionLookups = 0;

  // This is the real requestHttps path. The fixture models the unsafe default
  // Agent behavior so the test fails if route identity is not isolated from
  // the host/port pool key.
  https.request = (options, callback) => {
    const request = new EventEmitter();
    request.setTimeout = () => {};
    request.write = () => {};
    request.end = () => {
      let actualAddress = null;
      if (options.agent === false || pooledAddress === null) {
        options.lookup(options.hostname, {}, (error, address, family) => {
          assert.equal(error, null);
          actualAddress = address;
          transportLookups += 1;
        });
      } else {
        actualAddress = pooledAddress;
      }
      if (pooledAddress === null) pooledAddress = actualAddress;
      requests.push({
        actualAddress,
        hostname: options.hostname,
        servername: options.servername,
        hostHeader: options.headers.Host,
        agent: options.agent
      });

      const response = new EventEmitter();
      response.statusCode = 200;
      response.headers = { 'content-type': 'application/json' };
      callback(response);
      response.emit('data', Buffer.from('{"ok":true}'));
      response.emit('end');
    };
    return request;
  };

  try {
    const client = new HttpClient({
      egressPolicy: new EgressPolicy({
        lookup: async () => {
          const address = addresses[admissionLookups];
          admissionLookups += 1;
          return [{ address, family: 4 }];
        }
      })
    });

    const first = await client.get('https://provider.example.test/profile', {
      bearerToken: 'access-token',
      ...HTTPS_CONTEXT
    });
    const second = await client.get('https://provider.example.test/profile', {
      bearerToken: 'access-token',
      ...HTTPS_CONTEXT
    });
    assert.deepEqual(first.data, { ok: true });
    assert.deepEqual(second.data, { ok: true });
  } finally {
    https.request = originalRequest;
  }

  assert.deepEqual(requests.map(({ actualAddress }) => actualAddress), ['8.8.8.8', '1.1.1.1']);
  assert.equal(admissionLookups, 2);
  assert.equal(transportLookups, 2);
  assert.ok(requests.every((request) => request.agent === false));
  assert.ok(requests.every((request) => request.hostname === 'provider.example.test'));
  assert.ok(requests.every((request) => request.servername === 'provider.example.test'));
  assert.ok(requests.every((request) => request.hostHeader === 'provider.example.test'));

  const blockedRequests = requests.length;
  const blockedClient = new HttpClient({
    egressPolicy: policyFor(['127.0.0.1'])
  });
  await rejectsCode(
    () => blockedClient.get('https://provider.example.test/profile', HTTPS_CONTEXT),
    'EGRESS_TARGET_BLOCKED'
  );
  assert.equal(requests.length, blockedRequests);
});

test('SSRF-ATTACK-007: redirects are terminal errors', async () => {
  const client = new HttpClient({
    egressPolicy: policyFor(['8.8.8.8']),
    transport: async () => ({
      status: 302,
      headers: { location: 'https://internal.example.test' },
      body: ''
    })
  });
  await rejectsCode(
    () => client.get('https://provider.example.test/redirect', HTTPS_CONTEXT),
    'EGRESS_REDIRECT_BLOCKED'
  );
});

test('SSRF-ATTACK-008: redirects never forward credential material to a new origin', async () => {
  const requests = [];
  const client = new HttpClient({
    egressPolicy: policyFor(['8.8.8.8']),
    transport: async (request) => {
      requests.push(request);
      return {
        status: 302,
        headers: { location: 'https://internal.example.test' },
        body: ''
      };
    }
  });
  await rejectsCode(
    () => client.get('https://provider.example.test/redirect-with-secret', {
      ...HTTPS_CONTEXT,
      bearerToken: 'test-bearer-token'
    }),
    'EGRESS_REDIRECT_BLOCKED'
  );
  assert.equal(requests.length, 1);
  assert.equal(requests[0].headers.Authorization, 'Bearer test-bearer-token');
});

test('SSRF-ATTACK-009: malformed targets and scheme confusion are rejected', async () => {
  const policy = policyFor(['8.8.8.8']);
  await rejectsCode(() => policy.admit('http://example.test/x', HTTPS_CONTEXT), 'EGRESS_SCHEME_BLOCKED');
  await rejectsCode(() => policy.admit('https://user:password@example.test/x', HTTPS_CONTEXT), 'EGRESS_INVALID_TARGET');
  await rejectsCode(() => policy.admit('https://127.0.0.1:443/x', HTTPS_CONTEXT), 'EGRESS_TARGET_BLOCKED');
  await rejectsCode(() => policy.admit('https://example..test/x', HTTPS_CONTEXT), 'EGRESS_INVALID_TARGET');
});

test('SSRF-ATTACK-010: port policy preserves an explicitly admitted port', async () => {
  let request;
  const client = new HttpClient({
    egressPolicy: policyFor(['8.8.8.8']),
    transport: async (value) => {
      request = value;
      return { status: 204, headers: {}, body: '' };
    }
  });
  await client.get('https://provider.example.test:8443/me', {
    ...HTTPS_CONTEXT,
    purpose: 'OAUTH_PROFILE_LOOKUP',
    bearerToken: 'test-bearer-token'
  });
  assert.equal(request.route.port, 8443);
  assert.equal(request.route.hostHeader, 'provider.example.test:8443');
});

test('SSRF-ATTACK-011: private exceptions are exact, bounded, and never override hard blocks', async () => {
  const ftpPolicy = new EgressPolicy({
    allowPrivateNetworks: true,
    privateException: {
      protocol: 'ftp',
      purpose: 'CREDENTIAL_CONNECTION_TEST',
      hostname: 'internal.example.test',
      cidr: '10.0.0.0/24',
      port: 21
    },
    lookup: async () => [{ address: '10.0.0.8', family: 4 }]
  });
  const ftpContext = { pathId: 'FTP-DRAFT', purpose: 'CREDENTIAL_CONNECTION_TEST', protocol: 'ftp', port: 21 };
  assert.equal((await ftpPolicy.admit('internal.example.test', ftpContext)).connectAddress, '10.0.0.8');
  await rejectsCode(() => ftpPolicy.admit('other.example.test', ftpContext), 'EGRESS_TARGET_BLOCKED');
  await rejectsCode(() => ftpPolicy.admit('internal.example.test', { ...ftpContext, port: 22 }), 'EGRESS_TARGET_BLOCKED');
  await rejectsCode(() => ftpPolicy.admit('internal.example.test', { ...ftpContext, protocol: 'sftp' }), 'EGRESS_TARGET_BLOCKED');
  await rejectsCode(() => ftpPolicy.admit('internal.example.test', { ...ftpContext, purpose: 'OAUTH_REFRESH' }), 'EGRESS_TARGET_BLOCKED');
  await rejectsCode(
    () => new EgressPolicy({
      allowPrivateNetworks: true,
      lookup: async () => [{ address: '10.0.0.8', family: 4 }]
    }).admit('internal.example.test', ftpContext),
    'EGRESS_TARGET_BLOCKED'
  );
  assert.throws(
    () => new EgressPolicy({
      allowPrivateNetworks: true,
      privateException: { protocol: 'ftp', purpose: 'CREDENTIAL_CONNECTION_TEST', cidr: '10.0.0.0/24', port: 21 }
    }),
    (error) => error.code === 'EGRESS_INVALID_CONTEXT'
  );
  assert.throws(
    () => new EgressPolicy({
      allowPrivateNetworks: true,
      privateException: { protocol: 'ftp', purpose: 'CREDENTIAL_CONNECTION_TEST', hostname: 'internal.example.test', cidr: '10.0.0.0/24/ignored', port: 21 }
    }),
    (error) => error.code === 'EGRESS_INVALID_CONTEXT'
  );
  await rejectsCode(
    () => new EgressPolicy({
      allowPrivateNetworks: true,
      privateException: { protocol: 'ftp', purpose: 'CREDENTIAL_CONNECTION_TEST', hostname: 'internal.example.test', cidr: '10.0.0.0/24', port: 21 },
      lookup: async () => [{ address: '10.0.1.8', family: 4 }]
    }).admit('internal.example.test', ftpContext),
    'EGRESS_TARGET_BLOCKED'
  );
  await rejectsCode(() => ftpPolicy.admit('127.0.0.1', ftpContext), 'EGRESS_TARGET_BLOCKED');
  await rejectsCode(() => new EgressPolicy({ allowPrivateNetworks: true }).admit('https://10.0.0.8/x', HTTPS_CONTEXT), 'EGRESS_TARGET_BLOCKED');

  const sftpPolicy = new EgressPolicy({
    allowPrivateNetworks: true,
    privateException: { protocol: 'sftp', purpose: 'PROVIDER_HEALTH_CHECK', hostname: 'internal-sftp.example.test', cidr: 'fc00::/7', port: 22 },
    lookup: async () => [{ address: 'fc00::8', family: 6 }]
  });
  assert.equal((await sftpPolicy.admit('internal-sftp.example.test', { pathId: 'SFTP-STORED', purpose: 'PROVIDER_HEALTH_CHECK', protocol: 'sftp', port: 22 })).connectAddress, 'fc00::8');
});

test('SSRF-ATTACK-012: connector bypass attempts are blocked before any connection', async () => {
  let connects = 0;
  const blockedClient = new FtpClient({
    egressPolicy: policyFor(['127.0.0.1']),
    connector: { async connect() { connects += 1; } }
  });
  await rejectsCode(() => blockedClient.testConnection({ host: '127.0.0.1', port: 21, username: 'u', password: 'test-password' }), 'EGRESS_TARGET_BLOCKED');
  assert.equal(connects, 0);

  const policy = policyFor(['8.8.8.8']);
  const seen = [];
  const ftp = new FtpClient({
    egressPolicy: policy,
    connector: { async connect(options) { seen.push(['ftp', options.host, options.servername]); return { async disconnect() {} }; } }
  });
  const sftp = new SftpClient({
    egressPolicy: policy,
    connector: { async connect(options) { seen.push(['sftp', options.host, options.hostKeyAlias]); return { async disconnect() {} }; } }
  });
  await ftp.testConnection({ host: 'ftp.example.test', port: 21, username: 'u', password: 'test-password', purpose: 'CREDENTIAL_CONNECTION_TEST', pathId: 'FTP-DRAFT' });
  await sftp.testConnection({ host: 'sftp.example.test', port: 22, username: 'u', password: 'test-password', purpose: 'PROVIDER_VALIDATION', pathId: 'SFTP-STORED' });
  assert.deepEqual(seen, [
    ['ftp', '8.8.8.8', 'ftp.example.test'],
    ['sftp', '8.8.8.8', 'sftp.example.test']
  ]);
  await rejectsCode(
    () => policy.admit('https://future.example.test/x', { ...HTTPS_CONTEXT, purpose: 'SECURITY_INTELLIGENCE' }),
    'EGRESS_INVALID_CONTEXT'
  );
});

test('SSRF-ATTACK-013: response materialization is bounded', async () => {
  const originalRequest = https.request;
  let chunksSent = 0;
  let destroyed = 0;
  let responseEnded = false;

  // Exercise requestHttps directly through HttpClient's default transport and
  // cross the limit on the second streamed chunk.
  https.request = (options, callback) => {
    const request = new EventEmitter();
    request.setTimeout = () => {};
    request.end = () => {
      const response = new EventEmitter();
      response.statusCode = 200;
      response.headers = { 'content-type': 'text/plain' };
      response.destroy = () => { destroyed += 1; };
      response.once('end', () => { responseEnded = true; });
      callback(response);
      response.emit('data', Buffer.from('1234'));
      chunksSent += 1;
      response.emit('data', Buffer.from('56789'));
      chunksSent += 1;
    };
    return request;
  };

  try {
    const client = new HttpClient({
      maxResponseBytes: 8,
      egressPolicy: policyFor(['8.8.8.8'])
    });
    await rejectsCode(
      () => client.get('https://provider.example.test/large', HTTPS_CONTEXT),
      'EGRESS_RESPONSE_LIMIT_EXCEEDED'
    );
  } finally {
    https.request = originalRequest;
  }

  assert.equal(chunksSent, 2);
  assert.equal(destroyed, 1);
  assert.equal(responseEnded, false);
});

test('SSRF-ATTACK-014: failed transport has no hidden retry or second admission', async () => {
  let lookups = 0;
  let calls = 0;
  const client = new HttpClient({
    egressPolicy: new EgressPolicy({ lookup: async () => { lookups += 1; return [{ address: '8.8.8.8', family: 4 }]; } }),
    transport: async () => {
      calls += 1;
      throw new EgressError('EGRESS_TRANSPORT_FAILED', null, { statusCode: 502 });
    }
  });
  await rejectsCode(() => client.get('https://provider.example.test/retry', HTTPS_CONTEXT), 'EGRESS_TRANSPORT_FAILED');
  assert.equal(lookups, 1);
  assert.equal(calls, 1);
});
