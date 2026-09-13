import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';
import { listenOAuthCallbackServer } from '../support/oauth-callback-test-server.js';
import {
  AbuseAdmission,
  AbuseAdmissionResult,
  AbusePolicyClass
} from '../../src/security/abuse-admission.js';
import { resolveTrustedSourceIdentity } from '../../src/security/trusted-source-identity.js';

const silentLogger = Object.freeze({ success() {}, info() {}, error() {} });

function clock(start = 0) {
  let now = start;
  return {
    now: () => now,
    advance: (milliseconds) => { now += milliseconds; }
  };
}

function admission(policyClass, overrides = {}, options = {}) {
  return new AbuseAdmission({
    ...options,
    policyOverrides: { [policyClass]: overrides }
  });
}

async function listen(app) {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

function testServer(abuseAdmission, providerManager = {}, overrides = {}) {
  return new OAuthCallbackServer({
    providerManager: { listProviders() { return []; }, ...providerManager },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    schedulerService: { listJobs() { return []; } },
    abuseAdmission,
    config: { get(key, fallback = null) {
      if (key === 'NODE_ENV') return 'test';
      if (key === 'OAUTH_CALLBACK_PORT') return 0;
      return fallback;
    } },
    logger: silentLogger,
    ...overrides
  });
}

test('ABUSE-ATTACK-001: Resolve and discovery harvesting is bounded before amplification', () => {
  const limiter = admission(AbusePolicyClass.CONSUMER_DISCOVERY, { capacity: 2 });
  const input = {
    policyClass: AbusePolicyClass.CONSUMER_DISCOVERY,
    sourceIdentity: 'source:one',
    consumerIdentity: 'consumer-one'
  };
  assert.equal(limiter.decide(input).result, AbuseAdmissionResult.ALLOW);
  assert.equal(limiter.decide(input).result, AbuseAdmissionResult.ALLOW);
  assert.equal(limiter.decide(input).result, AbuseAdmissionResult.THROTTLE);
});

test('ABUSE-ATTACK-002: spoofed forwarded source cannot bypass the source budget', () => {
  const first = resolveTrustedSourceIdentity({
    socket: { remoteAddress: '10.0.0.8' },
    headers: { 'x-forwarded-for': '198.51.100.1' }
  });
  const second = resolveTrustedSourceIdentity({
    socket: { remoteAddress: '10.0.0.8' },
    headers: { 'x-forwarded-for': '198.51.100.2' }
  });
  assert.equal(first.identity, second.identity);
});

test('ABUSE-ATTACK-003: IPv4, IPv6 and mapped address spellings share canonical identity', () => {
  const ipv4 = resolveTrustedSourceIdentity({ socket: { remoteAddress: '127.0.0.1' }, headers: {} });
  const mapped = resolveTrustedSourceIdentity({ socket: { remoteAddress: '::ffff:127.0.0.1' }, headers: {} });
  const ipv6 = resolveTrustedSourceIdentity({ socket: { remoteAddress: '::1' }, headers: {} });
  assert.equal(ipv4.identity, mapped.identity);
  assert.notEqual(ipv4.identity, ipv6.identity);
});

test('ABUSE-ATTACK-004: invalid bearer churn never creates token-shaped limiter keys', () => {
  const limiter = new AbuseAdmission({ maxTotalKeys: 16, domainQuotas: { source: 4, global: 1 } });
  for (let index = 0; index < 20; index += 1) {
    assert.equal(limiter.decide({
      policyClass: AbusePolicyClass.PRE_AUTH_FAILURE,
      sourceIdentity: 'source:one',
      apiTokenIdentity: `raw-invalid-token-${index}`
    }).result, AbuseAdmissionResult.ALLOW);
  }
  const keys = limiter.snapshot().buckets.map(({ key }) => key);
  assert.equal(keys.some((key) => key.includes('raw-invalid-token')), false);
  assert.equal(limiter.snapshot().totalKeys <= 16, true);
});

test('ABUSE-ATTACK-005: throttled responses do not disclose resource existence', async () => {
  const server = testServer(admission(AbusePolicyClass.PRE_AUTH_FAILURE, { capacity: 1 }));
  const http = await listenOAuthCallbackServer(server);
  try {
    const first = await fetch(`${http.baseUrl}/api/v1/credentials/meta`);
    assert.equal(first.status, 200);
    const throttled = await fetch(`${http.baseUrl}/api/v1/credentials/not-a-real-id`);
    assert.equal(throttled.status, 429);
    assert.equal(await throttled.text(), JSON.stringify({ error: { code: 'RATE_LIMITED', message: 'Too many requests. Please retry later.' } }));
    assert.match(throttled.headers.get('retry-after') ?? '', /^[1-9][0-9]*$/);
    assert.equal(throttled.headers.get('cache-control'), 'no-store');
  } finally {
    await new Promise((resolve) => http.server.close(resolve));
  }
});

test('ABUSE-ATTACK-005A: every body-bearing route is admitted before JSON parsing', async () => {
  const server = testServer(admission(AbusePolicyClass.PRE_AUTH_FAILURE, { capacity: 1 }));
  const http = await listen(server.app);
  try {
    const health = await fetch(`${http.baseUrl}/health`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
    });
    assert.equal(health.status, 404);

    for (const [pathname, body] of [
      ['/consumer/not-found.js', '{'],
      ['/unmatched-route', '{'],
      ['/api/v1/credentials', '{'],
      ['/shared/not-found.js', JSON.stringify({ payload: 'x'.repeat(1024 * 1024 + 1) })]
    ]) {
      const response = await fetch(`${http.baseUrl}${pathname}`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body
      });
      assert.equal(response.status, 429, pathname);
      assert.deepEqual(await response.json(), {
        error: { code: 'RATE_LIMITED', message: 'Too many requests. Please retry later.' }
      });
    }
  } finally {
    await new Promise((resolve) => http.server.close(resolve));
  }
});

test('ABUSE-ATTACK-005B: OAuth wizard intents have scheduled, per-actor and global bounds', async () => {
  let now = 0;
  let scheduledCleanup = null;
  const starts = [];
  const providerManager = {
    async startOAuth(_provider, options) {
      starts.push(options.actorUserId);
      return {
        success: true,
        data: { authorizationUrl: `https://provider.example.test/?redirect_uri=${encodeURIComponent(options.redirectUri)}` }
      };
    },
    async cancelOAuth() { return true; }
  };
  const overrides = {
    accessManagementService: { async authorize() {}, async listUsers() { return []; } },
    apiTokenService: {
      async createToken() { return {}; },
      async listTokens() { return []; },
      async authenticate(token) { return { authenticated: true, userId: token, scopes: ['providers:manage'] }; }
    },
    config: { get(key, fallback = null) { return key === 'NODE_ENV' ? 'development' : fallback; } },
    oauthStateClock: () => now,
    oauthStateMaxEntries: 2,
    oauthStateMaxPerActor: 1,
    schedule(task) { scheduledCleanup = task; return null; }
  };
  const perActorServer = testServer(new AbuseAdmission({
    maxTotalKeys: 100,
    domainQuotas: { actor: 20 },
    policyOverrides: { [AbusePolicyClass.PRE_AUTH_FAILURE]: { capacity: 20 } }
  }), providerManager, overrides);
  const perActorHttp = await listen(perActorServer.app);
  const start = (baseUrl, token) => fetch(`${baseUrl}/api/v1/providers/google/oauth/start`, {
    method: 'POST', headers: { authorization: `Bearer ${token}`, origin: baseUrl, 'content-type': 'application/json' }, body: '{}'
  });
  try {
    assert.equal((await start(perActorHttp.baseUrl, 'actor-a')).status, 200);
    assert.equal((await start(perActorHttp.baseUrl, 'actor-a')).status, 429);
    now = 10 * 60 * 1000 + 1;
    scheduledCleanup();
    assert.equal((await start(perActorHttp.baseUrl, 'actor-a')).status, 200);
    assert.deepEqual(starts, ['actor-a', 'actor-a', 'actor-a']);
  } finally {
    await new Promise((resolve) => perActorHttp.server.close(resolve));
  }

  const globalServer = testServer(new AbuseAdmission({
    maxTotalKeys: 100,
    domainQuotas: { actor: 20 },
    policyOverrides: { [AbusePolicyClass.PRE_AUTH_FAILURE]: { capacity: 20 } }
  }), providerManager, { ...overrides, oauthStateMaxPerActor: 2, schedule() { return null; } });
  const globalHttp = await listen(globalServer.app);
  try {
    assert.equal((await start(globalHttp.baseUrl, 'actor-a')).status, 200);
    assert.equal((await start(globalHttp.baseUrl, 'actor-b')).status, 200);
    assert.equal((await start(globalHttp.baseUrl, 'actor-c')).status, 429);
  } finally {
    await new Promise((resolve) => globalHttp.server.close(resolve));
  }
});

test('ABUSE-ATTACK-006: 20-item batches pay weighted cost and invalid batches pay maximum cost', () => {
  const valid = admission(AbusePolicyClass.CONSUMER_BATCH_RESOLVE, { capacity: 20 });
  const input = { policyClass: AbusePolicyClass.CONSUMER_BATCH_RESOLVE, sourceIdentity: 'source:one', consumerIdentity: 'consumer-one', apiTokenIdentity: 'token-one' };
  assert.equal(valid.decide({ ...input, cost: 20 }).result, AbuseAdmissionResult.ALLOW);
  assert.equal(valid.decide({ ...input, cost: 1 }).result, AbuseAdmissionResult.THROTTLE);
  const invalid = admission(AbusePolicyClass.CONSUMER_BATCH_RESOLVE, { capacity: 20 });
  assert.equal(invalid.decide({ ...input, cost: 20 }).result, AbuseAdmissionResult.ALLOW);
  assert.equal(invalid.decide({ ...input, cost: 1 }).result, AbuseAdmissionResult.THROTTLE);
});

test('ABUSE-ATTACK-007: parallel batch fan-out is bounded by two leases', () => {
  const limiter = admission(AbusePolicyClass.CONSUMER_BATCH_RESOLVE, { concurrency: 2 });
  const input = { policyClass: AbusePolicyClass.CONSUMER_BATCH_RESOLVE, sourceIdentity: 'source:one', consumerIdentity: 'consumer-one', apiTokenIdentity: 'token-one', cost: 1 };
  const first = limiter.admit(input);
  const second = limiter.admit(input);
  const third = limiter.admit(input);
  assert.equal(first.result, AbuseAdmissionResult.ALLOW);
  assert.equal(second.result, AbuseAdmissionResult.ALLOW);
  assert.equal(third.result, AbuseAdmissionResult.CONCURRENCY_BLOCK);
  limiter.release(first.leaseId);
  limiter.release(second.leaseId);
  assert.equal(limiter.admit(input).result, AbuseAdmissionResult.ALLOW);
});

test('ABUSE-ATTACK-008: invalid OAuth callback does not exchange provider tokens or amplify audit', async () => {
  let exchanges = 0;
  let cancellations = 0;
  const server = testServer(admission(AbusePolicyClass.OAUTH_CALLBACK_INVALID, { capacity: 10 }), {
    async cancelOAuth() { cancellations += 1; return true; },
    async handleOAuthCallback() { exchanges += 1; throw new Error('must not exchange'); }
  });
  const http = await listenOAuthCallbackServer(server);
  try {
    const response = await fetch(`${http.baseUrl}/oauth/google/callback?error=access_denied`, { redirect: 'manual' });
    assert.equal(response.status, 400);
    assert.equal(exchanges, 0);
    assert.equal(cancellations, 1);
  } finally {
    await new Promise((resolve) => http.server.close(resolve));
  }
});

test('ABUSE-ATTACK-009: OAuth start and valid callback have bounded provider-work admission', () => {
  const limiter = admission(AbusePolicyClass.OAUTH_START, { capacity: 1 });
  const input = { policyClass: AbusePolicyClass.OAUTH_START, sourceIdentity: 'source:one', actorIdentity: 'actor-one', providerIdentity: 'google' };
  assert.equal(limiter.admit(input).result, AbuseAdmissionResult.ALLOW);
  assert.equal(limiter.admit(input).result, AbuseAdmissionResult.THROTTLE);
});

test('ABUSE-ATTACK-010: management mutation bursts consume the actor budget', () => {
  const limiter = admission(AbusePolicyClass.MANAGEMENT_MUTATION, { capacity: 2 });
  const input = { policyClass: AbusePolicyClass.MANAGEMENT_MUTATION, sourceIdentity: 'source:one', actorIdentity: 'actor-one' };
  assert.equal(limiter.decide(input).result, AbuseAdmissionResult.ALLOW);
  assert.equal(limiter.decide(input).result, AbuseAdmissionResult.ALLOW);
  assert.equal(limiter.decide(input).result, AbuseAdmissionResult.THROTTLE);
});

test('ABUSE-ATTACK-011: expensive provider work is admitted before the operation budget is exhausted', () => {
  const limiter = admission(AbusePolicyClass.PROVIDER_HEALTH_OR_EXPENSIVE_MANAGEMENT, { capacity: 1, concurrency: 1 });
  const input = { policyClass: AbusePolicyClass.PROVIDER_HEALTH_OR_EXPENSIVE_MANAGEMENT, sourceIdentity: 'source:one', actorIdentity: 'actor-one', providerIdentity: 'google' };
  const first = limiter.admit(input);
  assert.equal(first.result, AbuseAdmissionResult.ALLOW);
  assert.equal(limiter.admit(input).result, AbuseAdmissionResult.THROTTLE);
  limiter.release(first.leaseId);
});

test('ABUSE-ATTACK-012: ordinary budget exhaustion does not block security containment', () => {
  const limiter = new AbuseAdmission({
    policyOverrides: {
      [AbusePolicyClass.MANAGEMENT_MUTATION]: { capacity: 1 },
      [AbusePolicyClass.SECURITY_CONTAINMENT]: { capacity: 1 }
    }
  });
  const ordinary = { policyClass: AbusePolicyClass.MANAGEMENT_MUTATION, sourceIdentity: 'source:one', actorIdentity: 'actor-one' };
  const containment = { policyClass: AbusePolicyClass.SECURITY_CONTAINMENT, sourceIdentity: 'source:one', actorIdentity: 'actor-one' };
  assert.equal(limiter.decide(ordinary).result, AbuseAdmissionResult.ALLOW);
  assert.equal(limiter.decide(ordinary).result, AbuseAdmissionResult.THROTTLE);
  assert.equal(limiter.decide(containment).result, AbuseAdmissionResult.ALLOW);
});

test('ABUSE-ATTACK-012A: unauthenticated containment paths stay pre-auth while authenticated containment uses its reserve', async () => {
  const limiter = new AbuseAdmission({
    policyOverrides: {
      [AbusePolicyClass.PRE_AUTH_FAILURE]: { capacity: 1 },
      [AbusePolicyClass.SECURITY_CONTAINMENT]: { capacity: 1, containmentCapacity: 1 }
    }
  });
  const server = testServer(limiter, {}, {
    accessManagementService: {
      async listUsers() { return []; },
      async isAuthorizationRequired() { return true; },
      async authorize() {}
    }
  });
  const http = await listenOAuthCallbackServer(server);
  try {
    const unauthenticated = await fetch(`${http.baseUrl}/api/v1/providers/example/disable`, { method: 'POST' });
    assert.notEqual(unauthenticated.status, 429);
    assert.equal(limiter.snapshot().buckets.some(({ domain }) => domain === 'containment'), false);

    const authenticated = await fetch(`${http.baseUrl}/api/v1/providers/example/disable`, {
      method: 'POST', headers: { 'x-credential-hub-user': 'operator-one' }
    });
    assert.notEqual(authenticated.status, 429);
    assert.equal(limiter.snapshot().buckets.some(({ domain }) => domain === 'containment'), true);
  } finally {
    await new Promise((resolve) => http.server.close(resolve));
  }
});

test('ABUSE-ATTACK-013: limiter key churn remains bounded and preserves stable identities', () => {
  const limiter = new AbuseAdmission({ maxTotalKeys: 8, domainQuotas: { source: 2 } });
  const stable = { policyClass: AbusePolicyClass.PRE_AUTH_FAILURE, sourceIdentity: 'stable-source' };
  limiter.decide(stable);
  for (let index = 0; index < 100; index += 1) limiter.decide({ ...stable, sourceIdentity: `churn-${index}` });
  const snapshot = limiter.snapshot();
  assert.equal(snapshot.totalKeys <= 8, true);
  assert.equal(snapshot.buckets.some(({ key }) => key.includes('stable-source')), false);
  assert.equal(snapshot.buckets.some(({ key }) => key.endsWith(':overflow')), true);
});

test('ABUSE-ATTACK-014: restart resets local state and request input cannot control clock', () => {
  const time = clock();
  const limiter = admission(AbusePolicyClass.PRE_AUTH_FAILURE, { capacity: 1 }, { clock: time.now });
  const input = { policyClass: AbusePolicyClass.PRE_AUTH_FAILURE, sourceIdentity: 'source:one' };
  assert.equal(limiter.decide(input).result, AbuseAdmissionResult.ALLOW);
  assert.equal(limiter.decide({ ...input, now: Number.MAX_SAFE_INTEGER }).result, AbuseAdmissionResult.THROTTLE);
  limiter.reset();
  assert.equal(limiter.decide(input).result, AbuseAdmissionResult.ALLOW);
});

test('ABUSE-ATTACK-015: Retry-After is bounded and admission performs no hidden retry', () => {
  let decisions = 0;
  const time = clock();
  const limiter = admission(AbusePolicyClass.PRE_AUTH_FAILURE, { capacity: 1 }, { clock: () => { decisions += 1; return time.now(); } });
  const input = { policyClass: AbusePolicyClass.PRE_AUTH_FAILURE, sourceIdentity: 'source:one' };
  const before = decisions;
  limiter.decide(input);
  const result = limiter.decide(input);
  assert.equal(result.result, AbuseAdmissionResult.THROTTLE);
  assert.ok(result.retryAfterSeconds >= 3 && result.retryAfterSeconds <= 60);
  assert.equal(decisions - before, 2);
});
