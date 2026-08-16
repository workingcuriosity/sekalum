import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { AdminApiClient, ConsumerApiClient, ManagementTokenStore } from '../../public/admin/auth.js';

const ADMIN_MODULES = [
  'dashboard.js',
  'wizard.js',
  'api-tokens.js',
  'credential-transfer.js',
  'credentials.js',
  'providers.js',
  'consumer-grants.js'
];

function storage() {
  const values = new Map();
  return { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
}

function response({ ok = true, status = 200, contentType = 'application/json', body = { success: true, data: {} } } = {}) {
  return {
    ok,
    status,
    headers: { get: (name) => name.toLowerCase() === 'content-type' ? contentType : null },
    json: async () => body,
    text: async () => typeof body === 'string' ? body : JSON.stringify(body)
  };
}

function header(headers, name) {
  return headers[name.toLowerCase()] ?? headers[name];
}

test('management token lifecycle trims, persists for the session, clears, and falls back to memory', () => {
  const session = storage();
  const store = new ManagementTokenStore({ storage: session });
  assert.equal(store.getToken(), '');
  assert.throws(() => store.setToken('  '), /Management-Token/);
  store.setToken('  management-token  ');
  assert.equal(store.getToken(), 'management-token');
  store.clearToken();
  assert.equal(store.getToken(), '');

  const unavailable = { getItem() { return null; }, setItem() { throw new Error('blocked'); }, removeItem() {} };
  const fallback = new ManagementTokenStore({ storage: unavailable });
  fallback.setToken('memory-token');
  assert.equal(fallback.getToken(), 'memory-token');
});

test('Safari-style blocked session storage still retains the token in memory for Bearer requests', async () => {
  const blockedStorage = {
    getItem() { throw new Error('SecurityError'); },
    setItem() { throw new Error('SecurityError'); },
    removeItem() { throw new Error('SecurityError'); }
  };
  const store = new ManagementTokenStore({ storage: blockedStorage });
  const calls = [];
  const client = new AdminApiClient({
    tokenStore: store,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return response();
    }
  });

  store.setToken(' safari-management-token ');
  await client.get('/api/v1/dashboard', { headers: { forEach(callback) { callback('safari', 'x-request-id'); } } });

  assert.equal(store.getToken(), 'safari-management-token');
  assert.equal(calls.length, 1);
  assert.equal(header(calls[0].options.headers, 'authorization'), 'Bearer safari-management-token');
  assert.equal(header(calls[0].options.headers, 'x-request-id'), 'safari');
  assert.equal(calls[0].options.headers instanceof Object, true);
});

test('AdminApiClient avoids iterator-only Headers APIs used by older WebKit', () => {
  const source = fs.readFileSync(path.resolve('public/admin/auth.js'), 'utf8');
  assert.doesNotMatch(source, /new Headers\s*\(/);
  assert.doesNotMatch(source, /headers\.values\s*\(/);
});

test('default fetch keeps the Window context required by Safari', async () => {
  const originalFetch = globalThis.fetch;
  const receivers = [];
  globalThis.fetch = function safariFetch() {
    receivers.push(this);
    return Promise.resolve(response());
  };
  try {
    const store = new ManagementTokenStore({ storage: storage() });
    store.setToken('management-token');
    await new AdminApiClient({ tokenStore: store }).get('/api/v1/dashboard');
    await new ConsumerApiClient().request('/api/v1/consumer/credentials/id/resolve', 'consumer-token');
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.deepEqual(receivers, [globalThis, globalThis]);
});

test('AdminApiClient exclusively builds Bearer JSON requests and surfaces response failures', async () => {
  const calls = [];
  const store = new ManagementTokenStore({ storage: storage() });
  const client = new AdminApiClient({ tokenStore: store, fetchImpl: async (url, options) => { calls.push({ url, options }); return response(); } });

  await assert.rejects(client.get('/api/v1/dashboard'), /Kein Management-Token/);
  assert.equal(calls.length, 0, 'a missing token must fail before fetch');
  store.setToken('management-token');
  await client.get('/api/v1/dashboard');
  await client.post('/api/v1/credentials', { name: 'credential' });
  await client.put('/api/v1/credentials/id', { name: 'updated' });
  await client.delete('/api/v1/credentials/id');
  for (const { options } of calls) {
    assert.equal(header(options.headers, 'authorization'), 'Bearer management-token');
    assert.equal(header(options.headers, 'accept'), 'application/json');
  }
  assert.equal(header(calls[1].options.headers, 'content-type'), 'application/json');
  await assert.rejects(client.get('/api/v1/test', { headers: { Authorization: 'Bearer other' } }), /eigene Authentifizierung/);
  await assert.rejects(client.get('/api/v1/test', { headers: { 'x-credential-hub-user': 'admin' } }), /eigene Authentifizierung/);
  await assert.rejects(client.get('/api/v1/test', { headers: { 'x-test': 'Basic encoded' } }), /Basic Authentication/);

  const failing = new AdminApiClient({ tokenStore: store, fetchImpl: async () => response({ ok: false, status: 401, body: { error: { code: 'API_TOKEN_AUTH_FAILED', message: 'Invalid token' } } }) });
  await assert.rejects(failing.get('/api/v1/dashboard'), (error) => error.code === 'API_TOKEN_AUTH_FAILED' && error.message === 'Invalid token');
  const textClient = new AdminApiClient({ tokenStore: store, fetchImpl: async () => response({ ok: false, status: 502, contentType: 'text/plain', body: 'Gateway unavailable' }) });
  await assert.rejects(textClient.get('/api/v1/dashboard'), /Gateway unavailable/);
});

test('ConsumerApiClient also centralizes Bearer headers for the wizard resolve flow', async () => {
  const calls = [];
  const client = new ConsumerApiClient({ fetchImpl: async (url, options) => { calls.push({ url, options }); return response(); } });

  await assert.rejects(client.request('/api/v1/consumer/credentials/id/resolve', ''), /Consumer-Token/);
  await client.request('/api/v1/consumer/credentials/id/resolve', ' consumer-token ', { method: 'POST', body: JSON.stringify({ secretNames: ['apiKey'] }) });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.headers.Authorization, 'Bearer consumer-token');
  assert.equal(calls[0].options.headers.Accept, 'application/json');
  assert.equal(calls[0].options.headers['Content-Type'], 'application/json');
});

test('every expected admin page exists and delegates protected requests to auth.js', () => {
  for (const file of ADMIN_MODULES) {
    const source = fs.readFileSync(path.resolve('public/admin', file), 'utf8');
    assert.match(source, /from ['"]\.\/auth\.js['"]/, `${file} imports the shared auth boundary`);
    assert.doesNotMatch(source, /\bfetch\s*\(/, `${file} has no direct fetch`);
    assert.doesNotMatch(source, /x-credential-hub-user/i, `${file} has no legacy header`);
    assert.doesNotMatch(source, /headers\s*:\s*[^\n]*Bearer/i, `${file} has no page-local Bearer header`);
    assert.doesNotMatch(source, /localStorage|sessionStorage|managementToken\s*:/i, `${file} has no page-local management-token storage`);
  }
});
