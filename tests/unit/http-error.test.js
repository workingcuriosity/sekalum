import test from 'node:test';
import assert from 'node:assert/strict';

import { HttpClient } from '../../src/api/http-client.js';
import { HttpError } from '../../src/api/http-error.js';
import { Logger } from '../../src/logging/logger.js';

test('HttpError maps only the provider redirect mismatch to the stable public code', () => {
  const mismatch = new HttpError({
    message: 'token exchange failed',
    status: 400,
    url: 'https://provider.example/token',
    response: null,
    body: { error: 'redirect_uri_mismatch', error_description: 'raw provider detail' }
  });
  const other = new HttpError({
    message: 'token exchange failed',
    status: 400,
    url: 'https://provider.example/token',
    response: null,
    body: { error: 'invalid_grant' }
  });

  assert.equal(mismatch.code, 'OAUTH_REDIRECT_URI_MISMATCH');
  assert.equal(other.code, undefined);
});

test('HttpError redacts secret query values while retaining safe request context', () => {
  const sentinel = 'PKG03_SENTINEL_ACCESS_TOKEN';
  const url = `https://provider.example.test/me?fields=id&Access_Token=${sentinel}&code=${sentinel}&state=${sentinel}`;
  const error = new HttpError({
    message: `GET ${url} failed`,
    status: 400,
    url,
    response: { status: 400, ok: false, redirected: false, type: 'basic', url },
    body: { access_token: sentinel, error: 'invalid_token' }
  });

  const serialized = JSON.stringify(error);
  assert.equal(serialized.includes(sentinel), false);
  assert.match(error.url, /fields=id/);
  assert.match(error.url, /Access_Token=%5BREDACTED%5D/);
  assert.match(error.url, /code=%5BREDACTED%5D/);
  assert.match(error.url, /state=%5BREDACTED%5D/);
  assert.match(error.message, /Access_Token=%5BREDACTED%5D/);
  assert.equal(error.body.access_token, '[REDACTED]');
  assert.equal(error.response.url, error.url);
});

test('HttpError fails closed for malformed secret-bearing request targets', () => {
  const sentinel = 'PKG03_SENTINEL_ACCESS_TOKEN';
  const malformedUrl = `not-a-url?access_token=${sentinel}`;
  const error = new HttpError({
    message: `GET ${malformedUrl} failed`,
    status: 400,
    url: malformedUrl,
    response: null,
    body: null
  });

  assert.equal(error.url, '[REDACTED]');
  assert.equal(JSON.stringify(error).includes(sentinel), false);
});

test('HttpClient keeps the raw query only at the transient fetch boundary', async () => {
  const sentinel = 'PKG03_SENTINEL_ACCESS_TOKEN';
  const originalFetch = globalThis.fetch;
  let observedTarget;
  globalThis.fetch = async (target, options) => {
    observedTarget = String(target);
    assert.equal(options.redirect, 'error');
    return new Response(JSON.stringify({ error: 'invalid_token' }), {
      status: 401,
      headers: { 'content-type': 'application/json' }
    });
  };

  try {
    await assert.rejects(
      new HttpClient().get('https://provider.example.test/me', { query: { access_token: sentinel } }),
      (error) => {
        assert.equal(JSON.stringify(error).includes(sentinel), false);
        assert.equal(error.url.includes(sentinel), false);
        assert.equal(error.message.includes(sentinel), false);
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(observedTarget.includes(sentinel), true);
});

test('logger serialization of HttpError remains secret-free', () => {
  const sentinel = 'PKG03_SENTINEL_CLIENT_SECRET';
  const url = `https://provider.example.test/token?client_secret=${sentinel}`;
  const error = new HttpError({
    message: `POST ${url} failed`,
    status: 400,
    url,
    response: new Response(null, { status: 400 }),
    body: { error: 'invalid_client', client_secret: sentinel }
  });
  const output = [];
  const originalLog = console.log;
  console.log = (...args) => output.push(args);

  try {
    new Logger().error(error);
  } finally {
    console.log = originalLog;
  }

  assert.equal(JSON.stringify(output).includes(sentinel), false);
});
