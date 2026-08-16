import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeBasePath, normalizePublicBaseUrl, withBasePath } from '../../src/config/base-path.js';
import { applicationPath, detectedBasePath } from '../../public/admin/base-path.js';

test('normalizes the root base path and trimmed subpaths', () => {
  assert.equal(normalizeBasePath(undefined), '/');
  assert.equal(normalizeBasePath(' / '), '/');
  assert.equal(normalizeBasePath('credential-hub/'), '/credential-hub');
  assert.equal(normalizeBasePath('/credential-hub/admin/'), '/credential-hub/admin');
});

test('rejects unsafe or malformed base paths', () => {
  for (const value of ['/credential hub', '/credential-hub?debug=true', '/credential-hub#anchor', '/credential//hub']) {
    assert.throws(() => normalizeBasePath(value), /BASE_PATH/);
  }
});

test('prefixes application routes without changing the root deployment', () => {
  assert.equal(withBasePath('/', '/health'), '/health');
  assert.equal(withBasePath('/credential-hub/', 'api/v1/providers'), '/credential-hub/api/v1/providers');
});

test('normalizes a public HTTP(S) origin', () => {
  assert.equal(normalizePublicBaseUrl(undefined), null);
  assert.equal(normalizePublicBaseUrl(' https://hub.example.test/ '), 'https://hub.example.test');
  assert.equal(normalizePublicBaseUrl('http://localhost:3000'), 'http://localhost:3000');
});

test('rejects unsafe public base URLs', () => {
  for (const value of ['hub.example.test', 'ftp://hub.example.test', 'https://user:secret@hub.example.test', 'https://hub.example.test/path', 'https://hub.example.test/?debug=1']) {
    assert.throws(() => normalizePublicBaseUrl(value), /PUBLIC_BASE_URL/);
  }
});

test('derives the browser application prefix from root and prefixed admin routes', () => {
  assert.equal(detectedBasePath('/admin/'), '');
  assert.equal(detectedBasePath('/admin'), '');
  assert.equal(detectedBasePath('/credential-hub/admin/dashboard.html'), '/credential-hub');
  assert.equal(detectedBasePath('/credential-hub/admin'), '/credential-hub');
  assert.equal(detectedBasePath('/apps/credential-hub/admin/dashboard.html'), '/apps/credential-hub');
  assert.equal(applicationPath('/api/v1/providers', '/credential-hub/admin/'), '/credential-hub/api/v1/providers');
  assert.equal(applicationPath('/oauth/google/login', '/apps/credential-hub/admin'), '/apps/credential-hub/oauth/google/login');
});
