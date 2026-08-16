import test from 'node:test';
import assert from 'node:assert/strict';

import { HttpError } from '../../src/api/http-error.js';

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
