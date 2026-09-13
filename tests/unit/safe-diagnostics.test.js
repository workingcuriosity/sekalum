import test from 'node:test';
import assert from 'node:assert/strict';

import { REDACTED, safeError, sanitizeDiagnostic } from '../../src/utils/safe-diagnostics.js';
import { AuditLogService } from '../../src/services/audit-log-service.js';
import { Logger } from '../../src/logging/logger.js';
import { ProviderController } from '../../src/controllers/provider-controller.js';

const SECRET_VALUES = [
  'TEST_SECRET_A',
  'TEST_SECRET_B',
  'TEST_TOKEN_C',
  'TEST_COOKIE_D',
  'TEST_KEY_E'
];

function serialized(value) {
  return JSON.stringify(value);
}

test('sanitizes nested headers, request bodies, URLs, causes and case variants', () => {
  const error = new Error('Request failed: Bearer TEST_TOKEN_C {"api_key":"REAL_SECRET_VALUE"}');
  error.code = 'UPSTREAM_FAILURE';
  error.request = {
    headers: {
      Authorization: 'Bearer TEST_SECRET_A',
      'X-API-Key': 'TEST_SECRET_B',
      Cookie: 'session=TEST_COOKIE_D'
    },
    url: 'https://provider.example.test/check?access_token=TEST_TOKEN_C&safe=value',
    body: { client_secret: 'TEST_KEY_E', displayName: 'safe' }
  };
  error.cause = { response: { headers: { authorization: 'TEST_SECRET_A' } } };

  const result = sanitizeDiagnostic(error);
  const output = serialized(result);

  for (const secret of SECRET_VALUES) assert.equal(output.includes(secret), false, secret);
  assert.equal(output.includes('REAL_SECRET_VALUE'), false);
  assert.equal(result.request.headers.Authorization, REDACTED);
  assert.equal(result.request.body.displayName, 'safe');
  assert.match(result.message, /Bearer \[REDACTED\]/);
  assert.match(result.request.url, /access_token=%5BREDACTED%5D/);
});

test('safeError keeps classification metadata but omits raw exception structure', () => {
  const error = Object.assign(new Error('invalid response TEST_SECRET_A'), {
    code: 'UPSTREAM_INVALID',
    status: 502,
    statusCode: 502,
    correlationId: 'corr-167',
    request: { body: { password: 'TEST_SECRET_A' } },
    stack: 'secret-bearing stack TEST_SECRET_A'
  });

  const result = safeError(error);
  const output = serialized(result);

  assert.equal(result.code, 'UPSTREAM_INVALID');
  assert.equal(result.status, 502);
  assert.equal(result.correlationId, 'corr-167');
  assert.equal('request' in result, false);
  assert.equal('stack' in result, false);
  assert.equal(output.includes('TEST_SECRET_A'), false);
});

test('audit, logger and API error boundaries reject injected secret-bearing diagnostics', async () => {
  const audit = new AuditLogService();
  await audit.record({
    action: 'provider.failed',
    targetType: 'provider',
    details: {
      error: Object.assign(new Error('upstream TEST_SECRET_A'), {
        request: { headers: { Authorization: 'Bearer TEST_TOKEN_C' } },
        response: { body: { refresh_token: 'TEST_TOKEN_C' } }
      }),
      config: { client_secret: 'TEST_KEY_E' }
    }
  });

  const auditOutput = JSON.stringify(await audit.list());
  for (const secret of SECRET_VALUES) assert.equal(auditOutput.includes(secret), false, `audit ${secret}`);

  const logOutput = [];
  const originalLog = console.log;
  console.log = (...args) => logOutput.push(args);
  try {
    new Logger().error('provider failed', {
      request: { headers: { authorization: 'Bearer TEST_SECRET_A' } },
      body: { access_token: 'TEST_TOKEN_C' }
    });
  } finally {
    console.log = originalLog;
  }
  const serializedLogs = JSON.stringify(logOutput);
  for (const secret of SECRET_VALUES) assert.equal(serializedLogs.includes(secret), false, `log ${secret}`);

  const controller = new ProviderController({
    providerManager: {
      async getProvider() {
        throw Object.assign(new Error('request failed: Bearer TEST_SECRET_A'), {
          code: 'UPSTREAM_FAILURE',
          request: { headers: { cookie: 'session=TEST_COOKIE_D' } },
          response: { body: { api_key: 'TEST_SECRET_B' } }
        });
      }
    }
  });
  const response = { statusCode: null, payload: null, status(code) { this.statusCode = code; return this; }, json(payload) { this.payload = payload; } };
  await controller.get({ params: { providerKey: 'openai' } }, response);
  const apiOutput = JSON.stringify(response.payload);
  for (const secret of SECRET_VALUES) assert.equal(apiOutput.includes(secret), false, `api ${secret}`);
  assert.equal(response.payload.error.code, 'UPSTREAM_FAILURE');
  assert.match(response.payload.error.message, /Bearer \[REDACTED\]/);
});
