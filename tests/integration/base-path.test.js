import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';

function createServer(basePath) {
  return new OAuthCallbackServer({
    providerManager: {
      listProviders() { return []; },
      getProvider() { throw new Error('not used'); },
      async cancelOAuth() { return false; }
    },
    importTokenCommand: {},
    credentialManager: {
      async listCredentials() { return []; }
    },
    schedulerService: { listJobs() { return []; } },
    config: {
      get(key, fallback) {
        if (key === 'BASE_PATH') return basePath;
        return fallback;
      }
    },
    logger: { success() {}, info() {}, error() {} }
  });
}

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

test('serves admin, health, and API metadata below a configured base path', async () => {
  const httpServer = createServer('/credential-hub/');
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const root = await fetch(`${baseUrl}/`, { redirect: 'manual' });
    assert.equal(root.status, 302);
    assert.equal(root.headers.get('location'), '/credential-hub/admin/');

    const base = await fetch(`${baseUrl}/credential-hub/`, { redirect: 'manual' });
    assert.equal(base.status, 302);
    assert.equal(base.headers.get('location'), '/credential-hub/admin/');

    const health = await fetch(`${baseUrl}/credential-hub/health`);
    assert.deepEqual(await health.json(), { status: 'UP' });

    const admin = await fetch(`${baseUrl}/credential-hub/admin/`);
    assert.equal(admin.status, 200);
    assert.match(await admin.text(), /Credential Wizard/);

    const metadata = await fetch(`${baseUrl}/credential-hub/api/v1/credentials/meta`);
    const body = await metadata.json();
    assert.equal(metadata.status, 200);
    assert.equal(body.data.endpoints.list.path, '/credential-hub/api/v1/credentials');

    const cancelledOAuth = await fetch(`${baseUrl}/credential-hub/oauth/threads/callback?error=access_denied`, { redirect: 'manual' });
    assert.equal(cancelledOAuth.status, 400);
    const cancelledPage = await cancelledOAuth.text();
    assert.match(cancelledPage, /data-oauth-result="cancelled"/);
    assert.match(cancelledPage, /href="\/credential-hub\/admin\/\?oauth=cancelled&amp;code=OAUTH_PROVIDER_REJECTED&amp;provider=threads"/);
    assert.match(cancelledPage, /href="\/credential-hub\/admin\/dashboard\.html"/);

    const unprefixedHealth = await fetch(`${baseUrl}/health`);
    assert.equal(unprefixedHealth.status, 404);
  } finally {
    server.close();
  }
});
