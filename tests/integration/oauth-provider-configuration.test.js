import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';

function createServer(providerManager) {
  return new OAuthCallbackServer({
    providerManager,
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    config: { get() { return 0; } },
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

test('OAuth start accepts provider configuration without returning secret values', async () => {
  const httpServer = createServer({
    async startOAuth(provider, options) {
      assert.equal(provider, 'x');
      assert.equal(options.providerConfiguration.clientSecret, 'browser-secret');
      assert.match(options.providerConfiguration.redirectUri, /^http:\/\/127\.0\.0\.1:\d+\/oauth\/x\/callback$/);
      return {
        success: true,
        data: {
          authorizationUrl: `https://twitter.com/i/oauth2/authorize?client_id=x-client&redirect_uri=${encodeURIComponent(options.providerConfiguration.redirectUri)}`,
          providerConfigurationId: 'configuration-1'
        }
      };
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: baseUrl },
      body: JSON.stringify({
        providerConfiguration: {
          clientId: 'x-client',
          clientSecret: 'browser-secret',
          redirectUri: 'https://attacker.example/oauth/x/callback'
        }
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.data.providerConfigurationId, 'configuration-1');
    assert.equal(body.data.redirectUri, `${baseUrl}/oauth/x/callback`);
    assert.equal(body.data.callbackPath, '/oauth/x/callback');
    assert.deepEqual(body.data.scopes, []);
    assert.equal(JSON.stringify(body).includes('browser-secret'), false);
  } finally {
    server.close();
  }
});

test('OAuth start derives a BASE_PATH-safe redirect URI from the request origin', async () => {
  const httpServer = new OAuthCallbackServer({
    providerManager: {
      async startOAuth(_provider, options) {
        assert.match(options.providerConfiguration.redirectUri, /^http:\/\/127\.0\.0\.1:\d+\/credential-hub\/oauth\/x\/callback$/);
        return { success: true, data: { authorizationUrl: `https://example.com/authorize?redirect_uri=${encodeURIComponent(options.providerConfiguration.redirectUri)}` } };
      }
    },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    config: { get(key, fallback) { return key === 'BASE_PATH' ? '/credential-hub' : fallback; } },
    logger: { success() {}, info() {}, error() {} },
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/credential-hub/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: baseUrl },
      body: JSON.stringify({ providerConfiguration: { clientId: 'x-client' } })
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.data.redirectUri, `${baseUrl}/credential-hub/oauth/x/callback`);
    assert.equal(body.data.callbackPath, '/credential-hub/oauth/x/callback');
  } finally {
    server.close();
  }
});

test('OAuth start uses a validated public base URL behind a reverse proxy', async () => {
  const httpServer = new OAuthCallbackServer({
    providerManager: {
      async startOAuth(_provider, options) {
        assert.equal(options.providerConfiguration.redirectUri, 'https://hub.example.test/credential-hub/oauth/x/callback');
        return {
          success: true,
          data: { authorizationUrl: `https://example.com/authorize?scope=openid%20email&redirect_uri=${encodeURIComponent(options.providerConfiguration.redirectUri)}` }
        };
      }
    },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    config: {
      get(key, fallback) {
        if (key === 'BASE_PATH') return '/credential-hub';
        if (key === 'PUBLIC_BASE_URL') return 'https://hub.example.test/';
        return fallback;
      }
    },
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/credential-hub/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://untrusted.example.test' },
      body: JSON.stringify({ providerConfiguration: { clientId: 'x-client' } })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.data.redirectUri, 'https://hub.example.test/credential-hub/oauth/x/callback');
    assert.deepEqual(body.data.scopes, ['openid', 'email']);
  } finally {
    server.close();
  }
});

test('OAuth start rejects and cleans up a redirect URI mismatch', async () => {
  const calls = [];
  const httpServer = createServer({
    async startOAuth(_provider, options) {
      return {
        success: true,
        data: {
          authorizationUrl: 'https://provider.example/authorize?redirect_uri=https%3A%2F%2Fwrong.example%2Fcallback',
          providerConfigurationId: 'configuration-mismatch'
        }
      };
    },
    async cancelOAuth(provider, state) {
      calls.push(['cancel', provider, state]);
    },
    async discardProviderConfiguration(configurationId, provider) {
      calls.push(['discard', configurationId, provider]);
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: baseUrl },
      body: JSON.stringify({ providerConfiguration: { clientId: 'x-client' } })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error.code, 'OAUTH_REDIRECT_URI_MISMATCH');
    assert.equal(body.error.details.redirectUri, `${baseUrl}/oauth/x/callback`);
    assert.equal(calls[0][0], 'cancel');
    assert.equal(calls[0][1], 'x');
    assert.equal(typeof calls[0][2], 'string');
    assert.equal(calls.length, 1);
  } finally {
    server.close();
  }
});

test('OAuth start falls back to discarding the configuration when mismatch cancellation fails', async () => {
  const calls = [];
  const httpServer = createServer({
    async startOAuth() {
      return {
        success: true,
        data: {
          authorizationUrl: 'https://provider.example/authorize?redirect_uri=https%3A%2F%2Fwrong.example%2Fcallback',
          providerConfigurationId: 'configuration-mismatch'
        }
      };
    },
    async cancelOAuth() {
      calls.push(['cancel']);
      throw new Error('State cleanup failed');
    },
    async discardProviderConfiguration(configurationId, provider) {
      calls.push(['discard', configurationId, provider]);
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: baseUrl },
      body: JSON.stringify({ providerConfiguration: { clientId: 'x-client' } })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error.code, 'OAUTH_REDIRECT_URI_MISMATCH');
    assert.equal(body.error.details.redirectUri, `${baseUrl}/oauth/x/callback`);
    assert.deepEqual(calls, [
      ['cancel'],
      ['discard', 'configuration-mismatch', 'x']
    ]);
  } finally {
    server.close();
  }
});

test('OAuth server rejects an invalid public base URL at startup', () => {
  assert.throws(() => new OAuthCallbackServer({
    providerManager: {},
    importTokenCommand: {},
    credentialManager: {},
    config: { get(key, fallback) { return key === 'PUBLIC_BASE_URL' ? 'https://hub.example.test/path' : fallback; } },
    logger: { success() {}, info() {}, error() {} }
  }), /PUBLIC_BASE_URL/);
});

test('OAuth start returns a stable provider configuration error code', async () => {
  const httpServer = createServer({
    async startOAuth() {
      return {
        success: false,
        error: { code: 'PROVIDER_CONFIGURATION_MISSING', statusCode: 400 }
      };
    }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ providerConfiguration: {} })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error.code, 'PROVIDER_CONFIGURATION_MISSING');
    assert.doesNotMatch(body.error.message, /X_CLIENT_ID|CLIENT_SECRET/);
  } finally {
    server.close();
  }
});
