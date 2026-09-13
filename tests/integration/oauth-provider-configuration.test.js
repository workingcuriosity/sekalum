import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';
import { listenOAuthCallbackServer } from '../support/oauth-callback-test-server.js';

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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

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

test('OAuth callback requires the initiating actor binding cookie', async () => {
  let state;
  let callbackCalls = 0;
  const httpServer = new OAuthCallbackServer({
    providerManager: {
      async startOAuth(_provider, options) {
        state = options.state;
        return {
          success: true,
          data: {
            authorizationUrl: `https://provider.example.test/authorize?state=${encodeURIComponent(options.state)}&redirect_uri=${encodeURIComponent(options.providerConfiguration.redirectUri)}`
          }
        };
      },
      async handleOAuthCallback(_provider, _callback, options) {
        callbackCalls += 1;
        assert.equal(options.expectedActorUserId, 'actor-a');
        return { success: true, data: { provider: 'x', metadata: {} } };
      },
      async cleanupExpiredOAuthContexts() {}
    },
    importTokenCommand: {
      async execute(result) {
        return { credentialId: 'credential-1', provider: result.provider };
      }
    },
    credentialManager: { async listCredentials() { return []; } },
    accessManagementService: {
      async listUsers() { return []; },
      async isAuthorizationRequired() { return true; },
      async authorize(userId) { assert.equal(userId, 'actor-a'); },
      async getUserIdentity(userId) { assert.equal(userId, 'actor-a'); return { userId, principalGeneration: 'generation-a' }; },
      async authorizeCurrentPrincipal(userId, generation) { assert.equal(userId, 'actor-a'); assert.equal(generation, 'generation-a'); },
      async withAuthorizedCurrentPrincipal(userId, generation, permission, operation) {
        await this.authorizeCurrentPrincipal(userId, generation, permission);
        return operation();
      }
    },
    apiTokenService: {
      async createToken() { return {}; },
      async listTokens() { return []; },
      async authenticate(token) {
        assert.equal(token, 'management-token');
        return { authenticated: true, userId: 'actor-a', scopes: ['providers:manage'] };
      }
    },
    config: {
      get(key, fallback) {
        if (key === 'NODE_ENV') return 'development';
        return key === 'OAUTH_WIZARD_INTENT_TTL_MS' ? 60000 : fallback;
      }
    },
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const start = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: { authorization: 'Bearer management-token', 'content-type': 'application/json' },
      body: JSON.stringify({ providerConfiguration: { clientId: 'client-id' } })
    });
    assert.equal(start.status, 200);
    const startBody = await start.json();
    const bindingCookie = start.headers.get('set-cookie');
    assert.match(bindingCookie, /HttpOnly/);
    assert.match(bindingCookie, /SameSite=Lax/);

    const cookieName = bindingCookie.split('=', 1)[0];
    const withoutValidBinding = await fetch(`${baseUrl}/oauth/x/callback?code=code&state=${encodeURIComponent(state)}`, {
      headers: { cookie: `${cookieName}=invalid` }
    });
    assert.ok(withoutValidBinding.status >= 400 && withoutValidBinding.status < 500);
    assert.equal(callbackCalls, 0);

    const withCookie = await fetch(`${baseUrl}/oauth/x/callback?code=code&state=${encodeURIComponent(state)}`, {
      headers: { cookie: bindingCookie.split(';', 1)[0] }
    });
    assert.equal(withCookie.status, 200);
    assert.match(await withCookie.text(), /data-oauth-result="success"/);
    assert.equal(callbackCalls, 1);
    assert.equal(startBody.data.callbackPath, '/oauth/x/callback');
  } finally {
    server.close();
  }
});

test('OAUTH-ATTACK-011: stale actor authority or generation blocks callback exchange and persistence', async () => {
  for (const stale of ['authorization', 'generation']) {
    let state; let callbackCalls = 0; let writes = 0; let authorized = true; let generation = 'generation-a';
    const httpServer = new OAuthCallbackServer({
      providerManager: {
        async startOAuth(_provider, options) { state = options.state; return { success: true, data: { authorizationUrl: `https://provider.example.test/?redirect_uri=${encodeURIComponent(options.providerConfiguration.redirectUri)}` } }; },
        async handleOAuthCallback() { callbackCalls += 1; return { success: true, data: { provider: 'x', metadata: {} } }; },
        async cleanupExpiredOAuthContexts() {}
      },
      importTokenCommand: { async execute() { writes += 1; return { credentialId: 'credential-1' }; } },
      credentialManager: { async listCredentials() { return []; } },
      accessManagementService: {
        async listUsers() { return []; }, async isAuthorizationRequired() { return true; },
        async getUserIdentity(userId) { return { userId, principalGeneration: generation }; },
        async authorize() {},
        async authorizeCurrentPrincipal(_userId, expectedGeneration) { if (!authorized || expectedGeneration !== generation) { const error = new Error('forbidden'); error.statusCode = 403; throw error; } },
        async withAuthorizedCurrentPrincipal(userId, expectedGeneration, permission, operation) {
          await this.authorizeCurrentPrincipal(userId, expectedGeneration, permission);
          return operation();
        }
      },
      apiTokenService: { async authenticate() { return { authenticated: true, userId: 'actor-a', scopes: ['providers:manage'] }; }, async createToken() { return {}; }, async listTokens() { return []; } },
      config: { get(key, fallback) { return key === 'NODE_ENV' ? 'development' : fallback; } }, logger: { success() {}, info() {}, error() {} }
    });
    const { server, baseUrl } = await listen(httpServer.app);
    try {
      const start = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, { method: 'POST', headers: { authorization: 'Bearer token', 'content-type': 'application/json' }, body: JSON.stringify({ providerConfiguration: { clientId: 'client' } }) });
      const cookie = start.headers.get('set-cookie').split(';', 1)[0];
      if (stale === 'authorization') authorized = false; else generation = 'generation-b';
      const callback = await fetch(`${baseUrl}/oauth/x/callback?code=code&state=${encodeURIComponent(state)}`, { headers: { cookie } });
      assert.equal(callback.status, 403); assert.equal(callbackCalls, 0); assert.equal(writes, 0);
    } finally { server.close(); }
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
    config: { get(key, fallback) { if (key === 'OAUTH_CALLBACK_PORT') return 0; return key === 'BASE_PATH' ? '/credential-hub' : fallback; } },
    logger: { success() {}, info() {}, error() {} },
  });
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

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
        if (key === 'OAUTH_CALLBACK_PORT') return 0;
        return fallback;
      }
    },
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

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

test('OAuth start derives the public origin from trusted proxy signals', async () => {
  const httpServer = new OAuthCallbackServer({
    providerManager: {
      async startOAuth(_provider, options) {
        assert.equal(options.providerConfiguration.redirectUri, 'https://public.example.test/oauth/x/callback');
        return { success: true, data: { authorizationUrl: `https://example.com/authorize?redirect_uri=${encodeURIComponent(options.providerConfiguration.redirectUri)}` } };
      }
    },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    config: {
      get(key, fallback) {
        if (key === 'TRUSTED_PROXY') return 'loopback';
        if (key === 'OAUTH_CALLBACK_PORT') return 0;
        return fallback;
      }
    },
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-forwarded-host': 'public.example.test',
        'x-forwarded-proto': 'https'
      },
      body: JSON.stringify({ providerConfiguration: { clientId: 'x-client' } })
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.data.redirectUri, 'https://public.example.test/oauth/x/callback');
  } finally {
    server.close();
  }
});

test('OAuth start ignores forwarded origin signals from an untrusted source', async () => {
  const httpServer = new OAuthCallbackServer({
    providerManager: {
      async startOAuth(_provider, options) {
        assert.match(options.providerConfiguration.redirectUri, /^http:\/\/127\.0\.0\.1:\d+\/oauth\/x\/callback$/);
        return { success: true, data: { authorizationUrl: `https://example.com/authorize?redirect_uri=${encodeURIComponent(options.providerConfiguration.redirectUri)}` } };
      }
    },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    config: { get(key, fallback) { return key === 'OAUTH_CALLBACK_PORT' ? 0 : fallback; } },
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-forwarded-host': 'attacker.example.test',
        'x-forwarded-proto': 'https'
      },
      body: JSON.stringify({ providerConfiguration: { clientId: 'x-client' } })
    });
    assert.equal(response.status, 200);
  } finally {
    server.close();
  }
});

test('OAuth start rejects conflicting trusted proxy signals without leaking details', async () => {
  const httpServer = new OAuthCallbackServer({
    providerManager: { async startOAuth() { throw new Error('must not be called'); } },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    config: { get(key, fallback) { if (key === 'OAUTH_CALLBACK_PORT') return 0; return key === 'TRUSTED_PROXY' ? 'loopback' : fallback; } },
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-forwarded-host': 'public.example.test, attacker.example.test',
        'x-forwarded-proto': 'https'
      },
      body: JSON.stringify({ providerConfiguration: { clientId: 'x-client' } })
    });
    const body = await response.json();
    assert.equal(response.status, 500);
    assert.equal(JSON.stringify(body).includes('public.example.test'), false);
    assert.equal(JSON.stringify(body).includes('attacker.example.test'), false);
  } finally {
    server.close();
  }
});

test('OAuth production configuration requires an external HTTPS public origin and permits it', () => {
  const config = (publicBaseUrl) => ({ get(key, fallback) {
    if (key === 'NODE_ENV') return 'production';
    if (key === 'PUBLIC_BASE_URL') return publicBaseUrl;
    return fallback;
  } });
  const options = {
    providerManager: {},
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    logger: { success() {}, info() {}, error() {} }
  };
  assert.throws(() => new OAuthCallbackServer({ ...options, config: config(null) }), /PUBLIC_BASE_URL is required/);
  assert.throws(() => new OAuthCallbackServer({ ...options, config: config('http://hub.example.test') }), /must use HTTPS/);
  assert.throws(() => new OAuthCallbackServer({ ...options, config: config('https://container:3000') }), /internal host/);
  assert.doesNotThrow(() => new OAuthCallbackServer({ ...options, config: config('https://hub.example.test') }));
  assert.doesNotThrow(() => new OAuthCallbackServer({
    ...options,
    config: { get(key, fallback) { return key === 'PUBLIC_BASE_URL' ? 'http://hub.example.test' : fallback; } }
  }));
});

test('OAuth production always marks its browser-binding cookie Secure', async () => {
  const httpServer = new OAuthCallbackServer({
    providerManager: {
      async startOAuth(_provider, options) {
        assert.equal(options.providerConfiguration.redirectUri, 'https://hub.example.test/oauth/x/callback');
        return {
          success: true,
          data: {
            authorizationUrl: `https://provider.example.test/authorize?redirect_uri=${encodeURIComponent(options.providerConfiguration.redirectUri)}`
          }
        };
      }
    },
    importTokenCommand: {},
    credentialManager: { async listCredentials() { return []; } },
    accessManagementService: {
      async listUsers() { return []; },
      async isAuthorizationRequired() { return true; },
      async authorize() {}
    },
    apiTokenService: {
      async createToken() { return {}; },
      async listTokens() { return []; },
      async authenticate() { return { authenticated: true, userId: 'actor-a', scopes: ['providers:manage'] }; }
    },
    config: {
      get(key, fallback) {
        if (key === 'NODE_ENV') return 'production';
        if (key === 'PUBLIC_BASE_URL') return 'https://hub.example.test';
        if (key === 'OAUTH_WIZARD_INTENT_TTL_MS') return 60000;
        return fallback;
      }
    },
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/api/v1/providers/x/oauth/start`, {
      method: 'POST',
      headers: { authorization: 'Bearer management-token', 'content-type': 'application/json' },
      body: JSON.stringify({ providerConfiguration: { clientId: 'client-id' } })
    });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('set-cookie'), /(?:^|;)\s*Secure(?:;|$)/);
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

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

test('hosted mode requires an explicit proxy and binds only to the private proxy network', async () => {
  const values = {
    HOSTED_MODE: 'true',
    PUBLIC_BASE_URL: 'https://hub.example.test',
    OAUTH_CALLBACK_PORT: '0'
  };
  const config = {
    get(key, fallback) { return Object.hasOwn(values, key) ? values[key] : fallback; }
  };

  assert.throws(() => new OAuthCallbackServer({
    providerManager: {},
    importTokenCommand: {},
    credentialManager: {},
    config,
    logger: { success() {}, info() {}, error() {} }
  }), /explicit TRUSTED_PROXY/);

  values.TRUSTED_PROXY = '172.30.0.2';
  values.APP_BIND_HOST = '0.0.0.0';
  const server = new OAuthCallbackServer({
    providerManager: {},
    importTokenCommand: {},
    credentialManager: {},
    config,
    logger: { success() {}, info() {}, error() {} }
  });

  await server.start();
  try {
    assert.equal(server.server.address().address, '0.0.0.0');
  } finally {
    await server.stop();
  }
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
  const { server, baseUrl } = await listenOAuthCallbackServer(httpServer);

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
