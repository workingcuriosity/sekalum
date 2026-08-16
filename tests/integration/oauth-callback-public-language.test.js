import test from 'node:test';
import assert from 'node:assert/strict';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';

function createServer() {
  return new OAuthCallbackServer({
    providerManager: {
      cancelled: [],
      discarded: [],
      async handleOAuthCallback(provider, callbackData) {
        assert.equal(provider, 'threads');
        assert.equal(callbackData.code, 'oauth-code');
        return {
          success: true,
          data: { provider, callbackData }
        };
      },
      async cancelOAuth(provider, state) {
        this.cancelled.push([provider, state]);
        return true;
      },
      async discardProviderConfiguration(configurationId, provider) {
        this.discarded.push([configurationId, provider]);
        return true;
      }
    },
    importTokenCommand: {
      async execute(oauthResult) {
        assert.equal(oauthResult.provider, 'threads');
        return {
          provider: 'threads',
          providerId: 'threads:main',
          accountId: 'main',
          accountName: 'Main Account'
        };
      }
    },
    credentialManager: {},
    config: {
      get() {
        return 0;
      }
    },
    logger: {
      success() {},
      error() {}
    }
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

test('OAuth callback renders a safe result page and reports success to the Wizard', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/oauth/threads/callback?code=oauth-code&state=state-1`, { redirect: 'manual' });

    assert.equal(response.status, 200);
    const page = await response.text();
    assert.match(page, /data-oauth-result="success"/);
    assert.match(page, /credential-hub:oauth-result/);
    assert.match(page, /href="\/admin\/\?oauth=success&amp;code=OAUTH_SUCCESS&amp;provider=threads&amp;credentialId=threads%3Amain"/);
    assert.match(page, /href="\/admin\/dashboard\.html"/);
    assert.match(page, /href="\/project-documents\/license"/);
    assert.match(page, /href="\/project-documents\/notice"/);
    assert.match(page, /href="\/project-documents\/third-party-software"/);
    assert.match(page, /href="\/project-documents\/security"/);
    assert.doesNotMatch(page, /github\.com\/[^" ]+\/blob\//);
    assert.doesNotMatch(page, /feature\/project-ai-knowledge-base/);
    assert.doesNotMatch(page, /stack/i);
  } finally {
    server.close();
  }
});

test('OAuth callback renders a localized cancellation result without raw provider errors', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/oauth/threads/callback?error=access_denied&state=cancel-state`, { redirect: 'manual' });

    assert.equal(response.status, 400);
    const page = await response.text();
    assert.match(page, /data-oauth-result="cancelled"/);
    assert.match(page, /Authorization cancelled/);
    assert.match(page, /Autorisierung abgebrochen/);
    assert.doesNotMatch(page, /access_denied/);
    assert.deepEqual(httpServer.providerManager.cancelled, [['threads', 'cancel-state']]);
  } finally {
    server.close();
  }
});

test('OAuth callback maps redirect_uri_mismatch without exposing raw provider text', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/oauth/threads/callback?error=redirect_uri_mismatch&error_description=secret-provider-detail&state=mismatch-state`);
    const page = await response.text();

    assert.equal(response.status, 400);
    assert.match(page, /OAUTH_REDIRECT_URI_MISMATCH/);
    assert.match(page, new RegExp(`${baseUrl.replaceAll('.', '\\.')}\\/oauth\\/threads\\/callback`));
    assert.doesNotMatch(page, /secret-provider-detail/);
    assert.deepEqual(httpServer.providerManager.cancelled, [['threads', 'mismatch-state']]);
  } finally {
    server.close();
  }
});

test('OAuth callback removes provider configuration when credential import fails', async () => {
  const discarded = [];
  const httpServer = new OAuthCallbackServer({
    providerManager: {
      async handleOAuthCallback() {
        return {
          success: true,
          data: {
            provider: 'threads',
            metadata: { providerConfigurationId: 'configuration-import-failure' }
          }
        };
      },
      async discardProviderConfiguration(configurationId, provider) {
        discarded.push([configurationId, provider]);
        return true;
      }
    },
    importTokenCommand: {
      async execute() {
        throw new Error('import failed');
      }
    },
    credentialManager: {},
    config: { get() { return 0; } },
    logger: { success() {}, info() {}, error() {} }
  });
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/oauth/threads/callback?code=oauth-code&state=state-1`);
    const page = await response.text();

    assert.equal(response.status, 400);
    assert.match(page, /OAUTH_CALLBACK_FAILED/);
    assert.deepEqual(discarded, [['configuration-import-failure', 'threads']]);
  } finally {
    server.close();
  }
});

test('OAuth callback cancels provider configuration when the authorization code is missing', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/oauth/threads/callback?state=missing-code-state`);
    const page = await response.text();

    assert.equal(response.status, 400);
    assert.match(page, /OAUTH_CALLBACK_FAILED/);
    assert.deepEqual(httpServer.providerManager.cancelled, [['threads', 'missing-code-state']]);
  } finally {
    server.close();
  }
});
