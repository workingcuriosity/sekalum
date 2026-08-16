import test from 'node:test';
import assert from 'node:assert/strict';

import { StartOAuthCommand } from '../../src/commands/start-oauth-command.js';
import { RefreshExpiredTokensCommand } from '../../src/commands/refresh-expired-tokens-command.js';
import { ImportTokenCommand } from '../../src/commands/import-token-command.js';
import { ProviderResult } from '../../src/models/provider-result.js';
import { OAuthResult } from '../../src/models/oauth-result.js';

test('StartOAuthCommand delegates to ProviderManager only', async () => {
  const calls = [];
  const command = new StartOAuthCommand({
    providerManager: {
      startOAuth(provider, options) {
        calls.push({ provider, options });
        return ProviderResult.success({ authorizationUrl: 'https://example.test/oauth' });
      }
    }
  });

  const result = await command.execute({
    provider: 'threads',
    account: 'main',
    scopes: ['threads_basic'],
    state: 'state-1'
  });

  assert.equal(result.success, true);
  assert.deepEqual(calls, [{
    provider: 'threads',
    options: {
      account: 'main',
      scopes: ['threads_basic'],
      state: 'state-1'
    }
  }]);
});


test('StartOAuthCommand omits empty scopes so providers can use defaults', async () => {
  const calls = [];
  const command = new StartOAuthCommand({
    providerManager: {
      startOAuth(provider, options) {
        calls.push({ provider, options });
        return ProviderResult.success({ authorizationUrl: 'https://example.test/oauth' });
      }
    }
  });

  const result = await command.execute({
    provider: 'google',
    scopes: []
  });

  assert.equal(result.success, true);
  assert.deepEqual(calls, [{
    provider: 'google',
    options: {
      account: null,
      state: null
    }
  }]);
});

test('RefreshExpiredTokensCommand delegates refresh workflow to CredentialManager only', async () => {
  const calls = [];
  const token = {
    provider: 'threads',
    providerId: 'threads:main',
    expiresAt: new Date(Date.now() - 1_000).toISOString()
  };

  const command = new RefreshExpiredTokensCommand({
    credentialManager: {
      async refreshExpiredCredentials() {
        calls.push('refreshExpiredCredentials');
        return [token];
      }
    }
  });

  const candidates = await command.execute();

  assert.deepEqual(candidates, [token]);
  assert.deepEqual(calls, ['refreshExpiredCredentials']);
});

test('ImportTokenCommand delegates import workflow to CredentialManager only', async () => {
  const calls = [];
  const oauthResult = new OAuthResult({
    providerId: 'threads:main',
    provider: 'threads',
    accountId: 'main',
    accessToken: 'access-token'
  });

  const command = new ImportTokenCommand({
    credentialManager: {
      async importCredential(result) {
        calls.push(result);
        return { providerId: result.providerId };
      }
    }
  });

  const result = await command.execute(oauthResult);

  assert.deepEqual(result, { providerId: 'threads:main' });
  assert.deepEqual(calls, [oauthResult]);
});
