import test from 'node:test';
import assert from 'node:assert/strict';

import { TwitchProvider } from '../../src/providers/twitch/twitch-provider.js';

test('TwitchProvider validates OAuth callback code before service call', async () => {
  const provider = new TwitchProvider({
    oauthService: {
      authenticate() {
        throw new Error('should not authenticate without code');
      }
    }
  });

  const result = await provider.handleOAuthCallback({});

  assert.equal(result.success, false);
  assert.equal(result.error.message, 'OAuth callback code is required');
});

test('TwitchProvider refresh requires Credential refreshToken', async () => {
  const provider = new TwitchProvider({
    oauthService: {
      refresh() {
        throw new Error('should not refresh without Credential refreshToken');
      }
    }
  });

  const result = await provider.refreshToken({ accessToken: 'access-token' });

  assert.equal(result.success, false);
  assert.equal(result.error.message, 'Credential with refreshToken is required');
});

test('TwitchProvider healthCheck requires Credential accessToken', async () => {
  const provider = new TwitchProvider({
    oauthService: {
      healthCheck() {
        throw new Error('should not health-check without Credential accessToken');
      }
    }
  });

  const result = await provider.healthCheck({ refreshToken: 'refresh-token' });

  assert.equal(result.success, false);
  assert.equal(result.error.message, 'Credential with accessToken is required');
});
