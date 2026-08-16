import test from 'node:test';
import assert from 'node:assert/strict';

import { ThreadsProvider } from '../../src/providers/threads/threads-provider.js';

test('ThreadsProvider missing credential failures use public Credential terminology', async () => {
  const provider = new ThreadsProvider({
    oauthService: {
      refresh() {
        throw new Error('should not refresh without credential accessToken');
      },
      healthCheck() {
        throw new Error('should not health-check without credential accessToken');
      }
    }
  });

  const refreshResult = await provider.refreshToken(null);
  const healthResult = await provider.healthCheck({});

  assert.equal(refreshResult.success, false);
  assert.equal(refreshResult.error.message, 'Credential with accessToken is required');
  assert.equal(healthResult.success, false);
  assert.equal(healthResult.error.message, 'Credential with accessToken is required');
});
