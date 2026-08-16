import test from 'node:test';
import assert from 'node:assert/strict';

import { SftpProvider } from '../../src/providers/sftp/sftp-provider.js';

test('SftpProvider validates credentials through the connection service', async () => {
  const provider = new SftpProvider({
    connectionService: {
      async validateCredential(credential) {
        assert.equal(credential.providerKey, 'sftp');
        return { valid: true, protocol: 'sftp' };
      }
    }
  });

  const result = await provider.validateCredential({ providerKey: 'sftp' });

  assert.equal(result.success, true);
  assert.deepEqual(result.data, { valid: true, protocol: 'sftp' });
});

test('SftpProvider healthCheck reports failed connections as ProviderResult failure', async () => {
  const provider = new SftpProvider({
    connectionService: {
      async healthCheck() {
        return { healthy: false, message: 'SFTP login failed' };
      }
    }
  });

  const result = await provider.healthCheck({ providerKey: 'sftp' });

  assert.equal(result.success, false);
  assert.equal(result.error.message, 'SFTP login failed');
});
