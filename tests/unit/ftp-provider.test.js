import test from 'node:test';
import assert from 'node:assert/strict';

import { FtpProvider } from '../../src/providers/ftp/ftp-provider.js';

test('FtpProvider validates credentials through the connection service', async () => {
  const provider = new FtpProvider({
    connectionService: {
      async validateCredential(credential) {
        assert.equal(credential.providerKey, 'ftp');
        return { valid: true, protocol: 'ftp' };
      }
    }
  });

  const result = await provider.validateCredential({ providerKey: 'ftp' });

  assert.equal(result.success, true);
  assert.deepEqual(result.data, { valid: true, protocol: 'ftp' });
});

test('FtpProvider healthCheck reports failed connections as ProviderResult failure', async () => {
  const provider = new FtpProvider({
    connectionService: {
      async healthCheck() {
        return { healthy: false, message: 'FTP login failed' };
      }
    }
  });

  const result = await provider.healthCheck({ providerKey: 'ftp' });

  assert.equal(result.success, false);
  assert.equal(result.error.message, 'FTP login failed');
});
