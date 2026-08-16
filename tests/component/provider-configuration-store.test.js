import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { Config } from '../../src/config/config.js';
import { JsonStore } from '../../src/storage/json-store.js';
import { EncryptedJsonStore } from '../../src/storage/encrypted-json-store.js';
import { ProviderConfigurationStore } from '../../src/storage/provider-configuration-store.js';

test('provider application secrets use the established encrypted JSON storage boundary', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'credential-hub-provider-config-'));
  const secureStore = new EncryptedJsonStore({
    jsonStore: new JsonStore(),
    config: new Config({ TOKEN_ENCRYPTION_KEY: '12345678901234567890123456789012' })
  });
  const store = new ProviderConfigurationStore({ jsonStore: secureStore, basePath: directory });
  const record = {
    configurationId: 'configuration-1',
    providerKey: 'x',
    configuration: { clientId: 'client-id', clientSecret: 'never-plaintext', redirectUri: 'https://credential-hub.example.com/oauth/x/callback' }
  };

  await store.save(record);
  assert.deepEqual(await store.load('configuration-1'), record);

  const raw = await fs.readFile(path.join(directory, 'provider-configurations.json'), 'utf8');
  assert.equal(raw.includes('never-plaintext'), false);
  assert.match(raw, /credential-hub-encrypted-json/);
});
