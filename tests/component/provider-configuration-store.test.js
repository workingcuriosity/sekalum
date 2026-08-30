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

test('provider configuration mutations serialize concurrent create, update and delete operations', async () => {
  let data = null;
  const jsonStore = {
    async exists() { return data !== null; },
    async load() {
      const snapshot = structuredClone(data);
      await new Promise((resolve) => setTimeout(resolve, 5));
      return snapshot;
    },
    async save(_path, value) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      data = structuredClone(value);
    }
  };
  const store = new ProviderConfigurationStore({ jsonStore, basePath: '/data' });
  await store.save({ configurationId: 'remove-me', providerKey: 'x', configuration: { clientId: 'old' } });

  await Promise.all([
    store.save({ configurationId: 'create-me', providerKey: 'x', configuration: { clientId: 'created' } }),
    store.save({ configurationId: 'remove-me', providerKey: 'x', configuration: { clientId: 'updated' } }),
    store.delete('remove-me')
  ]);

  assert.deepEqual(await store.list(), [
    { configurationId: 'create-me', providerKey: 'x', configuration: { clientId: 'created' } }
  ]);
});

test('provider configuration mutation queue continues after a failed write without corruption', async () => {
  let data = null;
  let failNextSave = true;
  const jsonStore = {
    async exists() { return data !== null; },
    async load() { return structuredClone(data); },
    async save(_path, value) {
      if (failNextSave) {
        failNextSave = false;
        throw new Error('simulated write failure');
      }
      data = structuredClone(value);
    }
  };
  const store = new ProviderConfigurationStore({ jsonStore, basePath: '/data' });

  await assert.rejects(
    store.save({ configurationId: 'failed', providerKey: 'x', configuration: { clientId: 'failed' } }),
    /simulated write failure/
  );
  await store.save({ configurationId: 'survives', providerKey: 'x', configuration: { clientId: 'survives' } });

  assert.deepEqual(await store.list(), [
    { configurationId: 'survives', providerKey: 'x', configuration: { clientId: 'survives' } }
  ]);
});
