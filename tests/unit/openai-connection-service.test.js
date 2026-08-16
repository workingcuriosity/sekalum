import test from 'node:test';
import assert from 'node:assert/strict';

import { Credential } from '../../src/models/credential.js';
import { OpenAIConnectionService } from '../../src/connections/openai/openai-connection-service.js';

function openAICredential(overrides = {}) {
  return new Credential({
    credentialId: 'openai:test',
    providerKey: 'openai',
    secrets: [
      { name: 'apiKey', value: 'sk-test' },
      { name: 'organizationId', value: 'org-test' },
      { name: 'projectId', value: 'proj-test' }
    ],
    metadata: {
      custom: {},
      ...(overrides.metadata ?? {})
    },
    ...(overrides.credential ?? {})
  });
}

test('OpenAIConnectionService validates an API-key credential', async () => {
  const service = new OpenAIConnectionService({
    client: {
      async validateApiKey(options) {
        assert.deepEqual(options, {
          apiKey: 'sk-test',
          organizationId: 'org-test',
          projectId: 'proj-test',
          timeoutMs: undefined
        });

        return { modelCount: 2 };
      }
    }
  });

  const result = await service.validateCredential(openAICredential());

  assert.equal(result.valid, true);
  assert.equal(result.provider, 'openai');
  assert.equal(result.modelCount, 2);
});

test('OpenAIConnectionService healthCheck returns down instead of throwing on provider failure', async () => {
  const service = new OpenAIConnectionService({
    client: {
      async validateApiKey() {
        throw new Error('Invalid API key');
      }
    }
  });

  const result = await service.healthCheck(openAICredential());

  assert.equal(result.healthy, false);
  assert.equal(result.status, 'down');
  assert.equal(result.provider, 'openai');
  assert.equal(result.message, 'Invalid API key');
});

test('OpenAIConnectionService rejects credentials without API key', async () => {
  const service = new OpenAIConnectionService({
    client: {
      async validateApiKey() {
        throw new Error('should not call OpenAI');
      }
    }
  });

  const credential = new Credential({
    credentialId: 'openai:missing-api-key',
    providerKey: 'openai',
    secrets: []
  });

  await assert.rejects(
    () => service.validateCredential(credential),
    /OpenAI credential requires apiKey/
  );
});

test('OpenAIConnectionService healthCheck returns up for a valid API key', async () => {
  const service = new OpenAIConnectionService({
    client: {
      async validateApiKey() {
        return { modelCount: 3 };
      }
    }
  });

  const result = await service.healthCheck(openAICredential());

  assert.equal(result.healthy, true);
  assert.equal(result.status, 'up');
  assert.equal(result.provider, 'openai');
  assert.equal(result.modelCount, 3);
});
