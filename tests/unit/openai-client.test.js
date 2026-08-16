import test from 'node:test';
import assert from 'node:assert/strict';

import { OpenAIClient } from '../../src/api/openai/openai-client.js';

test('OpenAIClient validates required API key before connecting', async () => {
  const client = new OpenAIClient({
    httpClient: {
      async get() {
        throw new Error('should not call OpenAI');
      }
    }
  });

  await assert.rejects(
    () => client.validateApiKey({}),
    /OpenAI API key is required/
  );
});

test('OpenAIClient validates API key through injected HTTP client', async () => {
  const client = new OpenAIClient({
    httpClient: {
      async get(url, options) {
        assert.equal(url, 'https://api.openai.com/v1/models');
        assert.equal(options.bearerToken, 'sk-test');
        assert.equal(options.headers['OpenAI-Organization'], 'org-test');
        assert.equal(options.headers['OpenAI-Project'], 'proj-test');
        return { data: { data: [{ id: 'gpt-test' }] } };
      }
    }
  });

  const result = await client.validateApiKey({
    apiKey: 'sk-test',
    organizationId: 'org-test',
    projectId: 'proj-test'
  });

  assert.equal(result.valid, true);
  assert.equal(result.provider, 'openai');
  assert.equal(result.modelCount, 1);
});

test('OpenAIClient omits optional organization and project headers when not configured', async () => {
  const client = new OpenAIClient({
    httpClient: {
      async get(url, options) {
        assert.equal(url, 'https://api.openai.com/v1/models');
        assert.deepEqual(options.headers, {});
        return { data: { data: [] } };
      }
    }
  });

  const result = await client.validateApiKey({ apiKey: 'sk-test' });

  assert.equal(result.valid, true);
  assert.equal(result.modelCount, 0);
});
