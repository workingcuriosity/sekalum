import test from 'node:test';
import assert from 'node:assert/strict';

import { OpenAIProvider } from '../../src/providers/openai/openai-provider.js';

test('OpenAIProvider validates credentials through the connection service', async () => {
  const provider = new OpenAIProvider({
    connectionService: {
      async validateCredential(credential) {
        assert.equal(credential.providerKey, 'openai');
        return { valid: true, provider: 'openai' };
      }
    }
  });

  const result = await provider.validateCredential({ providerKey: 'openai' });

  assert.equal(result.success, true);
  assert.deepEqual(result.data, { valid: true, provider: 'openai' });
});

test('OpenAIProvider healthCheck reports failed checks as ProviderResult failure', async () => {
  const provider = new OpenAIProvider({
    connectionService: {
      async healthCheck() {
        return { healthy: false, message: 'OpenAI API key invalid' };
      }
    }
  });

  const result = await provider.healthCheck({ providerKey: 'openai' });

  assert.equal(result.success, false);
  assert.equal(result.error.message, 'OpenAI API key invalid');
});

test('OpenAIProvider converts validation errors into ProviderResult failure', async () => {
  const provider = new OpenAIProvider({
    connectionService: {
      async validateCredential() {
        throw new Error('OpenAI credential requires apiKey');
      }
    }
  });

  const result = await provider.validateCredential({ providerKey: 'openai' });

  assert.equal(result.success, false);
  assert.equal(result.error.message, 'OpenAI credential requires apiKey');
});
