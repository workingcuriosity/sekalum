import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { OpenAIServiceProvider } from '../../src/providers/openai/openai-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

test('OpenAIServiceProvider registers OpenAI provider metadata and API-key capabilities', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new OpenAIServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('openai');

  assert.equal(definition.name, 'openai');
  assert.equal(definition.displayName, 'OpenAI API Key');
  assert.equal(definition.description, 'OpenAI API-key provider for OpenAI and ChatGPT API credentials');
  assert.deepEqual(definition.capabilities.toArray(), [
    'validation',
    'health-check'
  ]);
  assert.deepEqual(definition.oauthSecurityRequirements.toJSON(), {
    state: 'required',
    pkce: 'disabled',
    nonce: 'disabled'
  });
  assert.deepEqual(definition.metadata, {
    authType: 'api-key',
    credentialType: 'api-key',
    requiredSecrets: ['apiKey'],
    optionalSecrets: ['organizationId', 'projectId'],
    validationEndpoint: '/v1/models'
  });
  assert.deepEqual(
    definition.credentialFields.map((field) => field.key),
    ['displayName', 'description', 'apiKey', 'organizationId', 'projectId']
  );
  assert.equal(definition.credentialFields[2].secret, true);
});
