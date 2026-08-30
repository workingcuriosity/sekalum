import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { OpenAIClient } from '../../api/openai/openai-client.js';
import { OpenAIConnectionService } from '../../connections/openai/openai-connection-service.js';
import { OpenAIProvider } from './openai-provider.js';

export class OpenAIServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.OPENAI_CLIENT, (c) => {
      return new OpenAIClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT)
      });
    });

    container.singleton(TOKENS.OPENAI_CONNECTION_SERVICE, (c) => {
      return new OpenAIConnectionService({
        client: c.resolve(TOKENS.OPENAI_CLIENT)
      });
    });

    container.singleton(TOKENS.OPENAI_PROVIDER, (c) => {
      return new OpenAIProvider({
        connectionService: c.resolve(TOKENS.OPENAI_CONNECTION_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'openai',
        provider: container.resolve(TOKENS.OPENAI_PROVIDER),
        apiClient: container.resolve(TOKENS.OPENAI_CLIENT),
        displayName: 'OpenAI API Key',
        description: 'OpenAI API-key provider for OpenAI and ChatGPT API credentials',
        capabilities: new ProviderCapabilities([
          ProviderCapability.VALIDATION,
          ProviderCapability.HEALTH_CHECK
        ]),
        credentialFields: [
          {
            key: 'displayName',
            label: 'Display name',
            description: 'A unique display name for this credential.',
            type: 'text',
            required: true,
            csvAliases: ['name', 'credential_name'],
            group: 'Basic information',
            displayOrder: 10
          },
          {
            key: 'description',
            label: 'Description',
            description: 'Optional administrative notes for this credential.',
            type: 'textarea',
            required: false,
            csvAliases: ['notes', 'comment'],
            group: 'Basic information',
            displayOrder: 20
          },
          {
            key: 'apiKey',
            label: 'API key',
            description: 'API key issued by OpenAI.',
            type: 'api-key',
            required: true,
            secret: true,
            validation: { minLength: 20 },
            csvAliases: ['api_key', 'token'],
            group: 'API credentials',
            displayOrder: 30
          },
          {
            key: 'organizationId',
            label: 'Organization ID',
            description: 'Optional OpenAI organization identifier.',
            type: 'text',
            required: false,
            csvAliases: ['organization_id', 'organization'],
            group: 'API credentials',
            displayOrder: 40
          },
          {
            key: 'projectId',
            label: 'Project ID',
            description: 'Optional OpenAI project identifier.',
            type: 'text',
            required: false,
            csvAliases: ['project_id', 'project'],
            group: 'API credentials',
            displayOrder: 50
          }
        ],
        credentialMethods: [new CredentialMethod({
          key: 'api-key',
          displayName: 'API key',
          authenticationMethod: 'api-key',
          credentialFields: [
            { key: 'displayName', label: 'Display name', type: 'text', required: true, csvAliases: ['name', 'credential_name'], group: 'Basic information', displayOrder: 10 },
            { key: 'description', label: 'Description', type: 'textarea', required: false, csvAliases: ['notes', 'comment'], group: 'Basic information', displayOrder: 20 },
            { key: 'apiKey', label: 'API key', type: 'api-key', required: true, secret: true, validation: { minLength: 20 }, csvAliases: ['api_key', 'token'], group: 'API credentials', displayOrder: 30 },
            { key: 'organizationId', label: 'Organization ID', type: 'text', required: false, csvAliases: ['organization_id', 'organization'], group: 'API credentials', displayOrder: 40 },
            { key: 'projectId', label: 'Project ID', type: 'text', required: false, csvAliases: ['project_id', 'project'], group: 'API credentials', displayOrder: 50 }
          ],
          operationCapabilities: [ProviderCapability.VALIDATION, ProviderCapability.HEALTH_CHECK]
        })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'api-key' })],
        metadata: {
          authType: 'api-key',
          credentialType: 'api-key',
          requiredSecrets: ['apiKey'],
          optionalSecrets: ['organizationId', 'projectId'],
          validationEndpoint: '/v1/models'
        }
      })
    );
  }
}
