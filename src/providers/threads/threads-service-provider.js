import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { oauthCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { ThreadsApiClient } from '../../api/threads/threads-api-client.js';
import { ThreadsOAuthService } from '../../oauth/threads/threads-oauth-service.js';
import { ThreadsProvider } from './threads-provider.js';

export class ThreadsServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.THREADS_API_CLIENT, (c) => {
      return new ThreadsApiClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.THREADS_OAUTH_SERVICE, (c) => {
      return new ThreadsOAuthService({
        apiClient: c.resolve(TOKENS.THREADS_API_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.THREADS_PROVIDER, (c) => {
      return new ThreadsProvider({
        oauthService: c.resolve(TOKENS.THREADS_OAUTH_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'threads',
        provider: container.resolve(TOKENS.THREADS_PROVIDER),
        oauthService: container.resolve(TOKENS.THREADS_OAUTH_SERVICE),
        apiClient: container.resolve(TOKENS.THREADS_API_CLIENT),
        displayName: 'Threads',
        description: 'Meta Threads OAuth provider',
        capabilities: new ProviderCapabilities([
          ProviderCapability.OAUTH,
          ProviderCapability.REFRESH,
          ProviderCapability.HEALTH_CHECK
        ]),
        credentialFields: oauthCredentialFields({
          defaultScopes: ['threads_basic']
        }),
        credentialMethods: [new CredentialMethod({ key: 'oauth2', displayName: 'OAuth 2.0', authenticationMethod: 'oauth2', credentialFields: oauthCredentialFields({ defaultScopes: ['threads_basic'] }), operationCapabilities: [ProviderCapability.REFRESH, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'oauth2' })],
        metadata: {
          authType: 'oauth2',
          defaultScopes: ['threads_basic'],
          api: 'threads-api',
          platformFamily: 'meta',
          credentialType: 'user-token'
        }
      })
    );
  }
}
