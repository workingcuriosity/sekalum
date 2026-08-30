import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { OAuthSecurityRequirements } from '../../models/oauth-security-requirements.js';
import { oauthCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { XApiClient } from '../../api/x/x-api-client.js';
import { XOAuthService } from '../../oauth/x/x-oauth-service.js';
import { XProvider } from './x-provider.js';

export class XServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.X_API_CLIENT, (c) => {
      return new XApiClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.X_OAUTH_SERVICE, (c) => {
      return new XOAuthService({
        apiClient: c.resolve(TOKENS.X_API_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.X_PROVIDER, (c) => {
      return new XProvider({
        oauthService: c.resolve(TOKENS.X_OAUTH_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'x',
        provider: container.resolve(TOKENS.X_PROVIDER),
        oauthService: container.resolve(TOKENS.X_OAUTH_SERVICE),
        apiClient: container.resolve(TOKENS.X_API_CLIENT),
        displayName: 'X OAuth2',
        description: 'X OAuth2 user provider with PKCE for X API credentials',
        capabilities: new ProviderCapabilities([
          ProviderCapability.OAUTH,
          ProviderCapability.REFRESH,
          ProviderCapability.HEALTH_CHECK
        ]),
        oauthSecurityRequirements: new OAuthSecurityRequirements({
          state: 'required',
          pkce: 'required',
          nonce: 'disabled'
        }),
        credentialFields: oauthCredentialFields({
          defaultScopes: ['users.read', 'offline.access'],
          clientSecretRequired: false
        }),
        credentialMethods: [new CredentialMethod({ key: 'oauth2', displayName: 'OAuth 2.0', authenticationMethod: 'oauth2', credentialFields: oauthCredentialFields({ defaultScopes: ['users.read', 'offline.access'], clientSecretRequired: false }), operationCapabilities: [ProviderCapability.REFRESH, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'oauth2' })],
        metadata: {
          authType: 'oauth2',
          defaultScopes: ['users.read', 'offline.access'],
          api: 'x-api-v2',
          pkce: 'required',
          credentialType: 'user-token'
        }
      })
    );
  }
}
