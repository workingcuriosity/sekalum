import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { OAuthSecurityRequirements } from '../../models/oauth-security-requirements.js';
import { oauthCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { InstagramApiClient } from '../../api/instagram/instagram-api-client.js';
import { InstagramOAuthService } from '../../oauth/instagram/instagram-oauth-service.js';
import { InstagramProvider } from './instagram-provider.js';

export class InstagramServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.INSTAGRAM_API_CLIENT, (c) => {
      return new InstagramApiClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.INSTAGRAM_OAUTH_SERVICE, (c) => {
      return new InstagramOAuthService({
        apiClient: c.resolve(TOKENS.INSTAGRAM_API_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.INSTAGRAM_PROVIDER, (c) => {
      return new InstagramProvider({
        oauthService: c.resolve(TOKENS.INSTAGRAM_OAUTH_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'instagram',
        provider: container.resolve(TOKENS.INSTAGRAM_PROVIDER),
        oauthService: container.resolve(TOKENS.INSTAGRAM_OAUTH_SERVICE),
        apiClient: container.resolve(TOKENS.INSTAGRAM_API_CLIENT),
        displayName: 'Instagram OAuth2',
        description: 'Instagram OAuth2 provider for Instagram API credentials',
        capabilities: new ProviderCapabilities([
          ProviderCapability.OAUTH,
          ProviderCapability.REFRESH,
          ProviderCapability.HEALTH_CHECK
        ]),
        oauthSecurityRequirements: new OAuthSecurityRequirements({
          state: 'required',
          pkce: 'disabled',
          nonce: 'disabled'
        }),
        credentialFields: oauthCredentialFields({
          defaultScopes: ['instagram_business_basic']
        }),
        credentialMethods: [new CredentialMethod({ key: 'oauth2', displayName: 'OAuth 2.0', authenticationMethod: 'oauth2', credentialFields: oauthCredentialFields({ defaultScopes: ['instagram_business_basic'] }), operationCapabilities: [ProviderCapability.REFRESH, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'oauth2' })],
        metadata: {
          authType: 'oauth2',
          defaultScopes: ['instagram_business_basic'],
          api: 'instagram-api',
          platformFamily: 'meta',
          credentialType: 'user-token'
        }
      })
    );
  }
}
