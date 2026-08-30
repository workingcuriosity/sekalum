import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { OAuthSecurityRequirements } from '../../models/oauth-security-requirements.js';
import { oauthCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { FacebookApiClient } from '../../api/facebook/facebook-api-client.js';
import { FacebookOAuthService } from '../../oauth/facebook/facebook-oauth-service.js';
import { FacebookProvider } from './facebook-provider.js';

export class FacebookServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.FACEBOOK_API_CLIENT, (c) => {
      return new FacebookApiClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.FACEBOOK_OAUTH_SERVICE, (c) => {
      return new FacebookOAuthService({
        apiClient: c.resolve(TOKENS.FACEBOOK_API_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.FACEBOOK_PROVIDER, (c) => {
      return new FacebookProvider({
        oauthService: c.resolve(TOKENS.FACEBOOK_OAUTH_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'facebook',
        provider: container.resolve(TOKENS.FACEBOOK_PROVIDER),
        oauthService: container.resolve(TOKENS.FACEBOOK_OAUTH_SERVICE),
        apiClient: container.resolve(TOKENS.FACEBOOK_API_CLIENT),
        displayName: 'Facebook OAuth2',
        description: 'Facebook OAuth2 provider for Facebook Graph API credentials',
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
          defaultScopes: ['public_profile', 'email']
        }),
        credentialMethods: [new CredentialMethod({ key: 'oauth2', displayName: 'OAuth 2.0', authenticationMethod: 'oauth2', credentialFields: oauthCredentialFields({ defaultScopes: ['public_profile', 'email'] }), operationCapabilities: [ProviderCapability.REFRESH, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'oauth2' })],
        metadata: {
          authType: 'oauth2',
          defaultScopes: ['public_profile', 'email'],
          api: 'facebook-graph-api',
          platformFamily: 'meta',
          credentialType: 'user-token'
        }
      })
    );
  }
}
