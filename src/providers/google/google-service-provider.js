import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { oauthCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { GoogleApiClient } from '../../api/google/google-api-client.js';
import { GoogleOAuthService } from '../../oauth/google/google-oauth-service.js';
import { GoogleProvider } from './google-provider.js';

export class GoogleServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.GOOGLE_API_CLIENT, (c) => {
      return new GoogleApiClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.GOOGLE_OAUTH_SERVICE, (c) => {
      return new GoogleOAuthService({
        apiClient: c.resolve(TOKENS.GOOGLE_API_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.GOOGLE_PROVIDER, (c) => {
      return new GoogleProvider({
        oauthService: c.resolve(TOKENS.GOOGLE_OAUTH_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'google',
        provider: container.resolve(TOKENS.GOOGLE_PROVIDER),
        oauthService: container.resolve(TOKENS.GOOGLE_OAUTH_SERVICE),
        apiClient: container.resolve(TOKENS.GOOGLE_API_CLIENT),
        displayName: 'Google OAuth2',
        description: 'Google OAuth2 provider for Google account credentials',
        capabilities: new ProviderCapabilities([
          ProviderCapability.OAUTH,
          ProviderCapability.REFRESH,
          ProviderCapability.HEALTH_CHECK
        ]),
        credentialFields: oauthCredentialFields({
          defaultScopes: ['openid', 'email', 'profile']
        }),
        credentialMethods: [new CredentialMethod({ key: 'oauth2', displayName: 'OAuth 2.0', authenticationMethod: 'oauth2', credentialFields: oauthCredentialFields({ defaultScopes: ['openid', 'email', 'profile'] }), operationCapabilities: [ProviderCapability.REFRESH, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'oauth2' })],
        metadata: {
          authType: 'oauth2',
          defaultScopes: ['openid', 'email', 'profile']
        }
      })
    );
  }
}
