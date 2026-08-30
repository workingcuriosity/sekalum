import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { OAuthSecurityRequirements } from '../../models/oauth-security-requirements.js';
import { oauthCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { KickApiClient } from '../../api/kick/kick-api-client.js';
import { KickOAuthService } from '../../oauth/kick/kick-oauth-service.js';
import { KickProvider } from './kick-provider.js';

export class KickServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.KICK_API_CLIENT, (c) => {
      return new KickApiClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.KICK_OAUTH_SERVICE, (c) => {
      return new KickOAuthService({
        apiClient: c.resolve(TOKENS.KICK_API_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.KICK_PROVIDER, (c) => {
      return new KickProvider({
        oauthService: c.resolve(TOKENS.KICK_OAUTH_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'kick',
        provider: container.resolve(TOKENS.KICK_PROVIDER),
        oauthService: container.resolve(TOKENS.KICK_OAUTH_SERVICE),
        apiClient: container.resolve(TOKENS.KICK_API_CLIENT),
        displayName: 'Kick OAuth2.1',
        description: 'Kick OAuth 2.1 provider with PKCE for Kick Public API credentials',
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
          defaultScopes: ['user:read', 'channel:read']
        }),
        credentialMethods: [new CredentialMethod({ key: 'oauth2', displayName: 'OAuth 2.0', authenticationMethod: 'oauth2', credentialFields: oauthCredentialFields({ defaultScopes: ['user:read', 'channel:read'] }), operationCapabilities: [ProviderCapability.REFRESH, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'oauth2' })],
        metadata: {
          authType: 'oauth2.1',
          defaultScopes: ['user:read', 'channel:read'],
          api: 'kick-public-api',
          pkce: 'required'
        }
      })
    );
  }
}
