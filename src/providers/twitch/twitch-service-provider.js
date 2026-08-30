import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { oauthCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { TwitchApiClient } from '../../api/twitch/twitch-api-client.js';
import { TwitchOAuthService } from '../../oauth/twitch/twitch-oauth-service.js';
import { TwitchProvider } from './twitch-provider.js';

function twitchCredentialFields() {
  return oauthCredentialFields({ defaultScopes: ['user:read:email'] })
    .map((field) => field.key === 'clientId' ? { ...field, runtimePublic: true } : field);
}

export class TwitchServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.TWITCH_API_CLIENT, (c) => {
      return new TwitchApiClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.TWITCH_OAUTH_SERVICE, (c) => {
      return new TwitchOAuthService({
        apiClient: c.resolve(TOKENS.TWITCH_API_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.TWITCH_PROVIDER, (c) => {
      return new TwitchProvider({
        oauthService: c.resolve(TOKENS.TWITCH_OAUTH_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'twitch',
        provider: container.resolve(TOKENS.TWITCH_PROVIDER),
        oauthService: container.resolve(TOKENS.TWITCH_OAUTH_SERVICE),
        apiClient: container.resolve(TOKENS.TWITCH_API_CLIENT),
        displayName: 'Twitch OAuth2',
        description: 'Twitch OAuth2 provider for Helix API credentials',
        capabilities: new ProviderCapabilities([
          ProviderCapability.OAUTH,
          ProviderCapability.REFRESH,
          ProviderCapability.HEALTH_CHECK
        ]),
        credentialFields: twitchCredentialFields(),
        credentialMethods: [new CredentialMethod({ key: 'oauth2', displayName: 'OAuth 2.0', authenticationMethod: 'oauth2', credentialFields: twitchCredentialFields(), operationCapabilities: [ProviderCapability.REFRESH, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'oauth2' })],
        metadata: {
          authType: 'oauth2',
          defaultScopes: ['user:read:email'],
          api: 'helix'
        }
      })
    );
  }
}
