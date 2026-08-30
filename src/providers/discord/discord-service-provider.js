import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { OAuthSecurityRequirements } from '../../models/oauth-security-requirements.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';
import { oauthCredentialFields } from '../credential-field-sets.js';

import { DiscordApiClient } from '../../api/discord/discord-api-client.js';
import { DiscordOAuthService } from '../../oauth/discord/discord-oauth-service.js';
import { DiscordProvider } from './discord-provider.js';

export class DiscordServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.DISCORD_API_CLIENT, (c) => {
      return new DiscordApiClient({
        httpClient: c.resolve(TOKENS.HTTP_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.DISCORD_OAUTH_SERVICE, (c) => {
      return new DiscordOAuthService({
        apiClient: c.resolve(TOKENS.DISCORD_API_CLIENT),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.DISCORD_PROVIDER, (c) => {
      return new DiscordProvider({
        oauthService: c.resolve(TOKENS.DISCORD_OAUTH_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'discord',
        provider: container.resolve(TOKENS.DISCORD_PROVIDER),
        oauthService: container.resolve(TOKENS.DISCORD_OAUTH_SERVICE),
        apiClient: container.resolve(TOKENS.DISCORD_API_CLIENT),
        displayName: 'Discord OAuth2',
        description: 'Discord OAuth2 user provider for Discord API credentials',
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
          defaultScopes: ['identify', 'email', 'guilds']
        }),
        credentialMethods: [
          new CredentialMethod({
            key: 'oauth2',
            displayName: 'OAuth 2.0',
            authenticationMethod: 'oauth2',
            credentialFields: oauthCredentialFields({
              defaultScopes: ['identify', 'email', 'guilds']
            }),
            operationCapabilities: [
              ProviderCapability.REFRESH,
              ProviderCapability.HEALTH_CHECK
            ]
          }),
          new CredentialMethod({
            key: 'webhook',
            displayName: 'Webhook',
            authenticationMethod: 'webhook',
            description: 'Provider-neutral incoming webhook credential.',
            credentialFields: [
              {
                key: 'displayName',
                label: 'Display name',
                type: 'text',
                required: true,
                section: 'credentialDisplay',
                displayOrder: 10
              },
              {
                key: 'webhookUrl',
                label: 'Webhook URL',
                type: 'url',
                required: true,
                secret: true,
                validation: { format: 'url' },
                csvAliases: ['webhook_url'],
                displayOrder: 20
              }
            ],
            operationCapabilities: []
          })
        ],
        providerMethodBindings: [
          new ProviderMethodBinding({
            methodKey: 'oauth2',
            displayName: 'Discord OAuth 2.0',
            metadata: { defaultScopes: ['identify', 'email', 'guilds'] }
          }),
          new ProviderMethodBinding({
            methodKey: 'webhook',
            displayName: 'Discord Webhook'
          })
        ],
        metadata: {
          authType: 'oauth2',
          defaultScopes: ['identify', 'email', 'guilds'],
          api: 'discord-api',
          credentialType: 'user-token'
        }
      })
    );
  }
}
