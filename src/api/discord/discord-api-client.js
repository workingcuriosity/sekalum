import { oauthConfigurationValue } from '../../oauth/oauth-provider-configuration.js';

export class DiscordApiClient {
  constructor({ httpClient, config }) {
    this.httpClient = httpClient;
    this.config = config;

    this.tokenUrl = 'https://discord.com/api/oauth2/token';
    this.currentUserUrl = 'https://discord.com/api/users/@me';
  }

  async exchangeCodeForToken({ code, redirectUri, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'DISCORD_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'DISCORD_CLIENT_SECRET' }),
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'DISCORD-TOKEN', purpose: 'OAUTH_TOKEN_EXCHANGE', providerKey: 'discord', credentialBearing: true
    });

    return response.data;
  }

  async refreshAccessToken({ refreshToken, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'DISCORD_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'DISCORD_CLIENT_SECRET' }),
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'DISCORD-TOKEN', purpose: 'OAUTH_REFRESH', providerKey: 'discord', credentialBearing: true
    });

    return response.data;
  }

  async getCurrentUser({ accessToken }) {
    const response = await this.httpClient.get(this.currentUserUrl, {
      bearerToken: accessToken,
      pathId: 'DISCORD-PROFILE', purpose: 'OAUTH_PROFILE_LOOKUP', providerKey: 'discord', credentialBearing: true
    });

    if (!response.data?.id) {
      throw new Error('Discord user lookup returned no user');
    }

    return response.data;
  }
}
