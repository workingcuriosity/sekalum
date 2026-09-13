import { oauthConfigurationValue } from '../../oauth/oauth-provider-configuration.js';

export class TwitchApiClient {
  constructor({ httpClient, config }) {
    this.httpClient = httpClient;
    this.config = config;

    this.tokenUrl = 'https://id.twitch.tv/oauth2/token';
    this.validateUrl = 'https://id.twitch.tv/oauth2/validate';
    this.usersUrl = 'https://api.twitch.tv/helix/users';
  }

  async exchangeCodeForToken({ code, redirectUri, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'TWITCH_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'TWITCH_CLIENT_SECRET' }),
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'TWITCH-TOKEN', purpose: 'OAUTH_TOKEN_EXCHANGE', providerKey: 'twitch', credentialBearing: true
    });

    return response.data;
  }

  async refreshAccessToken({ refreshToken, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'TWITCH_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'TWITCH_CLIENT_SECRET' }),
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'TWITCH-TOKEN', purpose: 'OAUTH_REFRESH', providerKey: 'twitch', credentialBearing: true
    });

    return response.data;
  }

  async validateAccessToken({ accessToken }) {
    const response = await this.httpClient.get(this.validateUrl, {
      bearerToken: accessToken,
      pathId: 'TWITCH-VALIDATE', purpose: 'PROVIDER_VALIDATION', providerKey: 'twitch', credentialBearing: true
    });

    return response.data;
  }

  async getCurrentUser({ accessToken, providerConfiguration = null }) {
    const response = await this.httpClient.get(this.usersUrl, {
      bearerToken: accessToken,
      headers: {
        'Client-Id': oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'TWITCH_CLIENT_ID' })
      },
      pathId: 'TWITCH-PROFILE', purpose: 'OAUTH_PROFILE_LOOKUP', providerKey: 'twitch', credentialBearing: true
    });

    const users = Array.isArray(response.data?.data)
      ? response.data.data
      : [];

    if (users.length === 0) {
      throw new Error('Twitch user lookup returned no user');
    }

    return users[0];
  }
}
