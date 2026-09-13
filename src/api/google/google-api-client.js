import { oauthConfigurationValue } from '../../oauth/oauth-provider-configuration.js';

export class GoogleApiClient {
  constructor({ httpClient, config }) {
    this.httpClient = httpClient;
    this.config = config;

    this.tokenUrl = 'https://oauth2.googleapis.com/token';
    this.userInfoUrl = 'https://openidconnect.googleapis.com/v1/userinfo';
  }

  async exchangeCodeForToken({ code, redirectUri, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'GOOGLE_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'GOOGLE_CLIENT_SECRET' }),
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'GOOGLE-TOKEN', purpose: 'OAUTH_TOKEN_EXCHANGE', providerKey: 'google', credentialBearing: true
    });

    return response.data;
  }

  async refreshAccessToken({ refreshToken, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'GOOGLE_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'GOOGLE_CLIENT_SECRET' }),
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'GOOGLE-TOKEN', purpose: 'OAUTH_REFRESH', providerKey: 'google', credentialBearing: true
    });

    return response.data;
  }

  async getCurrentUser({ accessToken }) {
    const response = await this.httpClient.get(this.userInfoUrl, {
      bearerToken: accessToken,
      pathId: 'GOOGLE-PROFILE', purpose: 'OAUTH_PROFILE_LOOKUP', providerKey: 'google', credentialBearing: true
    });

    return response.data;
  }
}
