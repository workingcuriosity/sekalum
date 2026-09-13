import { oauthConfigurationValue } from '../../oauth/oauth-provider-configuration.js';

export class FacebookApiClient {
  constructor({ httpClient, config }) {
    this.httpClient = httpClient;
    this.config = config;

    this.tokenUrl = 'https://graph.facebook.com/v20.0/oauth/access_token';
    this.currentUserUrl = 'https://graph.facebook.com/v20.0/me';
  }

  async exchangeCodeForToken({ code, redirectUri, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'FACEBOOK_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'FACEBOOK_CLIENT_SECRET' }),
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'FACEBOOK-TOKEN', purpose: 'OAUTH_TOKEN_EXCHANGE', providerKey: 'facebook', credentialBearing: true
    });

    return response.data;
  }

  async refreshAccessToken({ refreshToken, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'FACEBOOK_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'FACEBOOK_CLIENT_SECRET' }),
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'FACEBOOK-TOKEN', purpose: 'OAUTH_REFRESH', providerKey: 'facebook', credentialBearing: true
    });

    return response.data;
  }

  async getCurrentUser({ accessToken }) {
    const response = await this.httpClient.get(this.currentUserUrl, {
      bearerToken: accessToken,
      query: {
        fields: 'id,name,email,picture'
      },
      pathId: 'FACEBOOK-PROFILE', purpose: 'OAUTH_PROFILE_LOOKUP', providerKey: 'facebook', credentialBearing: true
    });

    if (!response.data?.id) {
      throw new Error('Facebook user lookup returned no user');
    }

    return response.data;
  }
}
