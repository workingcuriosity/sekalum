import { oauthConfigurationValue } from '../../oauth/oauth-provider-configuration.js';

export class InstagramApiClient {
  constructor({ httpClient, config }) {
    this.httpClient = httpClient;
    this.config = config;

    this.tokenUrl = 'https://api.instagram.com/oauth/access_token';
    this.refreshUrl = 'https://graph.instagram.com/refresh_access_token';
    this.currentUserUrl = 'https://graph.instagram.com/me';
  }

  async exchangeCodeForToken({ code, redirectUri, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'INSTAGRAM_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'INSTAGRAM_CLIENT_SECRET' }),
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'INSTAGRAM-TOKEN', purpose: 'OAUTH_TOKEN_EXCHANGE', providerKey: 'instagram', credentialBearing: true
    });

    return response.data;
  }

  async refreshAccessToken({ refreshToken }) {
    const response = await this.httpClient.post(this.refreshUrl, new URLSearchParams({
      grant_type: 'ig_refresh_token',
      access_token: refreshToken
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      pathId: 'INSTAGRAM-REFRESH', purpose: 'OAUTH_REFRESH', providerKey: 'instagram', credentialBearing: true
    });

    return response.data;
  }

  async getCurrentUser({ accessToken }) {
    const response = await this.httpClient.get(this.currentUserUrl, {
      bearerToken: accessToken,
      query: {
        fields: 'id,username,account_type'
      },
      pathId: 'INSTAGRAM-PROFILE', purpose: 'OAUTH_PROFILE_LOOKUP', providerKey: 'instagram', credentialBearing: true
    });

    if (!response.data?.id) {
      throw new Error('Instagram user lookup returned no user');
    }

    return response.data;
  }
}
