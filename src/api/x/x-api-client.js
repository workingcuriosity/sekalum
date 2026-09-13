import { oauthConfigurationValue } from '../../oauth/oauth-provider-configuration.js';

export class XApiClient {
  constructor({ httpClient, config }) {
    this.httpClient = httpClient;
    this.config = config;

    this.tokenUrl = 'https://api.x.com/2/oauth2/token';
    this.currentUserUrl = 'https://api.x.com/2/users/me';
  }

  async exchangeCodeForToken({ code, redirectUri, codeVerifier, providerConfiguration = null }) {
    if (!codeVerifier) {
      throw new Error('X token exchange requires PKCE code_verifier');
    }

    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'X_CLIENT_ID' }),
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
      code
    });

    const clientSecret = oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'X_CLIENT_SECRET', required: false });
    if (clientSecret) {
      body.set('client_secret', clientSecret);
    }

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'X-TOKEN', purpose: 'OAUTH_TOKEN_EXCHANGE', providerKey: 'x', credentialBearing: true
    });

    return response.data;
  }

  async refreshAccessToken({ refreshToken, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'X_CLIENT_ID' }),
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    });

    const clientSecret = oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'X_CLIENT_SECRET', required: false });
    if (clientSecret) {
      body.set('client_secret', clientSecret);
    }

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'X-TOKEN', purpose: 'OAUTH_REFRESH', providerKey: 'x', credentialBearing: true
    });

    return response.data;
  }

  async getCurrentUser({ accessToken }) {
    const response = await this.httpClient.get(this.currentUserUrl, {
      bearerToken: accessToken,
      query: {
        'user.fields': 'id,name,username,verified,profile_image_url'
      },
      pathId: 'X-PROFILE', purpose: 'OAUTH_PROFILE_LOOKUP', providerKey: 'x', credentialBearing: true
    });

    const user = response.data?.data ?? response.data;

    if (!user?.id) {
      throw new Error('X user lookup returned no user');
    }

    return user;
  }
}
