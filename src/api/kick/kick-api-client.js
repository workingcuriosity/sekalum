import { oauthConfigurationValue } from '../../oauth/oauth-provider-configuration.js';

export class KickApiClient {
  constructor({ httpClient, config }) {
    this.httpClient = httpClient;
    this.config = config;

    this.tokenUrl = 'https://id.kick.com/oauth/token';
    this.introspectUrl = 'https://id.kick.com/oauth/token/introspect';
    this.usersUrl = 'https://api.kick.com/public/v1/users';
  }

  async exchangeCodeForToken({ code, redirectUri, codeVerifier, providerConfiguration = null }) {
    if (!codeVerifier) {
      throw new Error('Kick token exchange requires PKCE code_verifier');
    }

    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'KICK_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'KICK_CLIENT_SECRET' }),
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
      code
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'KICK-TOKEN', purpose: 'OAUTH_TOKEN_EXCHANGE', providerKey: 'kick', credentialBearing: true
    });

    return response.data;
  }

  async refreshAccessToken({ refreshToken, providerConfiguration = null }) {
    const body = new URLSearchParams({
      client_id: oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'KICK_CLIENT_ID' }),
      client_secret: oauthConfigurationValue({ providerConfiguration, field: 'clientSecret', config: this.config, environmentKey: 'KICK_CLIENT_SECRET' }),
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    });

    const response = await this.httpClient.post(this.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'KICK-TOKEN', purpose: 'OAUTH_REFRESH', providerKey: 'kick', credentialBearing: true
    });

    return response.data;
  }

  async introspectToken({ accessToken }) {
    const response = await this.httpClient.post(this.introspectUrl, null, {
      bearerToken: accessToken,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      pathId: 'KICK-INTROSPECT', purpose: 'OAUTH_INTROSPECTION', providerKey: 'kick', credentialBearing: true
    });

    return response.data;
  }

  async getCurrentUser({ accessToken }) {
    const response = await this.httpClient.get(this.usersUrl, {
      bearerToken: accessToken,
      pathId: 'KICK-PROFILE', purpose: 'OAUTH_PROFILE_LOOKUP', providerKey: 'kick', credentialBearing: true
    });

    const users = Array.isArray(response.data?.data)
      ? response.data.data
      : [];

    if (users.length === 0) {
      throw new Error('Kick user lookup returned no user');
    }

    return users[0];
  }
}
