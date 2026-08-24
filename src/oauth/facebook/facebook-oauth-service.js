import { OAuthResult } from '../../models/oauth-result.js';
import { HealthResult } from '../../models/health-result.js';
import { oauthConfigurationValue } from '../oauth-provider-configuration.js';
import { safeErrorMessage } from '../../utils/safe-diagnostics.js';
import { normalizeOAuthExpiry } from '../oauth-expiry.js';

const DEFAULT_SCOPES = Object.freeze([
  'public_profile',
  'email'
]);

export class FacebookOAuthService {
  constructor({ apiClient, config }) {
    this.apiClient = apiClient;
    this.config = config;
    this.authorizationUrl = 'https://www.facebook.com/v20.0/dialog/oauth';
  }

  getAuthorizationUrl({ state = null, scopes = DEFAULT_SCOPES, providerConfiguration = null } = {}) {
    const url = new URL(this.authorizationUrl);

    url.searchParams.set('client_id', oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'FACEBOOK_CLIENT_ID' }));
    url.searchParams.set('redirect_uri', oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'FACEBOOK_REDIRECT_URI' }));
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', scopes.join(','));

    if (state) {
      url.searchParams.set('state', state);
    }

    return url.toString();
  }

  async authenticate({ code, redirectUri = null, providerConfiguration = null }) {
    const finalRedirectUri = redirectUri ?? oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'FACEBOOK_REDIRECT_URI' });

    const token = await this.apiClient.exchangeCodeForToken({
      code,
      redirectUri: finalRedirectUri,
      ...(providerConfiguration ? { providerConfiguration } : {})
    });

    const user = await this.apiClient.getCurrentUser({
      accessToken: token.access_token
    });

    return this.#createOAuthResult({ token, user });
  }

  async refresh({ refreshToken, providerConfiguration = null }) {
    const token = await this.apiClient.refreshAccessToken({ refreshToken, ...(providerConfiguration ? { providerConfiguration } : {}) });

    const user = await this.apiClient.getCurrentUser({
      accessToken: token.access_token
    });

    return this.#createOAuthResult({
      token: {
        ...token,
        refresh_token: token.refresh_token ?? refreshToken
      },
      user
    });
  }

  async healthCheck({ accessToken }) {
    try {
      const user = await this.apiClient.getCurrentUser({ accessToken });

      return new HealthResult({
        healthy: true,
        status: 'ok',
        message: `Facebook credential valid for ${user.name ?? user.id}`
      });
    } catch (error) {
      return new HealthResult({
        healthy: false,
        status: 'failed',
        message: safeErrorMessage(error, 'Facebook OAuth health check failed')
      });
    }
  }

  #createOAuthResult({ token, user }) {
    return new OAuthResult({
      providerId: `facebook:${user.id}`,
      provider: 'facebook',
      accountId: user.id,
      accountName: user.name ?? user.id,
      accessToken: token.access_token,
      refreshToken: token.refresh_token ?? null,
      expiresAt: this.#calculateExpiresAt(token.expires_in),
      scopes: this.#parseScopes(token.scope),
      metadata: {
        tokenType: token.token_type ?? null,
        name: user.name ?? null,
        email: user.email ?? null,
        pictureUrl: user.picture?.data?.url ?? null
      }
    });
  }

  #parseScopes(scope) {
    if (!scope) {
      return [];
    }

    if (Array.isArray(scope)) {
      return scope.map((value) => String(value).trim()).filter(Boolean);
    }

    return String(scope)
      .split(/[ ,]+/u)
      .map((value) => value.trim())
      .filter(Boolean);
  }

  #calculateExpiresAt(expiresIn) {
    return normalizeOAuthExpiry(expiresIn);
  }
}
