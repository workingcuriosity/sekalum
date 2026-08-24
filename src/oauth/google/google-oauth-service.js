import { OAuthResult } from '../../models/oauth-result.js';
import { HealthResult } from '../../models/health-result.js';
import { oauthConfigurationValue } from '../oauth-provider-configuration.js';
import { safeErrorMessage } from '../../utils/safe-diagnostics.js';
import { normalizeOAuthExpiry } from '../oauth-expiry.js';

const DEFAULT_SCOPES = Object.freeze([
  'openid',
  'email',
  'profile'
]);

export class GoogleOAuthService {
  constructor({ apiClient, config }) {
    this.apiClient = apiClient;
    this.config = config;
    this.authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  }

  getAuthorizationUrl({ state = null, scopes = DEFAULT_SCOPES, providerConfiguration = null } = {}) {
    const url = new URL(this.authorizationUrl);

    url.searchParams.set('client_id', oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'GOOGLE_CLIENT_ID' }));
    url.searchParams.set('redirect_uri', oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'GOOGLE_REDIRECT_URI' }));
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', scopes.join(' '));
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('prompt', 'consent');

    if (state) {
      url.searchParams.set('state', state);
    }

    return url.toString();
  }

  async authenticate({ code, redirectUri = null, providerConfiguration = null }) {
    const finalRedirectUri =
      redirectUri ?? oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'GOOGLE_REDIRECT_URI' });

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
        message: `Google credential valid for ${user.email ?? user.sub}`
      });
    } catch (error) {
      return new HealthResult({
        healthy: false,
        status: 'failed',
        message: safeErrorMessage(error, 'Google OAuth health check failed')
      });
    }
  }

  #createOAuthResult({ token, user }) {
    const accountName = user.email ?? user.name ?? null;

    return new OAuthResult({
      providerId: `google:${user.sub}`,
      provider: 'google',
      accountId: user.sub,
      accountName,
      accessToken: token.access_token,
      refreshToken: token.refresh_token ?? null,
      expiresAt: this.#calculateExpiresAt(token.expires_in),
      scopes: this.#parseScopes(token.scope),
      metadata: {
        tokenType: token.token_type ?? null,
        email: user.email ?? null,
        emailVerified: user.email_verified ?? null,
        name: user.name ?? null,
        picture: user.picture ?? null
      }
    });
  }

  #parseScopes(scope) {
    if (!scope) {
      return [];
    }

    return String(scope)
      .split(' ')
      .map((value) => value.trim())
      .filter(Boolean);
  }

  #calculateExpiresAt(expiresIn) {
    return normalizeOAuthExpiry(expiresIn);
  }
}
