import { OAuthResult } from '../../models/oauth-result.js';
import { HealthResult } from '../../models/health-result.js';
import { oauthConfigurationValue } from '../oauth-provider-configuration.js';
import { safeErrorMessage } from '../../utils/safe-diagnostics.js';
import { normalizeOAuthExpiry } from '../oauth-expiry.js';

const DEFAULT_SCOPES = Object.freeze([
  'users.read',
  'offline.access'
]);

export class XOAuthService {
  constructor({ apiClient, config }) {
    this.apiClient = apiClient;
    this.config = config;
    this.authorizationUrl = 'https://twitter.com/i/oauth2/authorize';
  }

  getAuthorizationUrl({
    state = null,
    scopes = DEFAULT_SCOPES,
    codeChallenge = null,
    codeChallengeMethod = null,
    providerConfiguration = null
  } = {}) {
    if (!codeChallenge) {
      throw new Error('X OAuth requires PKCE code_challenge');
    }

    const url = new URL(this.authorizationUrl);

    url.searchParams.set('client_id', oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'X_CLIENT_ID' }));
    url.searchParams.set('redirect_uri', oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'X_REDIRECT_URI' }));
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', scopes.join(' '));
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', codeChallengeMethod ?? 'S256');

    if (state) {
      url.searchParams.set('state', state);
    }

    return url.toString();
  }

  async authenticate({ code, redirectUri = null, codeVerifier = null, providerConfiguration = null }) {
    if (!codeVerifier) {
      throw new Error('X OAuth callback requires PKCE code_verifier');
    }

    const finalRedirectUri = redirectUri ?? oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'X_REDIRECT_URI' });

    const token = await this.apiClient.exchangeCodeForToken({
      code,
      redirectUri: finalRedirectUri,
      codeVerifier,
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
        message: `X credential valid for ${user.username ?? user.id}`
      });
    } catch (error) {
      return new HealthResult({
        healthy: false,
        status: 'failed',
        message: safeErrorMessage(error, 'X OAuth health check failed')
      });
    }
  }

  #createOAuthResult({ token, user }) {
    return new OAuthResult({
      providerId: `x:${user.id}`,
      provider: 'x',
      accountId: user.id,
      accountName: user.username ?? user.name ?? user.id,
      accessToken: token.access_token,
      refreshToken: token.refresh_token ?? null,
      expiresAt: this.#calculateExpiresAt(token.expires_in),
      scopes: this.#parseScopes(token.scope),
      metadata: {
        tokenType: token.token_type ?? null,
        username: user.username ?? null,
        name: user.name ?? null,
        verified: user.verified ?? null,
        profileImageUrl: user.profile_image_url ?? null
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
      .split(' ')
      .map((value) => value.trim())
      .filter(Boolean);
  }

  #calculateExpiresAt(expiresIn) {
    return normalizeOAuthExpiry(expiresIn);
  }
}
