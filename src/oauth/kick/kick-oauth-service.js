import { OAuthResult } from '../../models/oauth-result.js';
import { HealthResult } from '../../models/health-result.js';
import { oauthConfigurationValue } from '../oauth-provider-configuration.js';
import { safeErrorMessage } from '../../utils/safe-diagnostics.js';
import { normalizeOAuthExpiry } from '../oauth-expiry.js';

const DEFAULT_SCOPES = Object.freeze([
  'user:read',
  'channel:read'
]);

export class KickOAuthService {
  constructor({ apiClient, config }) {
    this.apiClient = apiClient;
    this.config = config;
    this.authorizationUrl = 'https://id.kick.com/oauth/authorize';
  }

  getAuthorizationUrl({
    state = null,
    scopes = DEFAULT_SCOPES,
    codeChallenge = null,
    codeChallengeMethod = null,
    providerConfiguration = null
  } = {}) {
    if (!codeChallenge) {
      throw new Error('Kick OAuth requires PKCE code_challenge');
    }

    const url = new URL(this.authorizationUrl);

    url.searchParams.set('client_id', oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'KICK_CLIENT_ID' }));
    url.searchParams.set('redirect_uri', oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'KICK_REDIRECT_URI' }));
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
      throw new Error('Kick OAuth callback requires PKCE code_verifier');
    }

    const finalRedirectUri =
      redirectUri ?? oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'KICK_REDIRECT_URI' });

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
      const introspection = await this.apiClient.introspectToken({ accessToken });
      const data = introspection?.data ?? introspection;

      if (data?.active === false) {
        return new HealthResult({
          healthy: false,
          status: 'failed',
          message: 'Kick credential is inactive'
        });
      }

      return new HealthResult({
        healthy: true,
        status: 'ok',
        message: `Kick credential valid for client ${data?.client_id ?? 'unknown'}`
      });
    } catch (error) {
      return new HealthResult({
        healthy: false,
        status: 'failed',
        message: safeErrorMessage(error, 'Kick OAuth health check failed')
      });
    }
  }

  #createOAuthResult({ token, user }) {
    const accountId = String(user.user_id ?? user.id ?? user.username ?? user.name);
    const accountName = user.username ?? user.name ?? accountId;

    return new OAuthResult({
      providerId: `kick:${accountId}`,
      provider: 'kick',
      accountId,
      accountName,
      accessToken: token.access_token,
      refreshToken: token.refresh_token ?? null,
      expiresAt: this.#calculateExpiresAt(token.expires_in),
      scopes: this.#parseScopes(token.scope),
      metadata: {
        tokenType: token.token_type ?? null,
        username: user.username ?? null,
        name: user.name ?? null,
        email: user.email ?? null,
        profilePicture: user.profile_picture ?? null
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
