import { OAuthResult } from '../../models/oauth-result.js';
import { HealthResult } from '../../models/health-result.js';
import { oauthConfigurationValue } from '../oauth-provider-configuration.js';
import { safeErrorMessage } from '../../utils/safe-diagnostics.js';
import { normalizeOAuthExpiry } from '../oauth-expiry.js';

export class ThreadsOAuthService {
  constructor({ apiClient, config }) {
    this.apiClient = apiClient;
    this.config = config;

    this.authorizationUrl = 'https://threads.net/oauth/authorize';
  }

  getAuthorizationUrl({ state = null, scopes = ['threads_basic'], providerConfiguration = null } = {}) {
    const url = new URL(this.authorizationUrl);

    url.searchParams.set('client_id', oauthConfigurationValue({ providerConfiguration, field: 'clientId', config: this.config, environmentKey: 'THREADS_CLIENT_ID' }));
    url.searchParams.set('redirect_uri', oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'THREADS_REDIRECT_URI' }));
    url.searchParams.set('scope', scopes.join(','));
    url.searchParams.set('response_type', 'code');

    if (state) {
      url.searchParams.set('state', state);
    }

    return url.toString();
  }

  async authenticate({ code, redirectUri = null, providerConfiguration = null }) {
  const finalRedirectUri = redirectUri ?? oauthConfigurationValue({ providerConfiguration, field: 'redirectUri', config: this.config, environmentKey: 'THREADS_REDIRECT_URI' });

  const shortLived = await this.apiClient.exchangeCodeForToken({
    code,
    redirectUri: finalRedirectUri,
    ...(providerConfiguration ? { providerConfiguration } : {})
  });

    const longLived = await this.apiClient.exchangeForLongLivedToken({
      shortLivedToken: shortLived.access_token,
      ...(providerConfiguration ? { providerConfiguration } : {})
    });

    const user = await this.apiClient.getCurrentUser({
      accessToken: longLived.access_token
    });

    return this.#createOAuthResult({
      token: longLived,
      user
    });
  }

  async refresh({ accessToken }) {
    const refreshed = await this.apiClient.refreshLongLivedToken({
      accessToken
    });

    const user = await this.apiClient.getCurrentUser({
      accessToken: refreshed.access_token
    });

    return this.#createOAuthResult({
      token: refreshed,
      user
    });
  }

  async healthCheck({ accessToken }) {
    try {
      const user = await this.apiClient.getCurrentUser({
        accessToken
      });

      return new HealthResult({
        healthy: true,
        status: 'ok',
        message: `Threads credential valid for ${user.username ?? user.id}`
      });
    } catch (error) {
      return new HealthResult({
        healthy: false,
        status: 'failed',
        message: safeErrorMessage(error, 'Threads OAuth health check failed')
      });
    }
  }

  #createOAuthResult({ token, user }) {
    return new OAuthResult({
      providerId: `threads:${user.username ?? user.id}`,
      provider: 'threads',
      accountId: user.id,
      accountName: user.username ?? null,
      accessToken: token.access_token,
      refreshToken: null,
      expiresAt: this.#calculateExpiresAt(token.expires_in),
      scopes: [],
      metadata: {
        tokenType: token.token_type ?? null
      }
    });
  }

  #calculateExpiresAt(expiresIn) {
    return normalizeOAuthExpiry(expiresIn);
  }
}
