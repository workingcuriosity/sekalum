import { OAuthResult } from '../models/oauth-result.js';
import { TokenRecord } from '../models/token-record.js';

export class TokenLifecycleService {
  constructor({ tokenStore, backupStore, logger }) {
    this.tokenStore = tokenStore;
    this.backupStore = backupStore;
    this.logger = logger;
  }

  async import(oauthResult) {
    if (!(oauthResult instanceof OAuthResult)) {
      throw new Error('TokenLifecycleService.import() requires an OAuthResult');
    }

    let existingToken = null;
    if (await this.tokenStore.exists(oauthResult.providerId)) {
      existingToken = await this.tokenStore.load(oauthResult.providerId);
      await this.backupStore.createBackup(existingToken);
    }

    const tokenRecord = this.#fromOAuthResult(oauthResult, existingToken);

    await this.tokenStore.save(tokenRecord);

    this.logger.info(`Token imported: ${tokenRecord.providerId}`);

    return tokenRecord;
  }

  async refresh(existingToken, oauthResult) {
    if (!(existingToken instanceof TokenRecord)) {
      throw new Error('TokenLifecycleService.refresh() requires an existing TokenRecord');
    }

    if (!(oauthResult instanceof OAuthResult)) {
      throw new Error('TokenLifecycleService.refresh() requires an OAuthResult');
    }

    await this.backupStore.createBackup(existingToken);

    const now = new Date();

    const refreshedToken = new TokenRecord({
      id: existingToken.id,
      credentialKey: existingToken.credentialKey,
      providerId: existingToken.providerId,
      provider: existingToken.provider,
      accountId: existingToken.accountId,
      accountName: oauthResult.accountName ?? existingToken.accountName,

      accessToken: oauthResult.accessToken,
      refreshToken: oauthResult.refreshToken ?? existingToken.refreshToken,

      expiresAt: oauthResult.expiresAt,
      scopes: oauthResult.scopes,
      metadata: {
        ...existingToken.metadata,
        ...oauthResult.metadata
      },

      createdAt: existingToken.createdAt,
      updatedAt: now,
      lastRefreshAt: now,
      lastHealthCheckAt: existingToken.lastHealthCheckAt,

      version: existingToken.version + 1
    });

    await this.tokenStore.save(refreshedToken);

    this.logger.info(`Token refreshed: ${refreshedToken.providerId}`);

    return refreshedToken;
  }

  async restore(providerId, backupId) {
    let existingToken = null;
    if (this.tokenStore?.load) {
      try {
        existingToken = await this.tokenStore.load(providerId);
      } catch (error) {
        if (!['ENOENT', 'NOT_FOUND'].includes(error?.code)) throw error;
      }
    }
    const restoredToken = await this.backupStore.restore(providerId, backupId, {
      existingCredentialKey: existingToken?.credentialKey
    });

    await this.tokenStore.save(restoredToken);

    this.logger.info(`Token restored: ${providerId} from backup ${backupId}`);

    return restoredToken;
  }

  async load(providerId) {
    return this.tokenStore.load(providerId);
  }

  async exists(providerId) {
    return this.tokenStore.exists(providerId);
  }

  async delete(providerId) {
    const existed = await this.tokenStore.delete(providerId);

    if (existed) {
      this.logger.info(`Token deleted: ${providerId}`);
    }

    return existed;
  }

  #fromOAuthResult(oauthResult, existingToken = null) {
    const now = new Date();

    return new TokenRecord({
      ...(existingToken ? { id: existingToken.id, credentialKey: existingToken.credentialKey } : {}),
      providerId: oauthResult.providerId,
      provider: oauthResult.provider,
      accountId: oauthResult.accountId,
      accountName: oauthResult.accountName,

      accessToken: oauthResult.accessToken,
      refreshToken: oauthResult.refreshToken,

      expiresAt: oauthResult.expiresAt,
      scopes: oauthResult.scopes,
      metadata: oauthResult.metadata,

      createdAt: now,
      updatedAt: now,
      lastRefreshAt: null,
      lastHealthCheckAt: null,

      version: 1
    });
  }
}
