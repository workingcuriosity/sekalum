import { OAuthResult } from '../models/oauth-result.js';
import { TokenRecord } from '../models/token-record.js';
import { RestoreAdmissionService } from './restore-admission-service.js';
import { RestoreCommitCoordinator } from '../storage/restore-commit-coordinator.js';

export class TokenLifecycleService {
  constructor({ tokenStore, backupStore, logger, credentialManager = null, credentialManagerRef = null, restoreAdmissionService = null, restoreCommitCoordinator = null }) {
    this.tokenStore = tokenStore;
    this.backupStore = backupStore;
    this.logger = logger;
    this.credentialManager = credentialManager;
    this.credentialManagerRef = credentialManagerRef;
    this.restoreAdmissionService = restoreAdmissionService ?? new RestoreAdmissionService();
    this.restoreCommitCoordinator = restoreCommitCoordinator ?? new RestoreCommitCoordinator();
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
      ...(existingToken.credentialGeneration ? { credentialGeneration: existingToken.credentialGeneration } : {}),

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

    if (restoredToken.providerId !== providerId) {
      throw this.restoreAdmissionService.errorFromConflict({
        class: 'HARD_SECURITY_BLOCK',
        code: 'RESTORE_STATE_CHANGED',
        resourceType: 'TokenRecord',
        resourceId: restoredToken.providerId,
        remediation: 'Provider and account identity must match the requested restore target.'
      });
    }

    const credentialManager = this.credentialManager ?? this.credentialManagerRef?.();
    if (!credentialManager?.getCredentialByKey) {
      await this.tokenStore.save(restoredToken);
    } else {
      const currentCredential = await credentialManager.getCredentialByKey(restoredToken.credentialKey);
      const preflight = this.restoreAdmissionService.preflightLegacyProviderTokenRestore({
        restoredToken,
        currentToken: existingToken,
        currentCredential
      });
      this.restoreAdmissionService.assertCommitAllowed(preflight);

      await this.restoreCommitCoordinator.run(async () => {
        const finalToken = await this.#loadCurrentToken(providerId);
        const finalCredential = await credentialManager.getCredentialByKey(restoredToken.credentialKey);
        const finalAdmission = this.restoreAdmissionService.revalidateLegacyProviderTokenRestore({
          preflight,
          restoredToken,
          currentToken: finalToken,
          currentCredential: finalCredential
        });
        this.restoreAdmissionService.assertCommitAllowed(finalAdmission);
        await this.tokenStore.save(restoredToken);
      });
    }

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

  async #loadCurrentToken(providerId) {
    if (!this.tokenStore?.load) return null;
    try {
      return await this.tokenStore.load(providerId);
    } catch (error) {
      if (['ENOENT', 'NOT_FOUND'].includes(error?.code)) return null;
      throw error;
    }
  }

  #fromOAuthResult(oauthResult, existingToken = null) {
    const now = new Date();

    return new TokenRecord({
      ...(existingToken ? { id: existingToken.id, credentialKey: existingToken.credentialKey } : {}),
      providerId: oauthResult.providerId,
      provider: oauthResult.provider,
      accountId: oauthResult.accountId,
      accountName: oauthResult.accountName,
      ...(existingToken?.credentialGeneration ? { credentialGeneration: existingToken.credentialGeneration } : {}),

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
