// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { ProviderCapability } from '../models/provider-capability.js';
import { ProviderResult } from '../models/provider-result.js';
import { isProviderProfileMigrationVerified } from '../models/credential.js';
import { OAuthResult } from '../models/oauth-result.js';
import {
  OAuthClientBindingIdentity,
  OAuthCredentialBinding,
  compareOAuthContextEvidence,
  normalizeScopes
} from '../models/oauth-context-binding.js';

function compareCanonical(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export class ProviderManager {
  constructor({
    providerRegistry,
    oauthSecurityService = null,
    providerConfigurationService = null,
    logger
  }) {
    this.providerRegistry = providerRegistry;
    this.oauthSecurityService = oauthSecurityService;
    this.providerConfigurationService = providerConfigurationService;
    this.logger = logger;
  }


  listProviders() {
  return this.providerRegistry
    .list()
    .map((providerName) => this.#providerSummary(providerName));
}

getProvider(providerName) {
  if (!providerName || !this.providerRegistry.has(providerName)) {
    const error = new Error(`Provider '${providerName}' not found`);
    error.code = 'NOT_FOUND';
    throw error;
  }

  return this.#providerSummary(providerName);
}

getProviderCapabilities(providerName) {
  return this.getProvider(providerName).capabilities;
}

  listProviderCatalog() {
    return this.providerRegistry
      .list()
      .map((providerName) => this.#providerCatalogRecord(providerName))
      .sort((left, right) => compareCanonical(left.key, right.key));
  }

  async startOAuth(providerName, options = {}) {
    await this.cleanupExpiredOAuthContexts();
    const { actorUserId: _actorUserId, ...providerOptions } = options;
    return this.#execute({
      providerName,
      operation: 'startOAuth',
      capability: ProviderCapability.OAUTH,
      action: async (provider, definition) => {
        const configurationRecord = await this.#prepareProviderConfiguration({
          providerName,
          definition,
          options: providerOptions
        });
        const configuredOptions = configurationRecord
          ? {
              ...providerOptions,
              providerConfiguration: configurationRecord.configuration,
              providerConfigurationId: configurationRecord.configurationId,
              providerProfile: configurationRecord.providerProfile
            }
          : options;
        const credentialMethodKey = this.#oauthCredentialMethodKey(definition, configuredOptions);
        const boundOptions = {
          ...configuredOptions,
          credentialMethodKey,
          scopes: this.#resolveOAuthScopes(definition, configuredOptions)
        };
        let securityContext = null;
        try {
          securityContext = this.#createOAuthSecurityContext({
            providerName,
            definition,
            options: {
              ...boundOptions,
              actorUserId: _actorUserId ?? null,
              providerConfigurationTemporary: Boolean(
                configurationRecord && !providerOptions.providerConfigurationId
              )
            }
          });
          const result = await provider.startOAuth({
            ...boundOptions,
            ...this.#authorizationOptionsFromSecurityContext(securityContext),
            oauthSecurityContext: securityContext
          });
          if (!configurationRecord) return result;
          if (!result?.success) {
            this.oauthSecurityService?.discardAuthorizationContext?.(securityContext?.state);
            await this.#removeOAuthFlowConfiguration(securityContext, providerName);
            return result;
          }
          return ProviderResult.success({
            ...result.data,
            providerConfigurationId: configurationRecord.configurationId
          });
        } catch (error) {
          this.oauthSecurityService?.discardAuthorizationContext?.(securityContext?.state);
          await this.#removeOAuthFlowConfiguration(
            securityContext ?? {
              providerConfigurationId: configurationRecord?.configurationId,
              providerConfigurationTemporary: Boolean(
                configurationRecord && !providerOptions.providerConfigurationId
              )
            },
            providerName
          );
          throw error;
        }
      }
    });
  }

  async handleOAuthCallback(providerName, callbackData = {}, {
    expectedActorUserId = null,
    publicOrigin = null,
    redirectUri = null
  } = {}) {
    await this.cleanupExpiredOAuthContexts();
    const providerCallbackData = callbackData;
    return this.#execute({
      providerName,
      operation: 'handleOAuthCallback',
      capability: ProviderCapability.OAUTH,
      action: async (provider, definition) => {
        let securityContext;
        try {
        securityContext = this.#consumeOAuthSecurityContext({
            providerName,
            callbackData,
            providerProfile: definition.providerProfile,
          expectedActorUserId: expectedActorUserId ?? null
        });
        await this.#revalidateOAuthSecurityContext({
          providerName,
          definition,
          securityContext,
          publicOrigin,
          redirectUri
        });
        } catch (error) {
          await this.#removeOAuthFlowConfiguration(securityContext ?? error, error.providerKey ?? providerName);
          throw error;
        }

        try {
          const result = await provider.handleOAuthCallback({
            ...providerCallbackData,
            ...this.#callbackOptionsFromSecurityContext(securityContext),
            providerConfiguration: await this.#configurationForOAuthContext(
              securityContext,
              providerName,
              definition
            ),
            oauthSecurityContext: securityContext
          });
          if (!result?.success) {
            await this.#removeOAuthFlowConfiguration(securityContext, providerName);
            return result;
          }
          if (result.data?.provider && result.data.provider !== providerName) {
            const error = new Error('OAuth result provider does not match callback provider');
            error.code = 'OAUTH_PROVIDER_MISMATCH';
            error.statusCode = 400;
            throw error;
          }
          const admission = compareOAuthContextEvidence({
            providerKey: providerName,
            binding: this.#bindingFromSecurityContext(securityContext),
            currentBinding: this.#bindingFromSecurityContext(securityContext),
            oauthResult: result.data
          });
          if (!admission.pass) throw admission.failures[0];
          return this.#attachProviderConfigurationReference(result, securityContext, admission);
        } catch (error) {
          await this.#removeOAuthFlowConfiguration(securityContext, providerName);
          throw error;
        }
      }
    });
  }

  async cancelOAuth(providerName, state, { expectedActorUserId = null } = {}) {
    await this.cleanupExpiredOAuthContexts();
    const definition = this.providerRegistry.get(providerName);
    try {
      const securityContext = this.#consumeOAuthSecurityContext({
        providerName,
        callbackData: { state },
        providerProfile: definition.providerProfile,
        expectedActorUserId
      });
      return this.#removeOAuthFlowConfiguration(securityContext, providerName);
    } catch (error) {
      await this.#removeOAuthFlowConfiguration(error, error.providerKey ?? providerName);
      throw error;
    }
  }

  async cleanupExpiredOAuthContexts() {
    if (!this.oauthSecurityService?.purgeExpiredContexts) return [];
    const expired = this.oauthSecurityService.purgeExpiredContexts();
    for (const context of expired) {
      try {
        await this.#removeOAuthFlowConfiguration(context, context.provider);
      } catch (error) {
        this.logger?.error?.('OAuth flow cleanup failed', {
          code: error.code ?? 'OAUTH_CLEANUP_FAILED',
          provider: context.provider
        });
      }
    }
    return expired;
  }

  async discardProviderConfiguration(configurationId, providerName) {
    return this.#removeProviderConfiguration(configurationId, providerName);
  }

#providerSummary(providerName) {
  const definition = this.providerRegistry.get(providerName);
  const credentialFields = definition.credentialFields?.map((field) => field.toJSON?.() ?? field) ?? [];
  const credentialMethods = definition.credentialMethods?.map((method) => method.toJSON?.() ?? method) ?? [];
  const providerMethodBindings = definition.providerMethodBindings?.map((binding) => binding.toJSON?.() ?? binding) ?? [];

  const summary = {
    key: providerName,
    displayName: definition.displayName ?? providerName,
    description: definition.description ?? null,
    category: definition.metadata?.category ?? null,
    customProvider: Boolean(definition.metadata?.customProvider),
    capabilities: definition.capabilities?.toArray?.() ?? [],
    // Retained for clients that have not yet selected a credential method.
    credentialFields,
    providerConfigurationFields: credentialFields.filter((field) => field.section === 'providerConfiguration'),
    authType: definition.metadata?.authType ?? null,
    defaultScopes: definition.metadata?.defaultScopes ?? [],
    // These arrays are part of the public provider contract.  Always expose
    // them so API consumers do not need to infer support from missing keys.
    credentialMethods,
    providerMethodBindings,
    ...(definition.providerProfile ? { providerProfile: definition.providerProfile.identity?.() ?? definition.providerProfile } : {}),
    ...(definition.runtimeDerivation?.supportsRuntimeDerivation
      ? { runtimeDerivation: definition.runtimeDerivation.toJSON() }
      : {}),
    oauthSecurity: definition.oauthSecurityRequirements?.toJSON?.() ?? null,
    oauthTechnical: definition.oauthService
      ? {
          authorizationEndpoint: definition.oauthService.authorizationUrl ?? null
        }
      : null
  };

  return summary;
}

  #providerCatalogRecord(providerName) {
    const definition = this.providerRegistry.get(providerName);
    const capabilities = definition.capabilities?.toArray?.() ?? [];

    return {
      key: providerName,
      displayName: definition.displayName ?? providerName,
      description: definition.description ?? null,
      category: definition.metadata?.category ?? null,
      authType: definition.metadata?.authType ?? null,
      capabilities: [...capabilities].sort(compareCanonical),
    };
  }


  async refreshCredential(credential) {
    return this.#executeCredentialOperation({
      credential,
      operation: 'refreshCredential',
      capability: ProviderCapability.REFRESH,
      action: async (provider) => {
        const providerConfiguration = await this.#configurationForCredential({
          ...credential,
          provider: credential.providerKey
        }, this.providerRegistry.get(credential.providerKey));
        const configuredCredential = { ...credential, providerConfiguration };
        if (typeof provider.refreshCredential === 'function') {
          return provider.refreshCredential(configuredCredential);
        }
        return provider.refreshToken(configuredCredential);
      }
    });
  }

  async validateCredential(credential, operationContext = {}) {
    return this.#executeCredentialOperation({
      credential,
      operation: 'validateCredential',
      capability: ProviderCapability.VALIDATION,
      operationContext,
      action: (provider, _definition, context) => {
        if (typeof provider.validateCredential === 'function') {
          return provider.validateCredential(credential, context);
        }
        return provider.validateToken(credential);
      }
    });
  }

  async deriveRuntimeMaterial(credential, context = {}) {
    return this.#executeCredentialOperation({
      credential,
      operation: 'deriveRuntimeMaterial',
      capability: ProviderCapability.RUNTIME_DERIVATION,
      operationContext: context,
      action: (provider, definition, operationContext) => {
        if (typeof provider.deriveRuntimeMaterial !== 'function') {
          const error = new Error('Provider does not implement runtime derivation');
          error.code = 'DERIVATION_CONFIGURATION_INVALID';
          error.classification = 'provider_contract_incompatible';
          return ProviderResult.failure(error);
        }
        return provider.deriveRuntimeMaterial({
          credential,
          context: operationContext,
          providerProfile: definition.providerProfile
        });
      }
    });
  }

  async revokeCredential(credential) {
    return this.#executeCredentialOperation({
      credential,
      operation: 'revokeCredential',
      capability: ProviderCapability.REVOKE,
      action: (provider) => {
        if (typeof provider.revokeCredential === 'function') {
          return provider.revokeCredential(credential);
        }
        return provider.revokeToken(credential);
      }
    });
  }

  async healthCheckCredential(credential, operationContext = {}) {
    return this.#executeCredentialOperation({
      credential,
      operation: 'healthCheckCredential',
      capability: ProviderCapability.HEALTH_CHECK,
      operationContext,
      action: (provider, _definition, context) => provider.healthCheck(credential, context)
    });
  }

  async refreshToken(tokenRecord) {
    return this.#executeTokenOperation({
      tokenRecord,
      operation: 'refreshToken',
      capability: ProviderCapability.REFRESH,
      action: async (provider) => provider.refreshToken({
        ...tokenRecord,
        providerConfiguration: await this.#configurationForCredential(
          tokenRecord,
          this.providerRegistry.get(tokenRecord.provider)
        )
      })
    });
  }

  async validateToken(tokenRecord) {
    return this.#executeTokenOperation({
      tokenRecord,
      operation: 'validateToken',
      capability: ProviderCapability.VALIDATION,
      action: (provider) => provider.validateToken(tokenRecord)
    });
  }

  async revokeToken(tokenRecord) {
    return this.#executeTokenOperation({
      tokenRecord,
      operation: 'revokeToken',
      capability: ProviderCapability.REVOKE,
      action: (provider) => provider.revokeToken(tokenRecord)
    });
  }

  async healthCheck(providerName, tokenRecord = null) {
    return this.#execute({
      providerName,
      operation: 'healthCheck',
      capability: ProviderCapability.HEALTH_CHECK,
      action: (provider) => provider.healthCheck(tokenRecord),
      context: {
        providerId: tokenRecord?.providerId ?? null
      }
    });
  }

  async getOAuthClientBinding(credential) {
    const providerName = credential?.providerKey;
    const definition = this.providerRegistry.get(providerName);
    const configuration = await this.#configurationForCredential(credential, definition);
    const environmentKeys = {
      x: ['X_CLIENT_ID', 'X_REDIRECT_URI'],
      kick: ['KICK_CLIENT_ID', 'KICK_REDIRECT_URI'],
      twitch: ['TWITCH_CLIENT_ID', 'TWITCH_REDIRECT_URI'],
      google: ['GOOGLE_CLIENT_ID', 'GOOGLE_REDIRECT_URI'],
      discord: ['DISCORD_CLIENT_ID', 'DISCORD_REDIRECT_URI'],
      threads: ['THREADS_CLIENT_ID', 'THREADS_REDIRECT_URI'],
      facebook: ['FACEBOOK_CLIENT_ID', 'FACEBOOK_REDIRECT_URI'],
      instagram: ['INSTAGRAM_CLIENT_ID', 'INSTAGRAM_REDIRECT_URI']
    }[providerName] ?? [];
    const config = definition.oauthService?.config;
    const methodKey = credential.credentialMethodKey ?? this.#oauthCredentialMethodKey(definition);
    const redirectUri = configuration?.redirectUri
      ?? config?.get?.(environmentKeys[1])
      ?? 'https://invalid.invalid/oauth/callback';
    return OAuthClientBindingIdentity.from({
      providerKey: providerName,
      providerProfile: definition.providerProfile,
      credentialMethodKey: methodKey,
      providerConfigurationId: credential.providerConfigurationId
        ?? credential.metadata?.custom?.providerConfigurationId
        ?? null,
      clientId: configuration?.clientId ?? config?.get?.(environmentKeys[0]) ?? 'environment-client',
      redirectUri,
      publicOrigin: redirectUri
    });
  }

  async validateOAuthResultBinding(contextBinding) {
    if (!contextBinding) return true;
    const providerName = contextBinding.providerKey;
    const definition = this.providerRegistry.get(providerName);
    const currentProfile = definition.providerProfile?.identity?.() ?? definition.providerProfile ?? null;
    if (contextBinding.providerProfile?.digest && currentProfile?.digest
      && contextBinding.providerProfile.digest !== currentProfile.digest) {
      const error = new Error('OAuth provider profile changed before Credential commit');
      error.code = 'OAUTH_PROFILE_MISMATCH';
      error.statusCode = 409;
      throw error;
    }
    const methodKey = this.#oauthCredentialMethodKey(definition, { credentialMethodKey: contextBinding.credentialMethodKey });
    if (methodKey !== contextBinding.credentialMethodKey) {
      const error = new Error('OAuth credential method changed before Credential commit');
      error.code = 'OAUTH_METHOD_MISMATCH';
      error.statusCode = 409;
      throw error;
    }
    let configuration = null;
    if (contextBinding.providerConfigurationId && this.providerConfigurationService?.load) {
      const record = await this.providerConfigurationService.load(
        contextBinding.providerConfigurationId,
        providerName,
        currentProfile
      );
      configuration = record?.configuration ?? record ?? null;
    }
    const currentBinding = new OAuthClientBindingIdentity({
      providerKey: providerName,
      providerProfile: currentProfile,
      credentialMethodKey: methodKey,
      providerConfigurationId: contextBinding.providerConfigurationId,
      clientId: configuration?.clientId ?? this.#oauthClientId(definition, providerName),
      redirectUri: contextBinding.redirectUri,
      publicOrigin: contextBinding.publicOrigin
    });
    if (currentBinding.clientBindingFingerprint !== contextBinding.clientBindingFingerprint) {
      const error = new Error('OAuth client binding changed before Credential commit');
      error.code = 'OAUTH_CLIENT_MISMATCH';
      error.statusCode = 409;
      throw error;
    }
    return true;
  }




  #createOAuthSecurityContext({ providerName, definition, options }) {
    if (!this.oauthSecurityService) {
      return null;
    }

    return this.oauthSecurityService.createAuthorizationContext({
      provider: providerName,
      requirements: definition.oauthSecurityRequirements,
      state: options.state ?? null,
      scopes: options.scopes ?? null,
      account: options.account ?? null,
      providerConfiguration: options.providerConfiguration ?? null,
      providerConfigurationId: options.providerConfigurationId ?? null,
      providerConfigurationTemporary: options.providerConfigurationTemporary ?? false,
      actorUserId: options.actorUserId ?? null,
      providerProfile: definition.providerProfile,
      credentialMethodKey: options.credentialMethodKey ?? this.#oauthCredentialMethodKey(definition, options),
      publicOrigin: options.publicOrigin ?? null,
      redirectUri: options.redirectUri ?? options.providerConfiguration?.redirectUri ?? null,
      clientId: options.clientId ?? options.providerConfiguration?.clientId ?? this.#oauthClientId(definition, providerName),
      requiredScopes: options.requiredScopes ?? this.#oauthRequiredScopes(definition, options.credentialMethodKey),
      credentialBinding: options.credentialBinding ?? null
    });
  }

  #consumeOAuthSecurityContext({
    providerName,
    callbackData,
    providerProfile = null,
    expectedActorUserId = null
  }) {
    if (!this.oauthSecurityService || !callbackData?.state) {
      return null;
    }

    return this.oauthSecurityService.consumeCallbackContext({
      provider: providerName,
      state: callbackData.state,
      providerProfile,
      expectedActorUserId
    });
  }

  #authorizationOptionsFromSecurityContext(securityContext) {
    if (!securityContext) {
      return {};
    }

    return {
      state: securityContext.state,
      codeChallenge: securityContext.codeChallenge,
      codeChallengeMethod: securityContext.codeChallengeMethod,
      nonce: securityContext.nonce
    };
  }

  #callbackOptionsFromSecurityContext(securityContext) {
    if (!securityContext) {
      return {};
    }

    return {
      codeVerifier: securityContext.codeVerifier,
      nonce: securityContext.nonce,
      providerConfigurationId: securityContext.providerConfigurationId ?? null,
      providerProfile: securityContext.providerProfile ?? null,
      credentialMethodKey: securityContext.credentialMethodKey ?? null,
      redirectUri: securityContext.redirectUri ?? null,
      publicOrigin: securityContext.publicOrigin ?? null,
      clientBindingFingerprint: securityContext.clientBindingFingerprint ?? null,
      requestedScopes: securityContext.requestedScopes ?? securityContext.scopes ?? [],
      requiredScopes: securityContext.requiredScopes ?? []
    };
  }

  async #configurationForOAuthContext(securityContext, providerName, definition) {
    if (!securityContext?.providerConfigurationId || !this.providerConfigurationService?.load) return null;
    const record = await this.providerConfigurationService.load(
      securityContext.providerConfigurationId,
      providerName,
      definition.providerProfile
    );
    return record?.configuration ?? record ?? null;
  }

  #resolveOAuthScopes(definition, options = {}) {
    const preserveScopeOrder = (scopes) => {
      normalizeScopes(scopes);
      return [...new Set(scopes.map((scope) => scope.trim()))];
    };
    if (Array.isArray(options.scopes) && options.scopes.length > 0) return preserveScopeOrder(options.scopes);
    const method = definition.getCredentialMethod?.(options.credentialMethodKey)
      ?? definition.credentialMethods?.find((candidate) => candidate.key === options.credentialMethodKey);
    const field = method?.credentialFields?.find((candidate) => candidate.key === 'scopes');
    return preserveScopeOrder(definition.metadata?.defaultScopes ?? field?.defaultValue ?? []);
  }

  #oauthRequiredScopes(definition, methodKey = null) {
    const method = definition.getCredentialMethod?.(methodKey)
      ?? definition.credentialMethods?.find((candidate) => candidate.key === methodKey);
    return normalizeScopes(method?.requiredScopes ?? []);
  }

  #oauthClientId(definition, providerName) {
    const environmentKey = {
      x: 'X_CLIENT_ID', kick: 'KICK_CLIENT_ID', twitch: 'TWITCH_CLIENT_ID',
      google: 'GOOGLE_CLIENT_ID', discord: 'DISCORD_CLIENT_ID', threads: 'THREADS_CLIENT_ID',
      facebook: 'FACEBOOK_CLIENT_ID', instagram: 'INSTAGRAM_CLIENT_ID'
    }[providerName];
    return definition.oauthService?.config?.get?.(environmentKey) ?? 'environment-client';
  }

  #bindingFromSecurityContext(securityContext, overrides = {}) {
    return {
      providerKey: securityContext.provider,
      providerProfile: securityContext.providerProfile,
      credentialMethodKey: securityContext.credentialMethodKey,
      providerConfigurationId: securityContext.providerConfigurationId,
      clientBindingFingerprint: securityContext.clientBindingFingerprint,
      publicOrigin: overrides.publicOrigin ?? securityContext.publicOrigin,
      redirectUri: overrides.redirectUri ?? securityContext.redirectUri,
      requestedScopes: securityContext.requestedScopes ?? securityContext.scopes ?? [],
      requiredScopes: securityContext.requiredScopes ?? [],
      accountId: securityContext.account ?? null
    };
  }

  async #revalidateOAuthSecurityContext({ providerName, definition, securityContext, publicOrigin, redirectUri }) {
    const currentProfile = definition.providerProfile?.identity?.() ?? definition.providerProfile ?? null;
    if (securityContext.providerProfile?.digest && currentProfile?.digest
      && securityContext.providerProfile.digest !== currentProfile.digest) {
      const error = new Error('OAuth provider profile changed during the transaction');
      error.code = 'OAUTH_PROFILE_MISMATCH';
      error.statusCode = 400;
      throw error;
    }
    const methodKey = this.#oauthCredentialMethodKey(definition, { credentialMethodKey: securityContext.credentialMethodKey });
    if (methodKey !== securityContext.credentialMethodKey) {
      const error = new Error('OAuth credential method changed during the transaction');
      error.code = 'OAUTH_METHOD_MISMATCH';
      error.statusCode = 400;
      throw error;
    }
    let currentConfiguration = securityContext.providerConfiguration;
    if (securityContext.providerConfigurationId && this.providerConfigurationService?.load) {
      const record = await this.providerConfigurationService.load(
        securityContext.providerConfigurationId,
        providerName,
        currentProfile
      );
      currentConfiguration = record?.configuration ?? record ?? null;
    }
    const currentBinding = new OAuthClientBindingIdentity({
      providerKey: providerName,
      providerProfile: currentProfile,
      credentialMethodKey: methodKey,
      providerConfigurationId: securityContext.providerConfigurationId,
      clientId: currentConfiguration?.clientId ?? this.#oauthClientId(definition, providerName),
      redirectUri: redirectUri ?? securityContext.redirectUri,
      publicOrigin: publicOrigin ?? securityContext.publicOrigin
    });
    if (currentBinding.clientBindingFingerprint !== securityContext.clientBindingFingerprint) {
      const error = new Error('OAuth client binding changed during the transaction');
      error.code = 'OAUTH_CLIENT_MISMATCH';
      error.statusCode = 400;
      throw error;
    }
    if ((redirectUri && redirectUri !== securityContext.redirectUri)
      || (publicOrigin && publicOrigin !== securityContext.publicOrigin)) {
      const error = new Error('OAuth redirect or public origin changed during the transaction');
      error.code = 'OAUTH_REDIRECT_URI_MISMATCH';
      error.statusCode = 400;
      throw error;
    }
  }

  async #prepareProviderConfiguration({ providerName, definition, options }) {
    if (options.providerConfiguration === undefined) return null;
    if (!this.providerConfigurationService) {
      const error = new Error('Provider configuration storage is unavailable');
      error.code = 'PROVIDER_CONFIGURATION_UNAVAILABLE';
      error.statusCode = 500;
      throw error;
    }

    return this.providerConfigurationService.prepare({
      providerKey: providerName,
      fields: definition.credentialFields ?? [],
      values: options.providerConfiguration,
      configurationId: options.providerConfigurationId ?? null,
      providerProfile: definition.providerProfile,
      temporary: !options.providerConfigurationId,
      expiresAt: this.#oauthConfigurationExpiresAt()
    });
  }

  #oauthConfigurationExpiresAt() {
    const configuredTtl = Number(this.oauthSecurityService?.ttlMs);
    const ttlMs = Number.isFinite(configuredTtl) && configuredTtl >= 0
      ? configuredTtl
      : 10 * 60 * 1000;
    return new Date(Date.now() + ttlMs).toISOString();
  }

  async #configurationForCredential(credential, definition = null) {
    const configurationId = credential?.providerConfigurationId
      ?? credential?.metadata?.providerConfigurationId
      ?? credential?.metadata?.custom?.providerConfigurationId
      ?? null;
    if (!configurationId || !this.providerConfigurationService) return null;
    return (await this.providerConfigurationService.load(
      configurationId,
      credential.provider,
      definition?.providerProfile ?? null
    )).configuration;
  }

  async #removeProviderConfiguration(configurationId, providerName) {
    if (!configurationId || !this.providerConfigurationService) return false;
    return this.providerConfigurationService.remove(configurationId, providerName);
  }

  async #removeOAuthFlowConfiguration(context, providerName) {
    if (!context?.providerConfigurationTemporary) return false;
    return this.#removeProviderConfiguration(context.providerConfigurationId, providerName);
  }

  #attachProviderConfigurationReference(result, securityContext, admission = null) {
    const configurationId = securityContext?.providerConfigurationId;
    if (!result?.success || !(result.data instanceof OAuthResult)) return result;
    const data = result.data;
    const returnedProfile = data.metadata?.providerProfile ?? null;
    if (securityContext?.providerProfile && returnedProfile
      && returnedProfile.digest !== securityContext.providerProfile.digest) {
      const error = new Error('OAuth result provider profile does not match authorization context');
      error.code = 'OAUTH_PROFILE_MISMATCH';
      error.statusCode = 400;
      throw error;
    }
    return ProviderResult.success(new OAuthResult({
      providerId: data.providerId,
      provider: data.provider,
      accountId: data.accountId,
      accountName: data.accountName,
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      expiresAt: data.expiresAt,
      scopes: data.scopes,
      contextBinding: new OAuthCredentialBinding({
        providerKey: securityContext.provider,
        providerProfile: securityContext.providerProfile,
        credentialMethodKey: securityContext.credentialMethodKey,
        providerConfigurationId: securityContext.providerConfigurationId,
        clientBindingFingerprint: securityContext.clientBindingFingerprint,
        accountId: data.accountId,
        grantedScopes: admission?.grantedScopes ?? data.scopes ?? [],
        redirectUri: securityContext.redirectUri,
        publicOrigin: securityContext.publicOrigin
      }).toJSON(),
      evidence: admission?.evidence?.map((entry) => entry.toJSON?.() ?? entry) ?? [],
      metadata: {
        ...data.metadata,
        ...(configurationId ? { providerConfigurationId: configurationId } : {}),
        ...(securityContext.providerProfile ? { providerProfile: securityContext.providerProfile } : {}),
        ...(securityContext.credentialMethodKey ? { credentialMethodKey: securityContext.credentialMethodKey } : {})
      }
    }));
  }

  #oauthCredentialMethodKey(definition, options = {}) {
    if (options.credentialMethodKey) {
      const method = definition.getCredentialMethod?.(options.credentialMethodKey)
        ?? definition.credentialMethods?.find((candidate) => candidate.key === options.credentialMethodKey);
      if (!method || method.authenticationMethod !== 'oauth2') {
        const error = new Error('OAuth credential method is not bound to the provider profile');
        error.code = 'OAUTH_METHOD_INVALID';
        error.statusCode = 400;
        throw error;
      }
      return options.credentialMethodKey;
    }
    const methods = (definition.credentialMethods ?? []).filter((method) => method.authenticationMethod === 'oauth2');
    if (methods.length !== 1) {
      const error = new Error('OAuth credential method must be selected explicitly');
      error.code = 'OAUTH_METHOD_REQUIRED';
      error.statusCode = 400;
      throw error;
    }
    return methods[0].key;
  }

  async #executeCredentialOperation({
    credential,
    operation,
    capability,
    action,
    operationContext = {}
  }) {
    if (!credential) {
      return this.#frameworkFailure({
        providerName: null,
        operation,
        capability,
        error: new Error('credential is required')
      });
    }

    const methodContext = this.#credentialMethodContext({
      credential,
      operation,
      capability,
      operationContext
    });
    if (!methodContext.success) return methodContext;

    return this.#execute({
      providerName: credential.providerKey,
      operation,
      capability,
      action: (provider, definition) => {
        const profileIdentity = credential.providerProfile ?? credential.metadata?.custom?.providerProfile ?? null;
        if (definition.providerProfile && !profileIdentity) {
          const error = new Error('Credential provider profile is missing; explicit migration is required');
          error.code = 'CREDENTIAL_PROFILE_MISSING';
          error.statusCode = 409;
          error.classification = 'provider_contract_incompatible';
          return this.#frameworkFailure({
            providerName: credential.providerKey,
            operation,
            capability,
            context: { credentialId: credential.credentialId ?? null },
            error
          });
        }
        if (definition.providerProfile && !isProviderProfileMigrationVerified(credential)) {
          const error = new Error('Credential provider profile migration is incomplete or unverified');
          error.code = 'CREDENTIAL_PROFILE_MIGRATION_UNVERIFIED';
          error.statusCode = 409;
          error.classification = 'provider_contract_incompatible';
          return this.#frameworkFailure({
            providerName: credential.providerKey,
            operation,
            capability,
            context: { credentialId: credential.credentialId ?? null },
            error
          });
        }
        if (profileIdentity && definition.providerProfile
          && profileIdentity.digest !== definition.providerProfile.digest) {
          const error = new Error('Credential provider profile is stale or incompatible');
          error.code = 'CREDENTIAL_PROFILE_MISMATCH';
          error.statusCode = 409;
          error.classification = 'provider_contract_incompatible';
          return this.#frameworkFailure({
            providerName: credential.providerKey,
            operation,
            capability,
            context: { credentialId: credential.credentialId ?? null },
            error
          });
        }
        const adapter = methodContext.data?.binding?.adapterFor?.(capability);
        if (adapter) {
          return adapter({
            credential,
            provider,
            definition,
            providerProfile: definition.providerProfile,
            context: operationContext
          });
        }
        return action(provider, definition, operationContext);
      },
      context: {
        credentialId: credential.credentialId ?? null,
        ...(operationContext.auditContext ?? {})
      }
    });
  }

  #credentialMethodContext({ credential, operation, capability, operationContext = {} }) {
    let definition;
    try {
      definition = this.providerRegistry.get(credential.providerKey);
    } catch (error) {
      return this.#frameworkFailure({
        providerName: credential.providerKey,
        operation,
        capability,
        context: { credentialId: credential.credentialId ?? null },
        error
      });
    }

    const methods = definition.credentialMethods ?? [];
    const bindings = definition.providerMethodBindings ?? [];
    if (!credential.credentialMethodKey) {
      // Built-in providers always declare their method contract. This branch
      // exists solely for third-party pre-ADR definitions until they publish
      // one; persisted built-in records are migrated at application startup.
      if (methods.length === 0 && bindings.length === 0) return ProviderResult.success(null);
      return this.#frameworkFailure({
        providerName: credential.providerKey,
        operation,
        capability,
        context: { credentialId: credential.credentialId ?? null },
        error: Object.assign(
          new Error(`Credential '${credential.credentialId ?? 'unknown'}' requires an explicit credential method migration`),
          { classification: 'provider_contract_incompatible' }
        )
      });
    }

    const method = definition.getCredentialMethod?.(credential.credentialMethodKey);
    const binding = definition.getProviderMethodBinding?.(credential.credentialMethodKey);
    if (!method || !binding) {
      return this.#frameworkFailure({
        providerName: credential.providerKey,
        operation,
        capability,
        context: { credentialId: credential.credentialId ?? null },
        error: Object.assign(
          new Error(
            `Credential method '${credential.credentialMethodKey}' is not bound to provider '${credential.providerKey}'`
          ),
          { classification: 'provider_contract_incompatible' }
        )
      });
    }
    if (!method.supportsOperation(capability)) {
      return this.#frameworkFailure({
        providerName: credential.providerKey,
        operation,
        capability,
        context: { credentialId: credential.credentialId ?? null },
        error: Object.assign(
          new Error(
            `Credential method '${credential.credentialMethodKey}' does not support capability '${capability}'`
          ),
          { classification: 'provider_contract_incompatible' }
        )
      });
    }
    const grantedScopes = new Set(operationContext.scopes ?? credential.metadata?.scopes ?? credential.metadata?.toJSON?.().scopes ?? []);
    const missingScopes = (method.requiredScopes ?? []).filter((scope) => !grantedScopes.has(scope));
    if (missingScopes.length > 0) {
      return this.#frameworkFailure({
        providerName: credential.providerKey,
        operation,
        capability,
        context: { credentialId: credential.credentialId ?? null },
        error: Object.assign(
          new Error(`Credential is missing required provider scopes: ${missingScopes.join(', ')}`),
          { classification: 'scope_insufficient' }
        )
      });
    }
    return ProviderResult.success({ method, binding });
  }

  async #executeTokenOperation({
    tokenRecord,
    operation,
    capability,
    action
  }) {
    if (!tokenRecord) {
      return this.#frameworkFailure({
        providerName: null,
        operation,
        capability,
        error: new Error('credential record is required')
      });
    }

    return this.#execute({
      providerName: tokenRecord.provider,
      operation,
      capability,
      action,
      context: {
        providerId: tokenRecord.providerId ?? null
      }
    });
  }

  async #execute({
    providerName,
    operation,
    capability,
    action,
    context = {}
  }) {
    if (!providerName) {
      return this.#frameworkFailure({
        providerName: null,
        operation,
        capability,
        context,
        error: new Error('provider is required')
      });
    }

    const definition = this.#getProviderDefinition({
      providerName,
      operation,
      capability,
      context
    });

    if (!definition.success) {
      return definition;
    }

    const { provider } = definition.data;

    this.#logStart({ providerName, operation, context });

    try {
      const result = await action(provider, definition.data);

      const providerResult = this.#normalizeProviderResult({
        providerName,
        operation,
        capability,
        context,
        result
      });

      if (!providerResult.success) {
        this.#logFailure({ providerName, operation, capability, context, result: providerResult });
        return providerResult;
      }

      this.#logSuccess({ providerName, operation, context });
      return providerResult;
    } catch (error) {
      return this.#frameworkFailure({
        providerName,
        operation,
        capability,
        context,
        error
      });
    }
  }

  #getProviderDefinition({ providerName, operation, capability, context = {} }) {
    let definition;

    try {
      definition = this.providerRegistry.get(providerName);
    } catch (error) {
      return this.#frameworkFailure({
        providerName,
        operation,
        capability,
        context,
        error
      });
    }

    if (!definition?.provider) {
      return this.#frameworkFailure({
        providerName,
        operation,
        capability,
        context,
        error: new Error(`Unknown provider: ${providerName}`)
      });
    }

    if (!definition.capabilities?.has(capability)) {
      return this.#frameworkFailure({
        providerName,
        operation,
        capability,
        context,
        error: Object.assign(
          new Error(`Provider '${providerName}' does not support capability '${capability}'`),
          { code: 'PROVIDER_CAPABILITY_UNSUPPORTED', classification: 'provider_contract_incompatible' }
        )
      });
    }

    return ProviderResult.success(definition);
  }

  #normalizeProviderResult({
    providerName,
    operation,
    capability,
    context,
    result
  }) {
    if (result instanceof ProviderResult) {
      return result;
    }

    return this.#frameworkFailure({
      providerName,
      operation,
      capability,
      context,
      error: new Error(
        `Provider '${providerName}' operation '${operation}' violated provider contract: expected ProviderResult`
      )
    });
  }

  #frameworkFailure({
    providerName,
    operation,
    capability,
    context = {},
    error
  }) {
    const result = ProviderResult.failure(error);
    this.#logFailure({ providerName, operation, capability, context, result });
    return result;
  }

  #logStart({ providerName, operation, context }) {
    this.logger.info(
      `Provider operation '${operation}' via provider '${providerName}'`,
      context
    );
  }

  #logSuccess({ providerName, operation, context }) {
    this.logger.info(
      `Provider operation '${operation}' succeeded for '${providerName}'`,
      context
    );
  }

  #logFailure({ providerName, operation, capability, context, result }) {
    this.logger.error(
      `Provider operation '${operation}' failed for '${providerName ?? 'unknown'}'`,
      {
        capability,
        context,
        error: {
          name: result.error?.name ?? 'ProviderError',
          code: result.error?.code ?? 'PROVIDER_OPERATION_FAILED',
          statusCode: result.error?.statusCode ?? null,
          ...(result.error?.classification ? { classification: result.error.classification } : {})
        }
      }
    );
  }
}
