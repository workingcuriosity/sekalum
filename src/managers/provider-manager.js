// Copyright (C) 2026 Working Curiosity
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { ProviderCapability } from '../models/provider-capability.js';
import { ProviderResult } from '../models/provider-result.js';
import { OAuthResult } from '../models/oauth-result.js';

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

  async startOAuth(providerName, options = {}) {
    return this.#execute({
      providerName,
      operation: 'startOAuth',
      capability: ProviderCapability.OAUTH,
      action: async (provider, definition) => {
        const configurationRecord = await this.#prepareProviderConfiguration({
          providerName,
          definition,
          options
        });
        const configuredOptions = configurationRecord
          ? {
              ...options,
              providerConfiguration: configurationRecord.configuration,
              providerConfigurationId: configurationRecord.configurationId
            }
          : options;
        let securityContext = null;
        try {
          securityContext = this.#createOAuthSecurityContext({
            providerName,
            definition,
            options: configuredOptions
          });
          const result = await provider.startOAuth({
            ...configuredOptions,
            ...this.#authorizationOptionsFromSecurityContext(securityContext),
            oauthSecurityContext: securityContext
          });
          if (!configurationRecord) return result;
          if (!result?.success) {
            this.oauthSecurityService?.discardAuthorizationContext?.(securityContext?.state);
            await this.#removeProviderConfiguration(configurationRecord.configurationId, providerName);
            return result;
          }
          return ProviderResult.success({
            ...result.data,
            providerConfigurationId: configurationRecord.configurationId
          });
        } catch (error) {
          this.oauthSecurityService?.discardAuthorizationContext?.(securityContext?.state);
          await this.#removeProviderConfiguration(configurationRecord?.configurationId, providerName);
          throw error;
        }
      }
    });
  }

  async handleOAuthCallback(providerName, callbackData = {}) {
    return this.#execute({
      providerName,
      operation: 'handleOAuthCallback',
      capability: ProviderCapability.OAUTH,
      action: async (provider) => {
        let securityContext;
        try {
          securityContext = this.#consumeOAuthSecurityContext({
            providerName,
            callbackData
          });
        } catch (error) {
          await this.#removeProviderConfiguration(
            error.providerConfigurationId,
            error.providerKey ?? providerName
          );
          throw error;
        }

        try {
          const result = await provider.handleOAuthCallback({
            ...callbackData,
            ...this.#callbackOptionsFromSecurityContext(securityContext),
            oauthSecurityContext: securityContext
          });
          if (!result?.success) {
            await this.#removeProviderConfiguration(securityContext?.providerConfigurationId, providerName);
            return result;
          }
          return this.#attachProviderConfigurationReference(result, securityContext);
        } catch (error) {
          await this.#removeProviderConfiguration(securityContext?.providerConfigurationId, providerName);
          throw error;
        }
      }
    });
  }

  async cancelOAuth(providerName, state) {
    const securityContext = this.#consumeOAuthSecurityContext({
      providerName,
      callbackData: { state }
    });
    return this.#removeProviderConfiguration(securityContext?.providerConfigurationId, providerName);
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
    oauthSecurity: definition.oauthSecurityRequirements?.toJSON?.() ?? null,
    oauthTechnical: definition.oauthService
      ? {
          authorizationEndpoint: definition.oauthService.authorizationUrl ?? null
        }
      : null
  };

  return summary;
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
        });
        const configuredCredential = { ...credential, providerConfiguration };
        if (typeof provider.refreshCredential === 'function') {
          return provider.refreshCredential(configuredCredential);
        }
        return provider.refreshToken(configuredCredential);
      }
    });
  }

  async validateCredential(credential) {
    return this.#executeCredentialOperation({
      credential,
      operation: 'validateCredential',
      capability: ProviderCapability.VALIDATION,
      action: (provider) => {
        if (typeof provider.validateCredential === 'function') {
          return provider.validateCredential(credential);
        }
        return provider.validateToken(credential);
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

  async healthCheckCredential(credential) {
    return this.#executeCredentialOperation({
      credential,
      operation: 'healthCheckCredential',
      capability: ProviderCapability.HEALTH_CHECK,
      action: (provider) => provider.healthCheck(credential)
    });
  }

  async refreshToken(tokenRecord) {
    return this.#executeTokenOperation({
      tokenRecord,
      operation: 'refreshToken',
      capability: ProviderCapability.REFRESH,
      action: async (provider) => provider.refreshToken({
        ...tokenRecord,
        providerConfiguration: await this.#configurationForCredential(tokenRecord)
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
      providerConfigurationId: options.providerConfigurationId ?? null
    });
  }

  #consumeOAuthSecurityContext({ providerName, callbackData }) {
    if (!this.oauthSecurityService || !callbackData?.state) {
      return null;
    }

    return this.oauthSecurityService.consumeCallbackContext({
      provider: providerName,
      state: callbackData.state
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
      providerConfiguration: securityContext.providerConfiguration ?? null,
      providerConfigurationId: securityContext.providerConfigurationId ?? null
    };
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
      configurationId: options.providerConfigurationId ?? null
    });
  }

  async #configurationForCredential(credential) {
    const configurationId = credential?.metadata?.providerConfigurationId
      ?? credential?.metadata?.custom?.providerConfigurationId
      ?? null;
    if (!configurationId || !this.providerConfigurationService) return null;
    return (await this.providerConfigurationService.load(configurationId, credential.provider)).configuration;
  }

  async #removeProviderConfiguration(configurationId, providerName) {
    if (!configurationId || !this.providerConfigurationService) return false;
    return this.providerConfigurationService.remove(configurationId, providerName);
  }

  #attachProviderConfigurationReference(result, securityContext) {
    const configurationId = securityContext?.providerConfigurationId;
    if (!configurationId || !result?.success || !(result.data instanceof OAuthResult)) return result;
    const data = result.data;
    return ProviderResult.success(new OAuthResult({
      providerId: data.providerId,
      provider: data.provider,
      accountId: data.accountId,
      accountName: data.accountName,
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      expiresAt: data.expiresAt,
      scopes: data.scopes,
      metadata: { ...data.metadata, providerConfigurationId: configurationId }
    }));
  }

  async #executeCredentialOperation({
    credential,
    operation,
    capability,
    action
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
      capability
    });
    if (!methodContext.success) return methodContext;

    return this.#execute({
      providerName: credential.providerKey,
      operation,
      capability,
      action: (provider, definition) => {
        const adapter = methodContext.data?.binding?.adapterFor?.(capability);
        if (adapter) {
          return adapter({ credential, provider, definition });
        }
        return action(provider, definition);
      },
      context: {
        credentialId: credential.credentialId ?? null
      }
    });
  }

  #credentialMethodContext({ credential, operation, capability }) {
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
        error: new Error(`Credential '${credential.credentialId ?? 'unknown'}' requires an explicit credential method migration`)
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
        error: new Error(
          `Credential method '${credential.credentialMethodKey}' is not bound to provider '${credential.providerKey}'`
        )
      });
    }
    if (!method.supportsOperation(capability)) {
      return this.#frameworkFailure({
        providerName: credential.providerKey,
        operation,
        capability,
        context: { credentialId: credential.credentialId ?? null },
        error: new Error(
          `Credential method '${credential.credentialMethodKey}' does not support capability '${capability}'`
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
        error: new Error(`Provider '${providerName}' does not support capability '${capability}'`)
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
          statusCode: result.error?.statusCode ?? null
        }
      }
    );
  }
}
