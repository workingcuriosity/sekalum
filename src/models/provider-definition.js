// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { ProviderCapabilities } from './provider-capabilities.js';
import { OAuthSecurityRequirements } from './oauth-security-requirements.js';
import { CredentialFieldDefinition } from './credential-field-definition.js';
import { CredentialMethod } from './credential-method.js';
import { ProviderMethodBinding } from './provider-method-binding.js';
import { RuntimeDerivationContract } from './runtime-derivation-contract.js';
import crypto from 'node:crypto';

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function profileDigest(value) {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
}

/** Immutable, non-secret identity of the provider contract used by a credential operation. */
export class ProviderProfile {
  constructor({ providerKey, version = '1.0.0', providerKind = 'repository-provider', contract = {} } = {}) {
    if (typeof providerKey !== 'string' || providerKey.trim() === '') throw new Error("ProviderProfile: 'providerKey' is required");
    if (typeof version !== 'string' || version.trim() === '') throw new Error(`ProviderProfile '${providerKey}': version is required`);
    if (!contract || typeof contract !== 'object' || Array.isArray(contract)) throw new Error(`ProviderProfile '${providerKey}': contract must be an object`);
    this.providerKey = providerKey.trim();
    this.version = version.trim();
    this.providerKind = providerKind;
    this.contract = Object.freeze(canonicalize(contract));
    this.digest = profileDigest({ providerKey: this.providerKey, version: this.version, providerKind: this.providerKind, contract: this.contract });
    Object.freeze(this);
  }
  identity() {
    return Object.freeze({ providerKey: this.providerKey, version: this.version, providerKind: this.providerKind, digest: this.digest });
  }
  toJSON() { return { ...this.identity(), contract: this.contract }; }
  matches(identity) {
    return Boolean(identity) && identity.providerKey === this.providerKey && identity.version === this.version && identity.digest === this.digest;
  }
  static from(value) { return value instanceof ProviderProfile ? value : new ProviderProfile(value); }
}

export function providerProfileForDefinition({ providerKey, version = '1.0.0', providerKind = 'repository-provider', credentialFields = [], credentialMethods = [], providerMethodBindings = [], metadata = {}, oauthService = null, apiClient = null, providerProfile = null, runtimeDerivation = null } = {}) {
  if (providerProfile) return ProviderProfile.from({ providerKey, ...providerProfile });
  const runtimeDerivationInput = runtimeDerivation ?? metadata.runtimeDerivation ?? null;
  return new ProviderProfile({
    providerKey,
    version,
    providerKind,
    contract: {
      credentialFields: credentialFields.map((field) => field.toJSON?.() ?? field).filter((field) => !field.secret && field.defaultValue === null),
      credentialMethods: credentialMethods.map((method) => ({
        key: method.key,
        authenticationMethod: method.authenticationMethod,
        operationCapabilities: [...method.operationCapabilities],
        requiredScopes: [...method.requiredScopes],
        credentialFields: method.credentialFields.map((field) => field.toJSON()).map(({ defaultValue, ...field }) => field)
      })),
      providerMethodBindings: providerMethodBindings.map((binding) => binding.toJSON()),
      routing: metadata.providerRouting ?? metadata.routing ?? {
        api: metadata.api ?? null,
        validationEndpoint: metadata.validationEndpoint ?? null,
        protocol: metadata.protocol ?? null,
        defaultPort: metadata.defaultPort ?? null,
        ...Object.fromEntries(['baseUrl', 'apiVersion', 'tokenUrl', 'userInfoUrl', 'authorizationUrl', 'timeoutMs']
          .filter((key) => apiClient?.[key] !== undefined || oauthService?.[key] !== undefined)
          .map((key) => [key, apiClient?.[key] ?? oauthService?.[key]]))
      },
      oauth: metadata.oauthContract ?? (oauthService ? {
        authorizationEndpoint: oauthService.authorizationUrl ?? null,
        authorizationParameters: metadata.oauthAuthorizationParameters ?? {},
        tokenEndpointAuthMethod: metadata.oauthTokenEndpointAuthMethod ?? 'request-body',
        scopes: metadata.defaultScopes ?? []
      } : null),
      ...(runtimeDerivationInput !== null
        ? { runtimeDerivation: RuntimeDerivationContract.from(runtimeDerivationInput).toJSON() }
        : {})
    }
  });
}

export class ProviderDefinition {
  constructor({
    name,
    provider,
    oauthService = null,
    apiClient = null,
    capabilities = null,
    displayName = null,
    description = null,
    metadata = {},
    credentialFields = null,
    credentialMethods = [],
    providerMethodBindings = [],
    oauthSecurityRequirements = null,
    providerProfile = null,
    runtimeDerivation = null
  }) {
    if (!name) {
      throw new Error("ProviderDefinition: 'name' is required");
    }

    if (!provider) {
      throw new Error(`ProviderDefinition '${name}': provider is required`);
    }

    if (
      capabilities !== null &&
      !(capabilities instanceof ProviderCapabilities)
    ) {
      throw new Error(
        `ProviderDefinition '${name}': capabilities must be a ProviderCapabilities instance`
      );
    }

    const fieldInput = credentialFields ?? metadata.credentialFields ?? [];
    if (!Array.isArray(fieldInput)) {
      throw new Error(`ProviderDefinition '${name}': credentialFields must be an array`);
    }

    const normalizedFields = fieldInput
      .map((field) => CredentialFieldDefinition.from(field))
      .sort((left, right) => left.displayOrder - right.displayOrder);
    const fieldKeys = normalizedFields.map((field) => field.key);

    if (new Set(fieldKeys).size !== fieldKeys.length) {
      throw new Error(`ProviderDefinition '${name}': credentialFields contain duplicate keys`);
    }

    if (!Array.isArray(credentialMethods)) {
      throw new Error(`ProviderDefinition '${name}': credentialMethods must be an array`);
    }
    if (!Array.isArray(providerMethodBindings)) {
      throw new Error(`ProviderDefinition '${name}': providerMethodBindings must be an array`);
    }

    const methods = credentialMethods.map((method) => CredentialMethod.from(method));
    const methodKeys = methods.map((method) => method.key);
    if (new Set(methodKeys).size !== methodKeys.length) {
      throw new Error(`ProviderDefinition '${name}': credentialMethods contain duplicate keys`);
    }
    const methodsByKey = new Map(methods.map((method) => [method.key, method]));
    const bindings = providerMethodBindings.map((binding) => ProviderMethodBinding.from(binding));
    const bindingKeys = bindings.map((binding) => binding.methodKey);
    if (new Set(bindingKeys).size !== bindingKeys.length) {
      throw new Error(`ProviderDefinition '${name}': providerMethodBindings contain duplicate method keys`);
    }
    for (const binding of bindings) {
      const method = methodsByKey.get(binding.methodKey);
      if (!method) {
        throw new Error(
          `ProviderDefinition '${name}': binding references unknown credential method '${binding.methodKey}'`
        );
      }
      binding.validateAgainst(method);
    }

    this.name = name;
    this.provider = provider;
    this.oauthService = oauthService;
    this.apiClient = apiClient;
    this.capabilities = capabilities;
    this.displayName = displayName ?? metadata.displayName ?? name;
    this.description = description ?? metadata.description ?? null;
    this.credentialFields = Object.freeze(normalizedFields);
    this.credentialMethods = Object.freeze(methods);
    this.providerMethodBindings = Object.freeze(bindings);
    this.metadata = Object.freeze({ ...metadata });
    this.oauthSecurityRequirements = OAuthSecurityRequirements.from(
      oauthSecurityRequirements
        ?? metadata.oauthSecurityRequirements
      ?? {}
    );
    this.providerProfile = providerProfileForDefinition({
      providerKey: name,
      version: metadata.providerProfileVersion ?? '1.0.0',
      providerKind: metadata.providerKind ?? (metadata.customProvider ? 'declarative-custom-provider' : 'repository-provider'),
      credentialFields: normalizedFields,
      credentialMethods: methods,
      providerMethodBindings: bindings,
      metadata,
      oauthService,
      apiClient,
      providerProfile,
      runtimeDerivation
    });
    this.runtimeDerivation = RuntimeDerivationContract.from(runtimeDerivation ?? metadata.runtimeDerivation ?? {});
  }

  getCredentialMethod(methodKey) {
    return this.credentialMethods.find((method) => method.key === methodKey) ?? null;
  }

  getProviderMethodBinding(methodKey) {
    return this.providerMethodBindings.find((binding) => binding.methodKey === methodKey) ?? null;
  }
}
