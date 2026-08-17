// Copyright (C) 2026 Working Curiosity
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { ProviderCapabilities } from './provider-capabilities.js';
import { OAuthSecurityRequirements } from './oauth-security-requirements.js';
import { CredentialFieldDefinition } from './credential-field-definition.js';
import { CredentialMethod } from './credential-method.js';
import { ProviderMethodBinding } from './provider-method-binding.js';

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
    oauthSecurityRequirements = null
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
  }

  getCredentialMethod(methodKey) {
    return this.credentialMethods.find((method) => method.key === methodKey) ?? null;
  }

  getProviderMethodBinding(methodKey) {
    return this.providerMethodBindings.find((binding) => binding.methodKey === methodKey) ?? null;
  }
}
