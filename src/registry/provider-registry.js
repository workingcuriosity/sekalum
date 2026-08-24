import { ProviderDefinition } from '../models/provider-definition.js';
import { ProviderRegistrationError } from '../errors/provider-registration-error.js';
import {
  ProviderCapability,
  isProviderOperationCapability
} from '../models/provider-capability.js';

export class ProviderRegistry {
  constructor({ logger }) {
    this.logger = logger;
    this.providers = new Map();
  }

  register(definition) {
    if (!(definition instanceof ProviderDefinition)) {
      throw new Error(
        'ProviderRegistry only accepts ProviderDefinition instances.'
      );
    }

    if (this.providers.has(definition.name)) {
      throw new Error(`Provider already registered: ${definition.name}`);
    }

    this.#validate(definition);

    this.providers.set(definition.name, definition);
    this.logger.info(`Provider registered: ${definition.name}`);
  }

  #validate(definition) {
    const caps = definition.capabilities;

    if (!caps) {
      return;
    }

    const unsupportedCapabilities = caps
      .toArray()
      .filter((capability) => !isProviderOperationCapability(capability));

    if (unsupportedCapabilities.length > 0) {
      throw new ProviderRegistrationError(
        `${definition.name}: provider capabilities must only contain public provider operations: ${unsupportedCapabilities.join(', ')}`
      );
    }

    if (
      caps.has(ProviderCapability.OAUTH) &&
      !definition.oauthService
    ) {
      throw new ProviderRegistrationError(
        `${definition.name}: OAUTH capability requires an oauthService`
      );
    }

    if (
      caps.has(ProviderCapability.REFRESH) &&
      !definition.oauthService
    ) {
      throw new ProviderRegistrationError(
        `${definition.name}: REFRESH capability requires an oauthService`
      );
    }

    if (!definition.apiClient) {
      throw new ProviderRegistrationError(
        `${definition.name}: apiClient is required`
      );
    }
  }

  get(name) {
    if (!this.providers.has(name)) {
      throw new Error(`Provider not registered: ${name}`);
    }

    return this.providers.get(name);
  }

  getCredentialMethod(providerName, methodKey) {
    const method = this.get(providerName).getCredentialMethod(methodKey);
    if (!method) {
      throw new Error(`Credential method not registered for provider '${providerName}': ${methodKey}`);
    }
    return method;
  }

  getProviderMethodBinding(providerName, methodKey) {
    const binding = this.get(providerName).getProviderMethodBinding(methodKey);
    if (!binding) {
      throw new Error(`Credential method binding not registered for provider '${providerName}': ${methodKey}`);
    }
    return binding;
  }

  has(name) {
    return this.providers.has(name);
  }

  unregister(name) {
    const provider = this.providers.get(name);
    if (!provider) return null;
    this.providers.delete(name);
    this.logger.info(`Provider unregistered: ${name}`);
    return provider;
  }

  list() {
    return Array.from(this.providers.keys());
  }

  count() {
    return this.providers.size;
  }
}
