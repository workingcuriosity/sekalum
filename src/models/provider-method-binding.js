import { isProviderOperationCapability } from './provider-capability.js';
import { validateNamedIdentifier } from '../security/authorization-identifier.js';

/**
 * Provider-local availability and operation adapter for a CredentialMethod.
 */
export class ProviderMethodBinding {
  constructor({ methodKey, displayName = null, description = null, metadata = {}, operationAdapters = {} } = {}) {
    validateNamedIdentifier('methodKey', methodKey);
    if (!metadata || Array.isArray(metadata) || typeof metadata !== 'object') {
      throw new Error(`ProviderMethodBinding '${methodKey}': metadata must be an object`);
    }
    if (!operationAdapters || Array.isArray(operationAdapters) || typeof operationAdapters !== 'object') {
      throw new Error(`ProviderMethodBinding '${methodKey}': operationAdapters must be an object`);
    }

    const adapters = {};
    for (const [operation, adapter] of Object.entries(operationAdapters)) {
      if (!isProviderOperationCapability(operation)) {
        throw new Error(`ProviderMethodBinding '${methodKey}': unsupported adapter operation '${operation}'`);
      }
      if (typeof adapter !== 'function') {
        throw new Error(`ProviderMethodBinding '${methodKey}': adapter '${operation}' must be a function`);
      }
      adapters[operation] = adapter;
    }

    this.methodKey = methodKey;
    this.displayName = displayName;
    this.description = description;
    this.metadata = Object.freeze({ ...metadata });
    this.operationAdapters = Object.freeze(adapters);
    Object.freeze(this);
  }

  adapterFor(operation) {
    return this.operationAdapters[operation] ?? null;
  }

  validateAgainst(method) {
    for (const operation of Object.keys(this.operationAdapters)) {
      if (!method.supportsOperation(operation)) {
        throw new Error(
          `ProviderMethodBinding '${this.methodKey}': adapter '${operation}' is not declared by CredentialMethod '${method.key}'`
        );
      }
    }
  }

  toJSON() {
    return {
      methodKey: this.methodKey,
      displayName: this.displayName,
      description: this.description,
      metadata: { ...this.metadata },
      operationCapabilities: Object.keys(this.operationAdapters)
    };
  }

  static from(value) {
    return value instanceof ProviderMethodBinding ? value : new ProviderMethodBinding(value);
  }
}
