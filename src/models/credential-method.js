import { CredentialFieldDefinition } from './credential-field-definition.js';
import { isProviderOperationCapability } from './provider-capability.js';

/**
 * Reusable, provider-neutral description of a credential procedure.
 * Provider-specific presentation and operation adapters belong to a binding.
 */
export class CredentialMethod {
  constructor({ key, displayName = null, description = null, authenticationMethod = null, credentialFields = [], operationCapabilities = [], requiredScopes = [] } = {}) {
    if (typeof key !== 'string' || key.trim() === '') {
      throw new Error("CredentialMethod: 'key' is required");
    }
    if (!Array.isArray(credentialFields)) {
      throw new Error(`CredentialMethod '${key}': credentialFields must be an array`);
    }
    if (!Array.isArray(operationCapabilities)) {
      throw new Error(`CredentialMethod '${key}': operationCapabilities must be an array`);
    }
    if (!Array.isArray(requiredScopes) || requiredScopes.some((scope) => typeof scope !== 'string' || scope.trim() === '')) {
      throw new Error(`CredentialMethod '${key}': requiredScopes must contain non-empty strings`);
    }

    const fields = credentialFields
      .map((field) => CredentialFieldDefinition.from(field))
      .sort((left, right) => left.displayOrder - right.displayOrder);
    const fieldKeys = fields.map((field) => field.key);
    if (new Set(fieldKeys).size !== fieldKeys.length) {
      throw new Error(`CredentialMethod '${key}': credentialFields contain duplicate keys`);
    }

    const capabilities = [...new Set(operationCapabilities)];
    const invalid = capabilities.filter((capability) => !isProviderOperationCapability(capability));
    if (invalid.length > 0) {
      throw new Error(`CredentialMethod '${key}': unsupported operation capabilities: ${invalid.join(', ')}`);
    }

    this.key = key.trim();
    this.displayName = displayName ?? this.key;
    this.description = description;
    this.authenticationMethod = authenticationMethod;
    this.credentialFields = Object.freeze(fields);
    this.operationCapabilities = Object.freeze(capabilities);
    this.requiredScopes = Object.freeze([...new Set(requiredScopes.map((scope) => scope.trim()))]);
    Object.freeze(this);
  }

  supportsOperation(capability) {
    return this.operationCapabilities.includes(capability);
  }

  toJSON() {
    return {
      key: this.key,
      displayName: this.displayName,
      description: this.description,
      authenticationMethod: this.authenticationMethod,
      credentialFields: this.credentialFields.map((field) => field.toJSON()),
      operationCapabilities: [...this.operationCapabilities],
      requiredScopes: [...this.requiredScopes]
    };
  }

  static from(value) {
    return value instanceof CredentialMethod ? value : new CredentialMethod(value);
  }
}
