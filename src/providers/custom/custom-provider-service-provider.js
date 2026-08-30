import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';
import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { CredentialFieldDefinition } from '../../models/credential-field-definition.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';
import { DeclarativeCustomProvider } from './declarative-custom-provider.js';

const ALLOWED_AUTH_TYPES = new Set(['api-key', 'username-password', 'connection', 'manual']);
const ALLOWED_KEYS = new Set(['name', 'displayName', 'description', 'authType', 'credentialType', 'credentialFields']);
const PROVIDER_NAME_PATTERN = /^[a-z][a-z0-9-]{1,62}$/;

export class CustomProviderServiceProvider extends ServiceProvider {
  register(container) {
    const definitions = parseCustomProviderDefinitions(
      container.resolve(TOKENS.CONFIG).get('CUSTOM_PROVIDER_DEFINITIONS', '')
    );
    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    for (const definition of definitions) {
      registry.register(new ProviderDefinition({
        name: definition.name,
        provider: new DeclarativeCustomProvider({ name: definition.name }),
        apiClient: Object.freeze({ kind: 'declarative-custom-provider' }),
        capabilities: new ProviderCapabilities([]),
        displayName: definition.displayName,
        description: definition.description,
        credentialFields: definition.credentialFields,
        credentialMethods: [new CredentialMethod({
          key: definition.authType,
          displayName: definition.authType,
          authenticationMethod: definition.authType,
          credentialFields: definition.credentialFields,
          operationCapabilities: []
        })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: definition.authType })],
        metadata: {
          authType: definition.authType,
          credentialType: definition.credentialType,
          customProvider: true,
          runtimeOperations: []
        }
      }));
    }
  }
}

export function parseCustomProviderDefinitions(value) {
  if (value === undefined || value === null || value === '') return [];

  let parsed = value;
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value);
    } catch {
      throw new Error('CUSTOM_PROVIDER_DEFINITIONS must be valid JSON');
    }
  }

  if (!Array.isArray(parsed)) {
    throw new Error('CUSTOM_PROVIDER_DEFINITIONS must be a JSON array');
  }

  const names = new Set();
  return parsed.map((definition, index) => {
    if (!definition || typeof definition !== 'object' || Array.isArray(definition)) {
      throw new Error(`Custom provider at index ${index} must be an object`);
    }
    for (const key of Object.keys(definition)) {
      if (!ALLOWED_KEYS.has(key)) {
        throw new Error(`Custom provider '${definition.name ?? index}' contains unsupported property '${key}'`);
      }
    }
    if (typeof definition.name !== 'string' || !PROVIDER_NAME_PATTERN.test(definition.name)) {
      throw new Error(`Custom provider at index ${index} requires a lowercase kebab-case name`);
    }
    if (names.has(definition.name)) {
      throw new Error(`CUSTOM_PROVIDER_DEFINITIONS contains duplicate provider '${definition.name}'`);
    }
    names.add(definition.name);
    if (typeof definition.displayName !== 'string' || definition.displayName.trim() === '') {
      throw new Error(`Custom provider '${definition.name}' requires displayName`);
    }
    if (definition.description !== undefined && (typeof definition.description !== 'string' || definition.description.trim() === '')) {
      throw new Error(`Custom provider '${definition.name}' description must be a non-empty string when provided`);
    }
    if (!ALLOWED_AUTH_TYPES.has(definition.authType)) {
      throw new Error(`Custom provider '${definition.name}' has unsupported authType '${definition.authType}'`);
    }
    if (!Array.isArray(definition.credentialFields) || definition.credentialFields.length === 0) {
      throw new Error(`Custom provider '${definition.name}' requires at least one credential field`);
    }

    const credentialFields = definition.credentialFields.map((field) => CredentialFieldDefinition.from(field));
    const fieldKeys = credentialFields.map((field) => field.key);
    if (new Set(fieldKeys).size !== fieldKeys.length) {
      throw new Error(`Custom provider '${definition.name}' contains duplicate credential field keys`);
    }

    return Object.freeze({
      name: definition.name,
      displayName: definition.displayName.trim(),
      description: definition.description?.trim() ?? null,
      authType: definition.authType,
      credentialType: definition.credentialType ?? definition.authType,
      credentialFields
    });
  });
}
