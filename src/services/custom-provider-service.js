import { ProviderDefinition } from '../models/provider-definition.js';
import { ProviderCapabilities } from '../models/provider-capabilities.js';
import { CredentialMethod } from '../models/credential-method.js';
import { ProviderMethodBinding } from '../models/provider-method-binding.js';
import { DeclarativeCustomProvider } from '../providers/custom/declarative-custom-provider.js';

const PROVIDER_KEY = /^[a-z][a-z0-9-]{1,62}$/;
const ROOT_KEYS = new Set(['key', 'displayName', 'category', 'description', 'enabled', 'credentialMethods', 'providerMethodBindings', 'credentialFields']);
const FORBIDDEN_KEYS = new Set(['providerConfigurationFields', 'oauth', 'oauthSecurity', 'oauthTechnical', 'runtimeOperations', 'provider', 'apiClient', 'hooks', 'scripts', 'code', 'secrets', 'secretValues']);
const METHOD_KEYS = new Set(['key', 'displayName', 'description', 'credentialFields']);
const BINDING_KEYS = new Set(['methodKey', 'displayName', 'description']);
const FIELD_KEYS = new Set(['key', 'label', 'type', 'required', 'secret', 'description', 'section', 'displayOrder']);

/** Creates data-only providers. They intentionally have no executable operations or OAuth support. */
export class CustomProviderService {
  constructor({ store, providerRegistry, auditLogService = null }) {
    this.store = store;
    this.providerRegistry = providerRegistry;
    this.auditLogService = auditLogService;
    this.transitionLocks = new Map();
  }

  async hydrate() {
    for (const storedDefinition of await this.store.list()) {
      const definition = this.#storedDefinition(storedDefinition);
      this.#assertNoBuiltInConflict(definition.key);
      if (definition.enabled) this.#register(definition);
    }
  }

  async create(input) {
    const definition = this.#normalize(input);
    if (this.providerRegistry.has(definition.key)) {
      const error = new Error(`Provider '${definition.key}' already exists`);
      error.code = 'PROVIDER_ALREADY_EXISTS';
      error.statusCode = 409;
      throw error;
    }
    await this.store.save(definition);
    try {
      this.#register(definition);
    } catch (error) {
      // A persisted custom provider must always be available after restart.
      // Revert the durable write if registration fails so the two states stay aligned.
      try {
        await this.store.delete(definition.key);
      } catch (rollbackError) {
        error.rollbackError = rollbackError;
      }
      throw error;
    }
    return definition;
  }

  #normalize(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw this.#invalid('Provider definition must be an object');
    for (const key of Object.keys(input)) {
      if (FORBIDDEN_KEYS.has(key) || !ROOT_KEYS.has(key)) throw this.#invalid(`Provider definition contains unsupported property '${key}'`);
    }
    if (typeof input.key !== 'string' || !PROVIDER_KEY.test(input.key)) throw this.#invalid('Provider ID must be lowercase kebab-case');
    if (typeof input.displayName !== 'string' || input.displayName.trim() === '') throw this.#invalid('Provider display name is required');
    if (typeof input.category !== 'string' || input.category.trim() === '') throw this.#invalid('Provider category is required');
    if (input.description !== undefined && (typeof input.description !== 'string' || input.description.trim() === '')) throw this.#invalid('Provider description must be a non-empty string when supplied');
    if (!Array.isArray(input.credentialMethods) || input.credentialMethods.length === 0) throw this.#invalid('At least one credential method is required');
    if (!Array.isArray(input.providerMethodBindings) || input.providerMethodBindings.length === 0) throw this.#invalid('Each credential method requires a binding');
    if (!Array.isArray(input.credentialFields) || input.credentialFields.length === 0) throw this.#invalid('At least one credential field is required');

    try {
      input.credentialFields.forEach((field) => {
        this.#assertObjectKeys(field, FIELD_KEYS, 'Credential field');
        if (field.section !== undefined && field.section !== 'accountCredentials') {
          throw this.#invalid("Credential field section must be 'accountCredentials'");
        }
      });
      const methods = input.credentialMethods.map((method) => {
        this.#assertObjectKeys(method, METHOD_KEYS, 'Credential method');
        if (!Array.isArray(method.credentialFields) || method.credentialFields.length === 0) {
          throw this.#invalid('Credential method requires at least one credential field');
        }
        method.credentialFields.forEach((field) => {
          this.#assertObjectKeys(field, FIELD_KEYS, 'Credential field');
          if (field.section !== undefined && field.section !== 'accountCredentials') {
            throw this.#invalid("Credential field section must be 'accountCredentials'");
          }
        });
        return new CredentialMethod({
        key: method.key,
        displayName: method.displayName,
        description: method.description ?? null,
        credentialFields: method.credentialFields.map((field) => ({ ...field, section: 'accountCredentials' })),
        operationCapabilities: []
        });
      });
      const bindings = input.providerMethodBindings.map((binding) => {
        this.#assertObjectKeys(binding, BINDING_KEYS, 'Provider method binding');
        return new ProviderMethodBinding({
        methodKey: binding.methodKey,
        displayName: binding.displayName ?? null,
        description: binding.description ?? null,
        metadata: {},
        operationAdapters: {}
        });
      });
      const methodKeys = methods.map((method) => method.key).sort();
      const bindingKeys = bindings.map((binding) => binding.methodKey).sort();
      if (methodKeys.length !== bindingKeys.length || methodKeys.some((key, index) => key !== bindingKeys[index])) {
        throw this.#invalid('Provider method bindings must match credential methods exactly');
      }
      const fields = methods.flatMap((method) => method.credentialFields.map((field) => field.toJSON()));
      // Root fields are a UI convenience. Require them to match the method fields,
      // preventing a definition from declaring a hidden or unbound credential field.
      const declared = input.credentialFields.map((field) => field.key).sort();
      const derived = fields.map((field) => field.key).sort();
      if (declared.length !== derived.length || declared.some((key, index) => key !== derived[index])) {
        throw this.#invalid('Credential fields must match the credential method fields');
      }
      new ProviderDefinition({
        name: input.key,
        provider: new DeclarativeCustomProvider({ name: input.key }),
        apiClient: Object.freeze({ kind: 'declarative-custom-provider' }),
        capabilities: new ProviderCapabilities([]),
        credentialFields: fields,
        credentialMethods: methods,
        providerMethodBindings: bindings
      });
      return {
        key: input.key,
        displayName: input.displayName.trim(),
        category: input.category.trim(),
        description: input.description?.trim() ?? null,
        enabled: input.enabled ?? true,
        credentialFields: fields,
        credentialMethods: methods.map((method) => method.toJSON()),
        providerMethodBindings: bindings.map((binding) => binding.toJSON())
      };
    } catch (error) {
      if (error.code === 'PROVIDER_DEFINITION_INVALID') throw error;
      throw this.#invalid(error.message);
    }
  }

  async listManagement() {
    const definitions = await this.store.list();
    return definitions
      .map((storedDefinition) => this.#storedDefinition(storedDefinition))
      .map((definition) => ({
        providerKey: definition.key,
        key: definition.key,
        customProvider: true,
        enabled: definition.enabled,
        displayName: definition.displayName,
        description: definition.description ?? null,
        category: definition.category ?? null
      }))
      .sort((left, right) => left.providerKey.localeCompare(right.providerKey));
  }

  async disable(key, options = {}) {
    return this.#withTransitionLock(key, () => this.#disable(key, options));
  }

  async enable(key, options = {}) {
    return this.#withTransitionLock(key, () => this.#enable(key, options));
  }

  async #disable(key, options) {
    const definition = await this.#loadCustomDefinition(key);
    if (!definition.enabled) return this.#lifecycleResult(definition);
    if (!this.providerRegistry.has(key)) {
      throw this.#consistencyError(`Enabled custom provider '${key}' is missing from the runtime registry`);
    }

    await this.store.update(key, (current) => ({ ...current, enabled: false }));

    try {
      const removed = this.providerRegistry.unregister(key);
      if (!removed || this.providerRegistry.has(key)) {
        throw this.#consistencyError(`Provider '${key}' could not be removed from the runtime registry`);
      }
      await this.#auditLifecycle('disable', key, options.actorUserId, 'success');
      return this.#lifecycleResult({ ...definition, enabled: false });
    } catch (error) {
      await this.#compensateEnable(definition, key, error);
      await this.#tryAuditLifecycle('disable', key, options.actorUserId, 'failure', error);
      throw error;
    }
  }

  async #enable(key, options) {
    const definition = await this.#loadCustomDefinition(key);
    if (definition.enabled) return this.#lifecycleResult(definition);
    this.#assertNoBuiltInConflict(key);
    this.#register(definition);

    try {
      await this.store.update(key, (current) => ({ ...current, enabled: true }));
      if (!this.providerRegistry.has(key)) {
        throw this.#consistencyError(`Enabled custom provider '${key}' is missing from the runtime registry`);
      }
      await this.#auditLifecycle('enable', key, options.actorUserId, 'success');
      return this.#lifecycleResult({ ...definition, enabled: true });
    } catch (error) {
      await this.#compensateDisable(definition, key, error);
      await this.#tryAuditLifecycle('enable', key, options.actorUserId, 'failure', error);
      throw error;
    }
  }

  async #loadCustomDefinition(key) {
    const stored = await this.store.get(key);
    if (!stored) {
      if (this.providerRegistry.has(key)) {
        const error = new Error(`Built-in provider '${key}' cannot be changed through the custom-provider lifecycle`);
        error.code = 'BUILTIN_PROVIDER_IMMUTABLE';
        error.statusCode = 400;
        throw error;
      }
      const error = new Error(`Provider '${key}' not found`);
      error.code = 'NOT_FOUND';
      error.statusCode = 404;
      throw error;
    }
    const definition = this.#storedDefinition(stored);
    this.#assertNoBuiltInConflict(key);
    return definition;
  }

  #storedDefinition(definition) {
    if (!definition || typeof definition !== 'object' || Array.isArray(definition)) {
      throw this.#invalid('Persisted custom provider definition must be an object');
    }
    if (definition.enabled !== undefined && typeof definition.enabled !== 'boolean') {
      throw this.#invalid(`Persisted custom provider '${definition.key ?? 'unknown'}' has invalid enabled state`);
    }
    return { ...structuredClone(definition), enabled: definition.enabled ?? true };
  }

  #assertNoBuiltInConflict(key) {
    if (!this.providerRegistry.has(key)) return;
    const registered = this.providerRegistry.get(key);
    if (registered.metadata?.customProvider !== true) {
      const error = new Error(`Custom provider '${key}' conflicts with a built-in provider`);
      error.code = 'BUILTIN_PROVIDER_IMMUTABLE';
      error.statusCode = 400;
      throw error;
    }
  }

  #withTransitionLock(key, action) {
    const previous = this.transitionLocks.get(key) ?? Promise.resolve();
    const current = previous.catch(() => {}).then(action);
    const settled = current.then(() => undefined, () => undefined);
    this.transitionLocks.set(key, settled);
    settled.then(() => {
      if (this.transitionLocks.get(key) === settled) this.transitionLocks.delete(key);
    });
    return current;
  }

  async #compensateEnable(definition, key, originalError) {
    try {
      await this.store.update(key, (current) => ({ ...current, enabled: true }));
      if (!this.providerRegistry.has(key)) this.#register(definition);
      if (!this.providerRegistry.has(key)) throw new Error('Provider registry compensation did not restore the projection');
    } catch (rollbackError) {
      throw this.#consistencyError(`Disable transition for '${key}' failed and compensation failed`, originalError, rollbackError);
    }
  }

  async #compensateDisable(definition, key, originalError) {
    try {
      if (this.providerRegistry.has(key)) this.providerRegistry.unregister(key);
      await this.store.update(key, (current) => ({ ...current, enabled: false }));
      const stored = this.#storedDefinition(await this.store.get(key));
      if (stored.enabled || this.providerRegistry.has(key)) throw new Error('Provider lifecycle compensation did not restore the disabled state');
    } catch (rollbackError) {
      throw this.#consistencyError(`Enable transition for '${key}' failed and compensation failed`, originalError, rollbackError);
    }
  }

  async #auditLifecycle(action, key, actorUserId, result, error = null) {
    if (!this.auditLogService?.record) {
      throw new Error('Custom provider lifecycle audit is not configured');
    }
    await this.auditLogService.record({
      userId: actorUserId ?? null,
      action: `provider.lifecycle.${action}`,
      targetType: 'provider',
      targetId: key,
      result,
      details: error ? { message: error.message } : { enabled: action === 'enable' }
    });
  }

  async #tryAuditLifecycle(action, key, actorUserId, result, error) {
    try {
      await this.#auditLifecycle(action, key, actorUserId, result, error);
    } catch {
      // The transition has already failed; audit persistence cannot turn it into success.
    }
  }

  #lifecycleResult(definition) {
    return {
      providerKey: definition.key,
      enabled: definition.enabled,
      customProvider: true,
      displayName: definition.displayName,
      description: definition.description ?? null,
      category: definition.category ?? null
    };
  }

  #consistencyError(message, originalError = null, rollbackError = null) {
    const error = new Error(message);
    error.code = 'PROVIDER_LIFECYCLE_CONSISTENCY_FAILURE';
    error.statusCode = 500;
    if (originalError) error.cause = originalError;
    if (rollbackError) error.rollbackError = rollbackError;
    return error;
  }

  #register(definition) {
    if (this.providerRegistry.has(definition.key)) {
      const error = new Error(`Persisted custom provider '${definition.key}' conflicts with an existing provider`);
      error.code = 'PROVIDER_ALREADY_EXISTS';
      error.statusCode = 409;
      throw error;
    }
    this.providerRegistry.register(new ProviderDefinition({
      name: definition.key,
      provider: new DeclarativeCustomProvider({ name: definition.key }),
      apiClient: Object.freeze({ kind: 'declarative-custom-provider' }),
      capabilities: new ProviderCapabilities([]),
      displayName: definition.displayName,
      description: definition.description,
      credentialFields: definition.credentialFields,
      credentialMethods: definition.credentialMethods,
      providerMethodBindings: definition.providerMethodBindings,
      metadata: { category: definition.category, customProvider: true, runtimeOperations: [] }
    }));
  }

  #assertObjectKeys(value, allowedKeys, label) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw this.#invalid(`${label} must be an object`);
    }
    for (const key of Object.keys(value)) {
      if (!allowedKeys.has(key)) {
        throw this.#invalid(`${label} contains unsupported property '${key}'`);
      }
    }
  }

  #invalid(message) {
    const error = new Error(message);
    error.code = 'PROVIDER_DEFINITION_INVALID';
    error.statusCode = 400;
    return error;
  }
}
