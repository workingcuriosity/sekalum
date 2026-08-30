const CACHE_POLICIES = new Set(['NO_CACHE']);
const EXPIRY_SOURCES = new Set(['provider']);

function stringList(value, field) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.trim() === '')) {
    throw new Error(`RuntimeDerivationContract: '${field}' must contain non-empty strings`);
  }
  return [...new Set(value.map((item) => item.trim()))].sort();
}

/** Provider-neutral, version-bound declaration for ephemeral runtime derivation. */
export class RuntimeDerivationContract {
  constructor({
    supportsRuntimeDerivation = false,
    derivationMethod = null,
    requiredDurableInputs = [],
    supportedAudiences = [],
    supportedScopes = [],
    derivedFields = [],
    expirySource = 'provider',
    cachePolicy = 'NO_CACHE',
    refreshThresholdMs = 0
  } = {}) {
    if (typeof supportsRuntimeDerivation !== 'boolean') {
      throw new Error("RuntimeDerivationContract: 'supportsRuntimeDerivation' must be boolean");
    }
    if (supportsRuntimeDerivation && (typeof derivationMethod !== 'string' || derivationMethod.trim() === '')) {
      throw new Error('RuntimeDerivationContract: derivationMethod is required when derivation is enabled');
    }
    if (!CACHE_POLICIES.has(cachePolicy)) throw new Error(`RuntimeDerivationContract: unsupported cache policy '${cachePolicy}'`);
    if (!EXPIRY_SOURCES.has(expirySource)) throw new Error(`RuntimeDerivationContract: unsupported expiry source '${expirySource}'`);
    if (!Number.isInteger(refreshThresholdMs) || refreshThresholdMs < 0) {
      throw new Error("RuntimeDerivationContract: 'refreshThresholdMs' must be a non-negative integer");
    }

    this.supportsRuntimeDerivation = supportsRuntimeDerivation;
    this.derivationMethod = supportsRuntimeDerivation ? derivationMethod.trim() : null;
    this.requiredDurableInputs = Object.freeze(stringList(requiredDurableInputs, 'requiredDurableInputs'));
    this.supportedAudiences = Object.freeze(stringList(supportedAudiences, 'supportedAudiences'));
    this.supportedScopes = Object.freeze(stringList(supportedScopes, 'supportedScopes'));
    this.derivedFields = Object.freeze(stringList(derivedFields, 'derivedFields'));
    if (supportsRuntimeDerivation && this.derivedFields.length === 0) {
      throw new Error('RuntimeDerivationContract: at least one derived field is required when derivation is enabled');
    }
    this.expirySource = expirySource;
    this.cachePolicy = cachePolicy;
    this.refreshThresholdMs = refreshThresholdMs;
    Object.freeze(this);
  }

  accepts({ audience = null, scopes = [] } = {}) {
    if (this.supportedAudiences.length > 0 && (!audience || !this.supportedAudiences.includes(audience))) return false;
    const requestedScopes = stringList(scopes, 'scopes');
    return this.supportedScopes.length === 0
      || (requestedScopes.length > 0 && requestedScopes.every((scope) => this.supportedScopes.includes(scope)));
  }

  toJSON() {
    return {
      supportsRuntimeDerivation: this.supportsRuntimeDerivation,
      derivationMethod: this.derivationMethod,
      requiredDurableInputs: [...this.requiredDurableInputs],
      supportedAudiences: [...this.supportedAudiences],
      supportedScopes: [...this.supportedScopes],
      derivedFields: [...this.derivedFields],
      expirySource: this.expirySource,
      cachePolicy: this.cachePolicy,
      refreshThresholdMs: this.refreshThresholdMs
    };
  }

  static from(value) {
    if (value instanceof RuntimeDerivationContract) return value;
    return new RuntimeDerivationContract(value);
  }
}
