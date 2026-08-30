export class DerivedRuntimeMaterial {
  constructor({
    credentialIdentity,
    providerProfile,
    derivationMethod,
    values,
    expiresAt,
    effectiveScopes = [],
    audience = null,
    runtimeContext = {},
    sourceVersion = null
  } = {}) {
    if (typeof credentialIdentity !== 'string' || credentialIdentity.trim() === '') {
      throw new Error('DerivedRuntimeMaterial: credentialIdentity is required');
    }
    if (!providerProfile?.digest) throw new Error('DerivedRuntimeMaterial: providerProfile identity is required');
    if (typeof derivationMethod !== 'string' || derivationMethod.trim() === '') {
      throw new Error('DerivedRuntimeMaterial: derivationMethod is required');
    }
    if (!values || typeof values !== 'object' || Array.isArray(values) || Object.keys(values).length === 0) {
      throw new Error('DerivedRuntimeMaterial: values are required');
    }
    const expiry = expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
    if (Number.isNaN(expiry.getTime())) throw new Error('DerivedRuntimeMaterial: expiresAt must be valid');
    if (!Array.isArray(effectiveScopes) || effectiveScopes.some((scope) => typeof scope !== 'string' || scope.trim() === '')) {
      throw new Error('DerivedRuntimeMaterial: effectiveScopes must contain non-empty strings');
    }
    if (!runtimeContext || typeof runtimeContext !== 'object' || Array.isArray(runtimeContext)) {
      throw new Error('DerivedRuntimeMaterial: runtimeContext must be an object');
    }

    this.credentialIdentity = credentialIdentity.trim();
    this.providerProfile = Object.freeze({ ...providerProfile });
    this.derivationMethod = derivationMethod.trim();
    this.values = Object.freeze({ ...values });
    this.expiresAt = expiry;
    this.effectiveScopes = Object.freeze([...new Set(effectiveScopes.map((scope) => scope.trim()))].sort());
    this.audience = audience;
    this.runtimeContext = Object.freeze({ ...runtimeContext });
    this.sourceVersion = sourceVersion;
    Object.freeze(this);
  }

  isExpired({ now = new Date(), safetyWindowMs = 0 } = {}) {
    const timestamp = now instanceof Date ? now.getTime() : new Date(now).getTime();
    return Number.isNaN(timestamp) || this.expiresAt.getTime() <= timestamp + safetyWindowMs;
  }

  toAuthorizedSecrets(names) {
    if (!Array.isArray(names) || names.some((name) => typeof name !== 'string' || !Object.hasOwn(this.values, name))) {
      throw new Error('DerivedRuntimeMaterial: requested field is unavailable');
    }
    return Object.fromEntries(names.map((name) => [name, this.values[name]]));
  }

  toJSON() {
    return {
      credentialIdentity: this.credentialIdentity,
      providerProfile: { ...this.providerProfile },
      derivationMethod: this.derivationMethod,
      derivedFields: Object.keys(this.values).sort(),
      expiresAt: this.expiresAt.toISOString(),
      effectiveScopes: [...this.effectiveScopes],
      audience: this.audience,
      runtimeContext: { ...this.runtimeContext },
      sourceVersion: this.sourceVersion
    };
  }

  static from(value) {
    if (value instanceof DerivedRuntimeMaterial) return value;
    return new DerivedRuntimeMaterial(value);
  }
}
