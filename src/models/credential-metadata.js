const PUBLIC_CUSTOM_METADATA_KEYS = new Set([
  'accountName', 'credentialType', 'email', 'healthStatus', 'lastRefreshAt',
  'lastValidatedAt', 'login', 'name', 'tokenType', 'type', 'username'
]);

const INTERNAL_CUSTOM_METADATA_KEYS = new Set([
  ...PUBLIC_CUSTOM_METADATA_KEYS,
  'connectionVerificationHost', 'host', 'lastSecretRollbackAt', 'legacyProviderId',
  'legacyTokenMetadata', 'port', 'providerConfigurationId', 'providerProfile',
  'redirectUri', 'runtimeDerivation', 'source', 'sourceRow', 'organizationId'
]);

const NESTED_INTERNAL_CUSTOM_METADATA_KEYS = new Set([
  'legacyTokenMetadata', 'providerProfile', 'runtimeDerivation'
]);

function clone(value) {
  if (Array.isArray(value)) return value.map(clone);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, clone(entry)]));
  }
  return value;
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

function isSafeScalar(value) {
  return value === null
    || typeof value === 'string'
    || typeof value === 'number' && Number.isFinite(value)
    || typeof value === 'boolean'
    || Array.isArray(value) && value.every((entry) => typeof entry === 'string' && entry.trim() !== '');
}

function metadataError() {
  const error = new Error('Credential metadata contains unsupported custom values');
  error.code = 'CREDENTIAL_METADATA_INVALID';
  error.statusCode = 400;
  error.messageKey = 'credential.metadata.invalid';
  return error;
}

function assertCustomValues(custom, { allowSensitive = true } = {}) {
  if (!custom || typeof custom !== 'object' || Array.isArray(custom)) throw metadataError();
  for (const [key, value] of Object.entries(custom)) {
    if (!INTERNAL_CUSTOM_METADATA_KEYS.has(key)) throw metadataError();
    if (NESTED_INTERNAL_CUSTOM_METADATA_KEYS.has(key)) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw metadataError();
    } else if (!isSafeScalar(value)) {
      throw metadataError();
    }
  }
}

export const CredentialMetadataPolicy = Object.freeze({
  publicCustomKeys: PUBLIC_CUSTOM_METADATA_KEYS,
  internalCustomKeys: INTERNAL_CUSTOM_METADATA_KEYS
});

export class CredentialMetadata {
  constructor(input = {}) {
    const {
      displayName = null,
      description = null,
      scopes = [],
      tags = [],
      expiresAt = null,
      custom = {},
      sensitiveMetadata = {}
    } = input;
    const flatPublicCustom = Object.fromEntries(
      [...PUBLIC_CUSTOM_METADATA_KEYS]
        .filter((key) => Object.hasOwn(input, key))
        .map((key) => [key, input[key]])
    );
    this.displayName = displayName;
    this.description = description;
    this.scopes = freeze(clone(scopes));
    this.tags = freeze(clone(tags));
    this.expiresAt = expiresAt ? new Date(expiresAt) : null;
    this.custom = freeze(clone({ ...flatPublicCustom, ...custom }));
    this.sensitiveMetadata = freeze(clone(sensitiveMetadata));

    Object.freeze(this);
  }

  toJSON() {
    return {
      displayName: this.displayName,
      description: this.description,
      scopes: this.scopes,
      tags: this.tags,
      expiresAt: this.expiresAt ? this.expiresAt.toISOString() : null,
      custom: this.custom,
      sensitiveMetadata: this.sensitiveMetadata
    };
  }

  toPublicJSON() {
    const safeCustom = Object.fromEntries(
      Object.entries(this.custom)
        .filter(([key, value]) => PUBLIC_CUSTOM_METADATA_KEYS.has(key) && isSafeScalar(value))
        .map(([key, value]) => [key, clone(value)])
    );
    return {
      displayName: this.displayName,
      description: this.description,
      scopes: clone(this.scopes),
      tags: clone(this.tags),
      expiresAt: this.expiresAt ? this.expiresAt.toISOString() : null,
      ...safeCustom
    };
  }

  static assertWriteSafe(data = {}) {
    const metadata = data instanceof CredentialMetadata ? data.toJSON() : data;
    if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw metadataError();
    const allowedKeys = new Set(['displayName', 'description', 'scopes', 'tags', 'expiresAt', 'custom', 'sensitiveMetadata', ...PUBLIC_CUSTOM_METADATA_KEYS]);
    if (Object.keys(metadata).some((key) => !allowedKeys.has(key))) throw metadataError();
    const flatPublicCustom = Object.fromEntries(
      [...PUBLIC_CUSTOM_METADATA_KEYS]
        .filter((key) => Object.hasOwn(metadata, key))
        .map((key) => [key, metadata[key]])
    );
    assertCustomValues({ ...flatPublicCustom, ...(metadata.custom ?? {}) });
    if (Object.hasOwn(metadata, 'sensitiveMetadata')
      && (!metadata.sensitiveMetadata || typeof metadata.sensitiveMetadata !== 'object' || Array.isArray(metadata.sensitiveMetadata))) {
      throw metadataError();
    }
    return true;
  }

  static from(data = {}) {
    if (data instanceof CredentialMetadata) return data;
    return new CredentialMetadata(data);
  }
}
