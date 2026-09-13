/**
 * Provider-neutral authorization-identifier contracts.
 *
 * These validators deliberately validate rather than repair input.  Search and
 * presentation code may remain tolerant, but authorization and persistence
 * paths must use the exact value returned by this module.
 */

export const IdentifierDomain = Object.freeze({
  OPAQUE_EXACT: 'OPAQUE_EXACT',
  CANONICAL_TECHNICAL_KEY: 'CANONICAL_TECHNICAL_KEY',
  PREDEFINED_ENUM_EXACT: 'PREDEFINED_ENUM_EXACT',
  CASE_SENSITIVE_FIELD_KEY: 'CASE_SENSITIVE_FIELD_KEY',
  PROVIDER_OWNED_OPAQUE: 'PROVIDER_OWNED_OPAQUE',
  SECRET_EXACT: 'SECRET_EXACT',
  PATH_SEGMENT_EXACT: 'PATH_SEGMENT_EXACT'
});

const TECHNICAL_KEY = /^[a-z][a-z0-9-]{0,62}$/;
const FIELD_KEY = /^[a-z][a-zA-Z0-9-]{0,62}$/;
const PATH_SEGMENT = /^[^/\\?#%]+$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

const DEFINITIONS = Object.freeze({
  consumerId: IdentifierDomain.OPAQUE_EXACT,
  apiTokenId: IdentifierDomain.OPAQUE_EXACT,
  tokenId: IdentifierDomain.OPAQUE_EXACT,
  credentialId: IdentifierDomain.OPAQUE_EXACT,
  credentialKey: IdentifierDomain.OPAQUE_EXACT,
  credentialGeneration: IdentifierDomain.OPAQUE_EXACT,
  principalGeneration: IdentifierDomain.OPAQUE_EXACT,
  grantId: IdentifierDomain.OPAQUE_EXACT,
  userId: IdentifierDomain.OPAQUE_EXACT,
  providerConfigurationId: IdentifierDomain.OPAQUE_EXACT,
  providerKey: IdentifierDomain.CANONICAL_TECHNICAL_KEY,
  credentialMethodKey: IdentifierDomain.CANONICAL_TECHNICAL_KEY,
  methodKey: IdentifierDomain.CANONICAL_TECHNICAL_KEY,
  fieldKey: IdentifierDomain.CASE_SENSITIVE_FIELD_KEY,
  secretFieldKey: IdentifierDomain.CASE_SENSITIVE_FIELD_KEY,
  roleKey: IdentifierDomain.PREDEFINED_ENUM_EXACT,
  permissionScope: IdentifierDomain.PREDEFINED_ENUM_EXACT,
  externalReference: IdentifierDomain.PROVIDER_OWNED_OPAQUE,
  backupId: IdentifierDomain.PATH_SEGMENT_EXACT,
  oauthState: IdentifierDomain.SECRET_EXACT,
  authorizationCode: IdentifierDomain.SECRET_EXACT,
  bindingToken: IdentifierDomain.SECRET_EXACT
});

const ENUM_VALUES = Object.freeze({
  roleKey: Object.freeze(new Set(['admin', 'operator', 'viewer'])),
  permissionScope: null
});

export class AuthorizationIdentifierError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'AuthorizationIdentifierError';
    this.code = code;
    this.statusCode = 400;
    this.details = Object.freeze({ ...details });
  }
}

function invalid(domain, value, reason = 'invalid') {
  const safe = typeof value === 'string' ? value : typeof value;
  const code = reason === 'conflict' ? 'CANONICAL_IDENTITY_CONFLICT' : reason === 'unsupported' ? 'IDENTIFIER_DOMAIN_UNSUPPORTED' : reason === 'ambiguous' ? 'IDENTIFIER_AMBIGUOUS' : 'IDENTIFIER_INVALID';
  throw new AuthorizationIdentifierError(code, `Identifier is ${reason} for domain '${domain}'`, { domain, type: safe });
}

export function domainFor(name) {
  const domain = DEFINITIONS[name];
  if (!domain) throw new AuthorizationIdentifierError('IDENTIFIER_DOMAIN_UNSUPPORTED', `Unknown authorization identifier domain '${name}'`, { name });
  return domain;
}

export function validateIdentifier(domain, value, { enumValues = null } = {}) {
  if (!Object.values(IdentifierDomain).includes(domain)) invalid(domain, value, 'unsupported');
  if (typeof value !== 'string' || value.length === 0 || CONTROL.test(value) || value.trim() !== value) invalid(domain, value);
  if (domain === IdentifierDomain.CANONICAL_TECHNICAL_KEY && !TECHNICAL_KEY.test(value)) invalid(domain, value);
  if (domain === IdentifierDomain.CASE_SENSITIVE_FIELD_KEY && !FIELD_KEY.test(value)) invalid(domain, value);
  if (domain === IdentifierDomain.PATH_SEGMENT_EXACT && (!PATH_SEGMENT.test(value) || value === '.' || value === '..')) invalid(domain, value);
  if (domain === IdentifierDomain.PREDEFINED_ENUM_EXACT) {
    const allowed = enumValues instanceof Set ? enumValues : null;
    if (allowed && !allowed.has(value)) invalid(domain, value);
    if (!allowed && !/^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/.test(value)) invalid(domain, value);
  }
  return value;
}

export function validateNamedIdentifier(name, value, options = {}) {
  const domain = domainFor(name);
  const enumValues = options.enumValues ?? ENUM_VALUES[name] ?? null;
  try {
    return validateIdentifier(domain, value, { ...options, enumValues });
  } catch (error) {
    if (error instanceof AuthorizationIdentifierError && error.code === 'IDENTIFIER_INVALID') {
      error.message = `Identifier '${name}' is invalid for domain '${domain}'`;
    }
    throw error;
  }
}

export function compareIdentifiers(nameOrDomain, left, right) {
  if (DEFINITIONS[nameOrDomain]) {
    validateNamedIdentifier(nameOrDomain, left);
    validateNamedIdentifier(nameOrDomain, right);
  } else {
    validateIdentifier(nameOrDomain, left);
    validateIdentifier(nameOrDomain, right);
  }
  return left === right;
}

export function validateCompositeIdentity(components) {
  if (!components || typeof components !== 'object' || Array.isArray(components)) invalid('composite', components);
  return Object.freeze(Object.fromEntries(Object.entries(components).map(([name, value]) => [name, validateNamedIdentifier(name, value)])));
}

export const AUTHORIZATION_IDENTIFIER_DEFINITIONS = DEFINITIONS;
