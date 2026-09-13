// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import crypto from 'node:crypto';

function canonicalize(value) {
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((entry) => canonicalize(entry));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export function digestCredentialBinding(value) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(canonicalize(value)), 'utf8')
    .digest('hex');
}

// These fields identify the durable Credential and its provider/account
// binding. They must remain stable for an existing identity unless a caller
// uses an explicitly authorized migration path.
export const IMMUTABLE_CREDENTIAL_BINDING_FIELDS = Object.freeze([
  'credentialKey',
  'credentialGeneration',
  'providerKey',
  'credentialMethodKey',
  'externalReference',
  'providerProfile',
  'providerConfigurationId',
  'oauthCredentialBinding'
]);

const RESTORE_BINDING_FIELDS = Object.freeze(IMMUTABLE_CREDENTIAL_BINDING_FIELDS.filter((field) => (
  field !== 'credentialKey' && field !== 'credentialGeneration'
)));

export function credentialBindingProjection(credential = {}, { includeIdentityAnchors = true } = {}) {
  const fields = includeIdentityAnchors ? IMMUTABLE_CREDENTIAL_BINDING_FIELDS : RESTORE_BINDING_FIELDS;
  return Object.fromEntries(fields.map((field) => [
    field,
    credential?.[field] ?? null
  ]));
}

export function credentialBindingMatches(current, candidate, options = {}) {
  return digestCredentialBinding(credentialBindingProjection(current, options))
    === digestCredentialBinding(credentialBindingProjection(candidate, options));
}

export function assertCredentialBindingUnchanged(current, candidate, { operation = 'credential update' } = {}) {
  if (credentialBindingMatches(current, candidate)) return true;

  const error = new Error('Credential identity binding cannot be changed');
  error.code = 'CREDENTIAL_LIFECYCLE_CONFLICT';
  error.statusCode = 409;
  error.details = {
    credentialId: current?.credentialId ?? candidate?.credentialId ?? null,
    reason: 'IMMUTABLE_BINDING',
    operation
  };
  throw error;
}
