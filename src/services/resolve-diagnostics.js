// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

export const ResolveDiagnosticCode = Object.freeze({
  SUCCESS: 'RESOLVE_SUCCESS',
  CONSUMER_NOT_FOUND: 'CONSUMER_NOT_FOUND',
  CREDENTIAL_NOT_FOUND: 'CREDENTIAL_NOT_FOUND',
  CREDENTIAL_NOT_CONSUMABLE: 'CREDENTIAL_NOT_CONSUMABLE',
  CREDENTIAL_DISABLED: 'CREDENTIAL_DISABLED',
  GRANT_MISSING: 'GRANT_MISSING',
  SECRET_NOT_GRANTED: 'SECRET_NOT_GRANTED',
  INVALID_SECRET_REQUEST: 'INVALID_SECRET_REQUEST',
  NOT_AVAILABLE: 'RESOLVE_NOT_AVAILABLE'
});

export function resolveDiagnostic(code, { publicResponse = false } = {}) {
  if (publicResponse && code !== ResolveDiagnosticCode.INVALID_SECRET_REQUEST && code !== 'INTERNAL_ERROR') {
    if (code === ResolveDiagnosticCode.CREDENTIAL_NOT_FOUND) {
      return Object.freeze({ code, statusCode: 404, message: 'The selected credential is not available' });
    }
    if (code === ResolveDiagnosticCode.CREDENTIAL_NOT_CONSUMABLE) {
      return Object.freeze({ code, statusCode: 409, message: 'The selected credential is not active' });
    }
    return Object.freeze({ code: ResolveDiagnosticCode.NOT_AVAILABLE, statusCode: 403, message: 'The requested credential is not available to this consumer' });
  }

  const details = {
    [ResolveDiagnosticCode.SUCCESS]: [200, 'Credential resolution succeeded'],
    [ResolveDiagnosticCode.CONSUMER_NOT_FOUND]: [404, 'The selected consumer is not available'],
    [ResolveDiagnosticCode.CREDENTIAL_NOT_FOUND]: [404, 'The selected credential is not available'],
    [ResolveDiagnosticCode.CREDENTIAL_NOT_CONSUMABLE]: [409, 'The selected credential is not active'],
    [ResolveDiagnosticCode.CREDENTIAL_DISABLED]: [409, 'The selected credential is not active'],
    [ResolveDiagnosticCode.GRANT_MISSING]: [403, 'The selected consumer has no grant for this credential'],
    [ResolveDiagnosticCode.SECRET_NOT_GRANTED]: [403, 'One or more selected secret fields are not granted'],
    [ResolveDiagnosticCode.INVALID_SECRET_REQUEST]: [400, 'The requested secret fields are invalid']
  }[code] ?? [500, 'Credential resolution could not be completed'];

  return Object.freeze({ code, statusCode: details[0], message: details[1] });
}
