/**
 * Resolves the authenticated actor. The legacy header is retained only for
 * explicit test compatibility; production actors must come from req.auth.
 */
export function authenticatedUserId(req) {
  if (typeof req?.auth?.userId === 'string' && req.auth.userId.trim() !== '') {
    return req.auth.userId;
  }

  if (process.env.NODE_ENV === 'test') {
    return req?.headers?.['x-credential-hub-user'] ?? null;
  }

  return null;
}
