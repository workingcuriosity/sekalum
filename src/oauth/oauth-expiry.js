const MAX_OAUTH_EXPIRY_SECONDS = 10 * 365 * 24 * 60 * 60;

function numericExpirySeconds(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string' && value.trim() === '') return null;

  const seconds = typeof value === 'number' || typeof value === 'string'
    ? Number(value)
    : NaN;

  if (!Number.isFinite(seconds) || seconds < 0 || seconds > MAX_OAUTH_EXPIRY_SECONDS) {
    return null;
  }

  return seconds;
}

export function normalizeOAuthExpiry(expiresIn, { now = Date.now } = {}) {
  const seconds = numericExpirySeconds(expiresIn);
  if (seconds === null) return null;

  const expiresAt = new Date(now() + seconds * 1000);
  return Number.isNaN(expiresAt.getTime()) ? null : expiresAt;
}

export function oauthExpiryStatus(expiresIn) {
  if (expiresIn === null || expiresIn === undefined || (typeof expiresIn === 'string' && expiresIn.trim() === '')) {
    return 'missing';
  }
  return numericExpirySeconds(expiresIn) === null ? 'invalid' : 'valid';
}

export { MAX_OAUTH_EXPIRY_SECONDS };
