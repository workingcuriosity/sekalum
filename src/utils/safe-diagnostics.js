const REDACTED = '[REDACTED]';
const CIRCULAR = '[CIRCULAR]';

const SENSITIVE_KEY_PATTERN = /^(?:authorization|proxyauthorization|cookie|setcookie|apikey|api_key|access_token|accesstoken|refresh_token|refreshtoken|client_secret|clientsecret|password|secret|secrets|secretvalue|token|tokens|credential|credentials)$/i;
const SENSITIVE_TEXT_PATTERN = /((?:["']?)(?:authorization|proxy-authorization|cookie|set-cookie|api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|password|secret|token)(?:["']?)\s*[:=]\s*["']?)([^\s,;&}"']+)/gi;
const BEARER_PATTERN = /\bBearer\s+[^\s,;&}]+/gi;
const TEST_SECRET_PATTERN = /\b(?:TEST|FAKE|DUMMY)_(?:SECRET|TOKEN|COOKIE|KEY)[A-Z0-9_-]*\b/gi;

function keyIsSensitive(key) {
  if (typeof key !== 'string') return false;
  const normalized = key.replaceAll('-', '_').replaceAll(' ', '').toLowerCase();
  const compact = normalized.replaceAll('_', '');
  return SENSITIVE_KEY_PATTERN.test(normalized)
    || SENSITIVE_KEY_PATTERN.test(compact)
    || normalized.endsWith('secret')
    || normalized.endsWith('token')
    || normalized.endsWith('password')
    || normalized.endsWith('apikey');
}

function redactUrl(value) {
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    for (const key of [...url.searchParams.keys()]) {
      url.searchParams.set(key, REDACTED);
    }
    return url.toString();
  } catch {
    return value;
  }
}

function sanitizeString(value) {
  let result = String(value);
  result = result.replace(BEARER_PATTERN, 'Bearer ' + REDACTED);
  result = result.replace(SENSITIVE_TEXT_PATTERN, `$1${REDACTED}`);
  result = result.replace(TEST_SECRET_PATTERN, REDACTED);
  return result.replace(/https?:\/\/[^\s"'<>]+/gi, (url) => redactUrl(url));
}

function sanitizeValue(value, key, seen) {
  if (keyIsSensitive(key)) return REDACTED;
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return sanitizeString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'function' || typeof value === 'symbol') return undefined;
  if (value instanceof Date) return value.toISOString();
  if (seen.has(value)) return CIRCULAR;
  seen.add(value);

  if (value instanceof Error) {
    const output = {
      name: sanitizeString(value.name || 'Error'),
      message: sanitizeString(value.message || '')
    };
    for (const [childKey, childValue] of Object.entries(value)) {
      if (childKey === 'stack') continue;
      const sanitized = sanitizeValue(childValue, childKey, seen);
      if (sanitized !== undefined) output[childKey] = sanitized;
    }
    return output;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item, null, seen));
  }

  const output = {};
  for (const [childKey, childValue] of Object.entries(value)) {
    if (childKey === 'stack') continue;
    const sanitized = sanitizeValue(childValue, childKey, seen);
    if (sanitized !== undefined) output[childKey] = sanitized;
  }
  return output;
}

export function sanitizeDiagnostic(value) {
  return sanitizeValue(value, null, new WeakSet());
}

export function safeError(error, { fallbackMessage = 'Unexpected error' } = {}) {
  const normalized = sanitizeDiagnostic(error);
  const source = error && typeof error === 'object' ? error : {};
  const message = sanitizeString(source.message ?? (typeof error === 'string' ? error : fallbackMessage));
  const safe = {
    name: sanitizeString(source.name ?? normalized?.name ?? 'Error'),
    message: message || fallbackMessage
  };

  for (const key of ['code', 'statusCode', 'status', 'classification', 'correlationId', 'provider', 'operation']) {
    const value = source[key];
    if (value !== undefined && value !== null && !keyIsSensitive(key)) {
      safe[key] = typeof value === 'string' ? sanitizeString(value) : value;
    }
  }

  if (source.details !== undefined) safe.details = sanitizeDiagnostic(source.details);

  return Object.freeze(safe);
}

export function safeErrorMessage(error, fallbackMessage = 'Unexpected error') {
  return safeError(error, { fallbackMessage }).message;
}

export { REDACTED };
