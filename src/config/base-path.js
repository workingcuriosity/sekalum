import { isIP } from 'node:net';

export function normalizeBasePath(value) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim() === '/') {
    return '/';
  }

  const normalized = `/${value.trim().replace(/^\/+|\/+$/g, '')}`;
  if (!/^\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/.test(normalized)) {
    throw new Error('BASE_PATH must be / or a slash-prefixed path without query, fragment, or whitespace');
  }
  return normalized;
}

export function withBasePath(basePath, path) {
  const normalizedBasePath = normalizeBasePath(basePath);
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return normalizedBasePath === '/' ? normalizedPath : `${normalizedBasePath}${normalizedPath}`;
}

export function normalizePublicBaseUrl(value) {
  if (value === null || value === undefined || String(value).trim() === '') return null;

  let parsed;
  try {
    parsed = new URL(String(value).trim());
  } catch {
    throw new Error('PUBLIC_BASE_URL must be an absolute HTTP(S) URL');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw new Error('PUBLIC_BASE_URL must contain only an HTTP(S) origin without credentials, path, query, or fragment');
  }

  return parsed.origin;
}

function isTrustedProxyToken(value) {
  if (['loopback', 'linklocal', 'uniquelocal'].includes(value)) return true;
  const [address, prefix] = value.split('/');
  const family = isIP(address);
  if (!family) return false;
  if (prefix === undefined) return true;
  const maximum = family === 4 ? 32 : 128;
  return /^\d+$/.test(prefix) && Number(prefix) <= maximum;
}

export function normalizeTrustedProxy(value) {
  if (value === null || value === undefined || value === false || value === 0 || String(value).trim() === '' || String(value).trim().toLowerCase() === 'false') {
    return false;
  }

  const values = String(value).split(',').map((entry) => entry.trim()).filter(Boolean);
  if (!values.length || values.some((entry) => !isTrustedProxyToken(entry))) {
    throw new Error('TRUSTED_PROXY must contain only loopback, linklocal, uniquelocal, or IP/CIDR values');
  }
  if (values.some((entry) => ['0.0.0.0/0', '::/0'].includes(entry))) {
    throw new Error('TRUSTED_PROXY must identify an explicit proxy boundary');
  }
  if (values.some((entry) => entry.endsWith('/0'))) {
    throw new Error('TRUSTED_PROXY must identify an explicit proxy boundary');
  }
  return values.length === 1 ? values[0] : values;
}

export function normalizeApplicationBindHost(value, { hosted = false } = {}) {
  const host = typeof value === 'string' && value.trim() !== '' ? value.trim() : (hosted ? '0.0.0.0' : '127.0.0.1');
  const isLoopback = ['127.0.0.1', '::1', 'localhost'].includes(host);
  const isWildcard = ['0.0.0.0', '::'].includes(host);
  if (!isLoopback && !isWildcard) {
    throw new Error('APP_BIND_HOST must be a loopback or wildcard address');
  }
  if (hosted && isLoopback) {
    throw new Error('HOSTED_MODE requires a non-loopback application bind for the private proxy network');
  }
  if (!hosted && !isLoopback) {
    throw new Error('Standalone mode requires a loopback application bind');
  }
  return host;
}

export function isInternalPublicOrigin(value) {
  const parsed = new URL(value);
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal') || hostname === 'container') return true;
  const family = isIP(hostname);
  if (family === 4) {
    const octets = hostname.split('.').map(Number);
    return octets[0] === 10
      || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
      || (octets[0] === 192 && octets[1] === 168)
      || octets[0] === 127;
  }
  return family === 6 && (hostname === '::1' || hostname.startsWith('fc') || hostname.startsWith('fd') || hostname.startsWith('fe8') || hostname.startsWith('fe9') || hostname.startsWith('fea') || hostname.startsWith('feb'));
}

export function assertNoConflictingTrustedProxySignals(req, trustedProxy) {
  if (trustedProxy === false) return;
  const headers = [
    ['x', 'forwarded', 'host'].join('-'),
    ['x', 'forwarded', 'proto'].join('-')
  ];
  for (const header of headers) {
    const value = req.get(header);
    if (value !== undefined && value.split(',').map((entry) => entry.trim()).filter(Boolean).length !== 1) {
      throw new Error('TRUSTED_PROXY_FORWARDING_CONFLICT');
    }
  }
}
