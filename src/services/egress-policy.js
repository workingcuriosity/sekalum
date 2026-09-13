import { lookup as dnsLookup } from 'node:dns/promises';
import { domainToASCII } from 'node:url';
import net from 'node:net';

export const EGRESS_PURPOSES = Object.freeze({
  OAUTH_TOKEN_EXCHANGE: 'OAUTH_TOKEN_EXCHANGE',
  OAUTH_REFRESH: 'OAUTH_REFRESH',
  OAUTH_PROFILE_LOOKUP: 'OAUTH_PROFILE_LOOKUP',
  OAUTH_INTROSPECTION: 'OAUTH_INTROSPECTION',
  PROVIDER_VALIDATION: 'PROVIDER_VALIDATION',
  PROVIDER_HEALTH_CHECK: 'PROVIDER_HEALTH_CHECK',
  CREDENTIAL_CONNECTION_TEST: 'CREDENTIAL_CONNECTION_TEST'
});

const PURPOSE_SET = new Set(Object.values(EGRESS_PURPOSES));
const HTTP_PROTOCOLS = new Set(['https']);
const CONNECTION_PROTOCOLS = new Set(['ftp', 'sftp']);
const PRIVATE_EXCEPTION_PURPOSES = new Set([
  EGRESS_PURPOSES.CREDENTIAL_CONNECTION_TEST,
  EGRESS_PURPOSES.PROVIDER_VALIDATION,
  EGRESS_PURPOSES.PROVIDER_HEALTH_CHECK
]);

const HARD_BLOCKED_CLASSIFICATIONS = new Set([
  'loopback',
  'unspecified',
  'link-local',
  'carrier-grade-nat',
  'multicast',
  'reserved',
  'embedded-translated',
  'unknown'
]);

export class EgressError extends Error {
  constructor(code, message = null, { statusCode = 400, classification = null, field = null } = {}) {
    super(message ?? EGRESS_MESSAGES[code] ?? 'Egress request was rejected');
    this.name = 'EgressError';
    this.code = code;
    this.statusCode = statusCode;
    this.classification = classification;
    this.details = field ? { field } : undefined;
  }
}

const EGRESS_MESSAGES = Object.freeze({
  EGRESS_INVALID_CONTEXT: 'Egress request context is invalid',
  EGRESS_INVALID_TARGET: 'Egress target is invalid',
  EGRESS_DNS_FAILED: 'Egress target could not be resolved',
  EGRESS_TARGET_BLOCKED: 'Egress target is not allowed',
  EGRESS_REDIRECT_BLOCKED: 'Egress redirects are not allowed',
  EGRESS_POLICY_UNAVAILABLE: 'Egress policy is unavailable',
  EGRESS_TRANSPORT_UNSUPPORTED: 'Egress transport is unsupported',
  EGRESS_RESPONSE_LIMIT_EXCEEDED: 'Egress response exceeded its bounded limit',
  EGRESS_TIMEOUT: 'Egress request timed out',
  EGRESS_TRANSPORT_FAILED: 'Egress transport failed'
});

export function privateExceptionFromConfig(config) {
  const raw = config?.get?.('CONNECTION_TEST_PRIVATE_EXCEPTION', null);
  if (raw === null || raw === undefined || raw === '') return null;
  if (typeof raw === 'object' && !Array.isArray(raw)) return raw;
  if (typeof raw !== 'string') throw new EgressError('EGRESS_INVALID_CONTEXT');
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid exception');
    return parsed;
  } catch {
    throw new EgressError('EGRESS_INVALID_CONTEXT');
  }
}

export function classifyAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return classifyIpv4(address);
  if (family === 6) return classifyIpv6(address);
  return { family: 0, classification: 'unknown', embeddedAddress: null };
}

export class EgressPolicy {
  constructor({
    lookup = dnsLookup,
    allowPrivateNetworks = false,
    privateException = null
  } = {}) {
    this.lookup = lookup;
    this.allowPrivateNetworks = Boolean(allowPrivateNetworks);
    this.privateException = this.#normalizePrivateException(privateException);
  }

  async admit(target, context = {}) {
    const normalizedContext = this.#validateContext(context);
    const parsed = this.#parseTarget(target, normalizedContext);
    const addresses = await this.#resolve(parsed.hostname);
    const classifications = addresses.map((address) => ({ ...classifyAddress(address), address }));

    const mixedPublicPrivate = classifications.some((item) => item.classification === 'public')
      && classifications.some((item) => item.classification === 'private');
    if (classifications.length === 0 || mixedPublicPrivate || classifications.some((item) => !this.#isAdmitted(item, parsed, normalizedContext))) {
      throw new EgressError('EGRESS_TARGET_BLOCKED', null, {
        statusCode: 403,
        classification: classifications.find((item) => !this.#isAdmitted(item, parsed, normalizedContext))?.classification ?? 'unknown'
      });
    }

    const first = addresses[0];
    return Object.freeze({
      result: 'ADMITTED',
      protocol: normalizedContext.protocol,
      scheme: parsed.scheme,
      hostname: parsed.hostname,
      connectAddress: first,
      addressFamily: net.isIP(first),
      port: parsed.port,
      verificationHost: parsed.hostname,
      hostHeader: parsed.hostHeader,
      purpose: normalizedContext.purpose,
      pathId: normalizedContext.pathId,
      providerKey: normalizedContext.providerKey ?? null,
      targetSource: normalizedContext.targetSource,
      redirectPolicy: normalizedContext.redirectPolicy
    });
  }

  #validateContext(context) {
    if (!context || typeof context !== 'object' || Array.isArray(context)) {
      throw new EgressError('EGRESS_INVALID_CONTEXT');
    }

    const pathId = typeof context.pathId === 'string' ? context.pathId.trim() : '';
    const purpose = typeof context.purpose === 'string' ? context.purpose.trim() : '';
    const protocol = typeof context.protocol === 'string' ? context.protocol.toLowerCase() : '';
    if (!pathId || !/^[A-Z0-9][A-Z0-9_-]{1,79}$/.test(pathId) || !PURPOSE_SET.has(purpose)) {
      throw new EgressError('EGRESS_INVALID_CONTEXT');
    }
    if (!HTTP_PROTOCOLS.has(protocol) && !CONNECTION_PROTOCOLS.has(protocol)) {
      throw new EgressError('EGRESS_INVALID_CONTEXT');
    }
    if (HTTP_PROTOCOLS.has(protocol) && context.credentialBearing === undefined) {
      // The caller must make the credential-bearing boundary explicit for HTTP.
      throw new EgressError('EGRESS_INVALID_CONTEXT');
    }
    const redirectPolicy = typeof context.redirectPolicy === 'string'
      ? context.redirectPolicy.trim().toUpperCase()
      : 'ERROR';
    if (redirectPolicy !== 'ERROR') throw new EgressError('EGRESS_INVALID_CONTEXT');
    return Object.freeze({
      pathId,
      purpose,
      protocol,
      providerKey: typeof context.providerKey === 'string' ? context.providerKey : null,
      credentialBearing: Boolean(context.credentialBearing),
      port: context.port == null ? null : parsePort(context.port),
      targetSource: typeof context.targetSource === 'string' && context.targetSource.trim()
        ? context.targetSource.trim()
        : 'EXPLICIT',
      redirectPolicy
    });
  }

  #parseTarget(target, context) {
    if (typeof target !== 'string' || target.trim() === '') {
      throw new EgressError('EGRESS_INVALID_TARGET');
    }

    if (HTTP_PROTOCOLS.has(context.protocol)) {
      let url;
      try {
        url = new URL(target);
      } catch {
        throw new EgressError('EGRESS_INVALID_TARGET');
      }
      if (url.protocol !== 'https:') throw new EgressError('EGRESS_SCHEME_BLOCKED', null, { statusCode: 403 });
      if (url.username || url.password || !url.hostname) {
        throw new EgressError('EGRESS_INVALID_TARGET');
      }
      const hostname = normalizeHostname(url.hostname);
      const port = parsePort(url.port || '443');
      return {
        scheme: 'https',
        hostname,
        port,
        hostHeader: port === 443 ? formatHost(hostname) : `${formatHost(hostname)}:${port}`
      };
    }

    const hostname = normalizeHostname(target);
    const port = parsePort(context.port ?? (context.protocol === 'ftp' ? 21 : 22));
    return {
      scheme: context.protocol,
      hostname,
      port,
      hostHeader: `${formatHost(hostname)}:${port}`
    };
  }

  async #resolve(hostname) {
    if (net.isIP(hostname)) return [hostname];

    let result;
    try {
      result = await this.lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new EgressError('EGRESS_DNS_FAILED', null, { statusCode: 422 });
    }

    const records = Array.isArray(result) ? result : [result];
    const addresses = records
      .map((record) => typeof record === 'string' ? record : record?.address)
      .filter((address) => typeof address === 'string' && net.isIP(address));
    if (addresses.length !== records.length) throw new EgressError('EGRESS_TARGET_BLOCKED', null, { statusCode: 403, classification: 'unknown' });
    return addresses;
  }

  #isAdmitted(item, parsed, context) {
    if (item.classification === 'public') return true;
    if (item.classification === 'private') {
      return this.#privateExceptionMatches(item, parsed, context);
    }
    return !HARD_BLOCKED_CLASSIFICATIONS.has(item.classification);
  }

  #privateExceptionMatches(item, parsed, context) {
    if (!this.allowPrivateNetworks || !PRIVATE_EXCEPTION_PURPOSES.has(context.purpose)) return false;
    if (!CONNECTION_PROTOCOLS.has(context.protocol)) return false;

    const configured = this.privateException;
    if (!configured) return false;
    if (configured.protocol !== context.protocol || configured.purpose !== context.purpose) return false;
    if (configured.hostname !== parsed.hostname || configured.port !== parsed.port) return false;
    const address = item.embeddedAddress ?? item.address;
    return configured.cidrs.some((cidr) => addressInCidr(address, cidr));
  }

  #normalizePrivateException(value) {
    if (value === null || value === undefined) return null;
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new EgressError('EGRESS_INVALID_CONTEXT');
    }
    const protocol = typeof value.protocol === 'string' ? value.protocol.toLowerCase() : '';
    const purpose = typeof value.purpose === 'string' ? value.purpose.trim() : '';
    if (typeof value.hostname !== 'string' || value.hostname.trim() === '') {
      throw new EgressError('EGRESS_INVALID_CONTEXT');
    }
    let hostname;
    let port;
    try {
      hostname = normalizeHostname(value.hostname);
      port = parsePort(value.port);
    } catch {
      throw new EgressError('EGRESS_INVALID_CONTEXT');
    }
    const cidrValues = Array.isArray(value.cidrs) ? value.cidrs : [value.cidr];
    if (!CONNECTION_PROTOCOLS.has(protocol) || !PRIVATE_EXCEPTION_PURPOSES.has(purpose)
      || cidrValues.length === 0 || cidrValues.some((cidr) => !validCidr(cidr))) {
      throw new EgressError('EGRESS_INVALID_CONTEXT');
    }
    return Object.freeze({ protocol, purpose, hostname, port, cidrs: Object.freeze([...cidrValues]) });
  }
}

function normalizeHostname(value) {
  let host = String(value).trim();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (!host || /[\u0000-\u001f\u007f\s\\/@%]/.test(host) || host.includes('://')) {
    throw new EgressError('EGRESS_INVALID_TARGET');
  }
  if (net.isIP(host)) return host.toLowerCase();
  const ascii = domainToASCII(host).toLowerCase();
  if (!ascii || ascii.length > 253 || ascii.startsWith('.') || ascii.endsWith('.') || ascii.includes('..')) {
    throw new EgressError('EGRESS_INVALID_TARGET');
  }
  if (!/^[a-z0-9.-]+$/.test(ascii) || ascii.split('.').some((label) => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) {
    throw new EgressError('EGRESS_INVALID_TARGET');
  }
  return ascii;
}

function parsePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new EgressError('EGRESS_PORT_BLOCKED', null, { statusCode: 403 });
  return port;
}

function formatHost(hostname) {
  return net.isIP(hostname) === 6 ? `[${hostname}]` : hostname;
}

function classifyIpv4(address) {
  const octets = address.split('.').map(Number);
  const [a, b] = octets;
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return { family: 4, classification: 'unknown', embeddedAddress: null };
  }
  if (a === 0) return { family: 4, classification: 'unspecified', embeddedAddress: null };
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return { family: 4, classification: 'private', embeddedAddress: null };
  if (a === 127) return { family: 4, classification: 'loopback', embeddedAddress: null };
  if (a === 169 && b === 254) return { family: 4, classification: 'link-local', embeddedAddress: null };
  if (a === 100 && b >= 64 && b <= 127) return { family: 4, classification: 'carrier-grade-nat', embeddedAddress: null };
  if (a >= 224) return { family: 4, classification: 'multicast', embeddedAddress: null };
  if (a === 192 && b === 0 && octets[2] <= 255) return { family: 4, classification: 'reserved', embeddedAddress: null };
  if (a === 198 && (b === 18 || b === 19)) return { family: 4, classification: 'reserved', embeddedAddress: null };
  if (a === 198 && b === 51 && octets[2] === 100) return { family: 4, classification: 'reserved', embeddedAddress: null };
  if (a === 203 && b === 0 && octets[2] === 113) return { family: 4, classification: 'reserved', embeddedAddress: null };
  if (a === 192 && b === 88 && octets[2] === 99) return { family: 4, classification: 'reserved', embeddedAddress: null };
  if (a === 240) return { family: 4, classification: 'reserved', embeddedAddress: null };
  return { family: 4, classification: 'public', embeddedAddress: null };
}

function classifyIpv6(address) {
  const value = ipv6Value(address);
  if (value === null) return { family: 6, classification: 'unknown', embeddedAddress: null };

  const embedded = ipv4FromIpv6(value);
  if ((value >> 32n) === 0xffffn) return { ...classifyIpv4(embedded), family: 6, embeddedAddress: embedded };
  if ((value >> 32n) === 0n && (value & 0xffffffffn) !== 0n) return { family: 6, classification: 'embedded-translated', embeddedAddress: embedded };

  const nat64 = (value >> 96n) === 0x64ff9bn && ((value >> 32n) & 0xffffffffffffffffn) === 0n;
  if (nat64) return { ...classifyIpv4(embedded), family: 6, embeddedAddress: embedded };
  if (value === 0n) return { family: 6, classification: 'unspecified', embeddedAddress: null };
  if (value === 1n) return { family: 6, classification: 'loopback', embeddedAddress: null };
  const uniqueLocalStart = 0xfc00n << 112n;
  const uniqueLocalEnd = 0xfdffn << 112n;
  if (value >= uniqueLocalStart && value <= uniqueLocalEnd) return { family: 6, classification: 'private', embeddedAddress: null };
  const linkLocalStart = 0xfe80n << 112n;
  const linkLocalEnd = 0xfebfn << 112n;
  if (value >= linkLocalStart && value <= linkLocalEnd) return { family: 6, classification: 'link-local', embeddedAddress: null };
  if ((value >> 120n) === 0xffn) return { family: 6, classification: 'multicast', embeddedAddress: null };
  if ((value >> 112n) === 0x2002n || (value >> 96n) === 0x20010000n) return { family: 6, classification: 'embedded-translated', embeddedAddress: null };
  if ((value >> 96n) === 0x20010db8n) return { family: 6, classification: 'reserved', embeddedAddress: null };
  return { family: 6, classification: 'public', embeddedAddress: null };
}

function ipv4FromIpv6(value) {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 0xffn)).join('.');
}

function ipv6Value(address) {
  let normalized = address.toLowerCase();
  const dottedTail = normalized.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dottedTail) {
    const octets = dottedTail[2].split('.').map(Number);
    if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    normalized = `${dottedTail[1]}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const split = normalized.split('::');
  if (split.length > 2) return null;
  const left = split[0] ? split[0].split(':') : [];
  const right = split.length === 2 && split[1] ? split[1].split(':') : [];
  if (left.some((part) => !/^[0-9a-f]{1,4}$/.test(part)) || right.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  const parts = split.length === 2
    ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
    : left;
  if (parts.length !== 8) return null;
  return parts.reduce((value, part) => (value << 16n) + BigInt(`0x${part}`), 0n);
}

function addressInCidr(address, cidr) {
  if (typeof cidr !== 'string') return false;
  const parts = cidr.split('/');
  if (parts.length !== 2 || !/^\d+$/.test(parts[1])) return false;
  const [network, prefixText] = parts;
  const family = net.isIP(address);
  if (!family || net.isIP(network) !== family) return false;
  const prefix = Number(prefixText);
  const maxBits = family === 4 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxBits) return false;
  const value = family === 4
    ? ipv4Value(address)
    : ipv6Value(address);
  const networkValue = family === 4
    ? ipv4Value(network)
    : ipv6Value(network);
  if (value === null || networkValue === null) return false;
  const shift = BigInt(maxBits - prefix);
  return (value >> shift) === (networkValue >> shift);
}

function validCidr(cidr) {
  if (typeof cidr !== 'string') return false;
  const parts = cidr.split('/');
  if (parts.length !== 2 || !/^\d+$/.test(parts[1])) return false;
  const [network, prefixText] = parts;
  const family = net.isIP(network);
  const maximum = family === 4 ? 32 : family === 6 ? 128 : 0;
  const prefix = Number(prefixText);
  return Boolean(family) && Number.isInteger(prefix) && prefix >= 0 && prefix <= maximum;
}

function ipv4Value(address) {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return octets.reduce((value, part) => (value << 8n) + BigInt(part), 0n);
}
