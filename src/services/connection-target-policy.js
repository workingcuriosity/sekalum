import { lookup as dnsLookup } from 'node:dns/promises';
import net from 'node:net';

export class ConnectionTargetPolicy {
  constructor({ lookup = dnsLookup, allowPrivateNetworks = false } = {}) {
    this.lookup = lookup;
    this.allowPrivateNetworks = Boolean(allowPrivateNetworks);
  }

  async resolveAllowedTarget(host) {
    const normalizedHost = this.#normalizeHost(host);
    const addresses = net.isIP(normalizedHost)
      ? [{ address: normalizedHost }]
      : await this.#lookup(normalizedHost);

    if (addresses.length === 0 || addresses.some(({ address }) => this.#isBlocked(address))) {
      throw this.#blockedTargetError();
    }

    return Object.freeze({ host: normalizedHost, address: addresses[0].address });
  }

  #normalizeHost(host) {
    if (typeof host !== 'string' || host.trim() === '') throw this.#blockedTargetError();

    const normalizedHost = host.trim();
    if (normalizedHost.includes('/') || normalizedHost.includes('://') || normalizedHost.includes('@')) {
      throw this.#blockedTargetError();
    }

    return normalizedHost;
  }

  async #lookup(host) {
    try {
      const result = await this.lookup(host, { all: true, verbatim: true });
      return Array.isArray(result) ? result : [result];
    } catch {
      const error = new Error('Connection target could not be resolved');
      error.code = 'CREDENTIAL_CONNECTION_DNS_FAILED';
      error.statusCode = 422;
      error.messageKey = 'credential.connectionTest.dnsFailed';
      error.details = { field: 'host' };
      throw error;
    }
  }

  #isBlocked(address) {
    const family = net.isIP(address);
    if (family === 4) return this.#isBlockedIpv4(address);
    if (family === 6) return this.#isBlockedIpv6(address);
    return true;
  }

  #isBlockedIpv4(address) {
    const [first, second] = address.split('.').map(Number);

    if (first === 0 || first === 127 || first >= 224) return true;
    if (first === 169 && second === 254) return true;
    if (first === 100 && second >= 64 && second <= 127) return true;
    if (first === 198 && (second === 18 || second === 19)) return true;

    if (!this.allowPrivateNetworks) {
      return first === 10
        || (first === 172 && second >= 16 && second <= 31)
        || (first === 192 && second === 168);
    }

    return false;
  }

  #isBlockedIpv6(address) {
    const normalized = address.toLowerCase();
    if (normalized.startsWith('::ffff:')) return this.#isBlockedIpv4(normalized.slice('::ffff:'.length));

    const value = this.#ipv6Value(normalized);
    if (value === null) return true;

    // IPv4-mapped IPv6 addresses may be written in expanded hexadecimal form
    // (for example 0:0:0:0:0:ffff:c0a8:0101), which net.isIP reports as IPv6.
    // Apply the IPv4 policy to the embedded address before evaluating IPv6
    // ranges so private/metadata targets cannot bypass the boundary.
    if ((value >> 32n) === 0xffffn) {
      const octets = [24n, 16n, 8n, 0n].map((shift) => Number((value >> BigInt(shift)) & 0xffn));
      return this.#isBlockedIpv4(octets.join('.'));
    }

    const uniqueLocalStart = 0xfc00n << 112n;
    const linkLocalStart = 0xfe80n << 112n;
    const linkLocalEnd = 0xfebfn << 112n;

    if (value === 0n || value === 1n) return true;
    if (value >= uniqueLocalStart && value < (0xfe00n << 112n)) return !this.allowPrivateNetworks;
    if (value >= linkLocalStart && value <= linkLocalEnd) return true;

    return false;
  }

  #ipv6Value(address) {
    const split = address.split('::');
    if (split.length > 2) return null;

    const [left, right = ''] = split;
    const leftParts = left ? left.split(':') : [];
    const rightParts = right ? right.split(':') : [];
    const missing = 8 - leftParts.length - rightParts.length;
    const parts = address.includes('::')
      ? [...leftParts, ...Array(Math.max(missing, 0)).fill('0'), ...rightParts]
      : leftParts;

    if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) return null;

    return parts.reduce((value, part) => (value << 16n) + BigInt(`0x${part}`), 0n);
  }

  #blockedTargetError() {
    const error = new Error('Connection target is not allowed');
    error.code = 'CREDENTIAL_CONNECTION_TARGET_BLOCKED';
    error.statusCode = 400;
    error.messageKey = 'credential.connectionTest.targetBlocked';
    return error;
  }
}
