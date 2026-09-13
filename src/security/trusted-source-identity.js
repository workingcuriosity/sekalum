// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import crypto from 'node:crypto';
import { isIP } from 'node:net';

function sha256(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function header(req, name) {
  const value = req?.headers?.[name];
  return typeof value === 'string' ? value.trim() : null;
}

function normalizeAddress(value) {
  if (typeof value !== 'string') return null;
  let address = value.trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (address.startsWith('::ffff:') && isIP(address.slice(7)) === 4) address = address.slice(7);
  return isIP(address) ? address : null;
}

function classifyAddress(address) {
  if (!address) return 'unknown';
  if (isIP(address) === 4) {
    const [first, second] = address.split('.').map(Number);
    if (first === 127) return 'loopback';
    if (first === 169 && second === 254) return 'link-local';
    if (first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168)) return 'private';
    return 'public';
  }
  if (address === '::1') return 'loopback';
  if (/^fe[89ab][0-9a-f]:/i.test(address)) return 'link-local';
  if (/^(?:fc|fd)[0-9a-f]{2}:/i.test(address)) return 'unique-local';
  return 'public';
}

function forwardedForValues(req) {
  const value = header(req, 'x-forwarded-for');
  return value ? value.split(',').map(normalizeAddress).filter(Boolean) : [];
}

function forwardedForParameter(req) {
  const value = header(req, 'forwarded');
  if (!value) return [];
  return value.split(',').map((entry) => {
    const match = entry.match(/(?:^|;)\s*for=([^;]+)/i);
    return match ? normalizeAddress(match[1].replace(/^"|"$/g, '')) : null;
  }).filter(Boolean);
}

function socketAddress(req) {
  return normalizeAddress(req?.socket?.remoteAddress ?? req?.connection?.remoteAddress);
}

export function resolveTrustedSourceIdentity(req, { trustedProxy = false } = {}) {
  const socket = socketAddress(req);
  const xff = forwardedForValues(req);
  const forwarded = forwardedForParameter(req);
  const proxyConfigured = trustedProxy !== false && trustedProxy !== null && trustedProxy !== undefined;

  if (proxyConfigured && xff.length > 0 && forwarded.length > 0 && xff[0] !== forwarded[0]) {
    const error = new Error('Conflicting trusted proxy source signals');
    error.code = 'TRUSTED_PROXY_SOURCE_CONFLICT';
    error.statusCode = 400;
    throw error;
  }

  const expressIp = normalizeAddress(req?.ip);
  const address = proxyConfigured ? (expressIp ?? xff[0] ?? socket) : socket;
  const classification = classifyAddress(address);
  const canonical = address ? `${classification}:${address}` : 'unknown';
  return Object.freeze({
    classification,
    family: address ? `IPv${isIP(address)}` : 'unknown',
    identity: `source:${sha256(canonical)}`,
    address: address ?? null
  });
}

export function sourceIdentityKey(req, options = {}) {
  return resolveTrustedSourceIdentity(req, options).identity;
}
