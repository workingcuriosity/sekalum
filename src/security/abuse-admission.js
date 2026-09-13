// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import crypto from 'node:crypto';

export const AbuseAdmissionResult = Object.freeze({
  ALLOW: 'ALLOW',
  THROTTLE: 'THROTTLE',
  CONCURRENCY_BLOCK: 'CONCURRENCY_BLOCK'
});

export const AbusePolicyClass = Object.freeze({
  PRE_AUTH_FAILURE: 'PRE_AUTH_FAILURE',
  BOOTSTRAP: 'BOOTSTRAP',
  MANAGEMENT_AUTHENTICATED: 'MANAGEMENT_AUTHENTICATED',
  MANAGEMENT_MUTATION: 'MANAGEMENT_MUTATION',
  SECURITY_CONTAINMENT: 'SECURITY_CONTAINMENT',
  API_TOKEN_CREATE: 'API_TOKEN_CREATE',
  API_TOKEN_REVOKE: 'API_TOKEN_REVOKE',
  CONSUMER_DISCOVERY: 'CONSUMER_DISCOVERY',
  CONSUMER_RESOLVE: 'CONSUMER_RESOLVE',
  CONSUMER_BATCH_RESOLVE: 'CONSUMER_BATCH_RESOLVE',
  OAUTH_START: 'OAUTH_START',
  OAUTH_CALLBACK_INVALID: 'OAUTH_CALLBACK_INVALID',
  OAUTH_CALLBACK_VALID: 'OAUTH_CALLBACK_VALID',
  PROVIDER_HEALTH_OR_EXPENSIVE_MANAGEMENT: 'PROVIDER_HEALTH_OR_EXPENSIVE_MANAGEMENT',
  GLOBAL_EMERGENCY_BOUND: 'GLOBAL_EMERGENCY_BOUND'
});

const MAX_SAFE_DURATION_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_TOTAL_KEYS = 10_000;
const DEFAULT_MAX_CONCURRENCY_LEASES = 1_024;
const DEFAULT_IDLE_TTL_MS = 15 * 60 * 1000;
const DEFAULT_CLEANUP_INTERVAL_MS = 60 * 1000;
const DEFAULT_MAX_LEASE_DURATION_MS = 30 * 1000;
const DEFAULT_DOMAIN_QUOTAS = Object.freeze({
  source: 4_000,
  actor: 2_000,
  consumer: 2_000,
  token: 2_000,
  provider: 1_000,
  global: 64,
  containment: 512
});

const POLICY_DEFAULTS = Object.freeze({
  [AbusePolicyClass.PRE_AUTH_FAILURE]: Object.freeze({ capacity: 20, refillEveryMs: 3_000, minRetryAfterSeconds: 3, maxRetryAfterSeconds: 60, concurrency: 0 }),
  [AbusePolicyClass.BOOTSTRAP]: Object.freeze({ capacity: 3, refillEveryMs: 200_000, minRetryAfterSeconds: 60, maxRetryAfterSeconds: 600, concurrency: 1 }),
  [AbusePolicyClass.MANAGEMENT_AUTHENTICATED]: Object.freeze({ capacity: 120, refillEveryMs: 500, minRetryAfterSeconds: 1, maxRetryAfterSeconds: 60, concurrency: 0 }),
  [AbusePolicyClass.MANAGEMENT_MUTATION]: Object.freeze({ capacity: 30, refillEveryMs: 2_000, minRetryAfterSeconds: 2, maxRetryAfterSeconds: 60, concurrency: 8 }),
  [AbusePolicyClass.SECURITY_CONTAINMENT]: Object.freeze({ capacity: 120, refillEveryMs: 1_000, minRetryAfterSeconds: 1, maxRetryAfterSeconds: 60, concurrency: 16, containmentCapacity: 500, containmentRefillEveryMs: 200 }),
  [AbusePolicyClass.API_TOKEN_CREATE]: Object.freeze({ capacity: 10, refillEveryMs: 60_000, minRetryAfterSeconds: 60, maxRetryAfterSeconds: 600, concurrency: 2 }),
  [AbusePolicyClass.API_TOKEN_REVOKE]: Object.freeze({ capacity: 120, refillEveryMs: 2_000, minRetryAfterSeconds: 1, maxRetryAfterSeconds: 60, concurrency: 16 }),
  [AbusePolicyClass.CONSUMER_DISCOVERY]: Object.freeze({ capacity: 60, refillEveryMs: 1_000, minRetryAfterSeconds: 1, maxRetryAfterSeconds: 60, concurrency: 8 }),
  [AbusePolicyClass.CONSUMER_RESOLVE]: Object.freeze({ capacity: 120, refillEveryMs: 500, minRetryAfterSeconds: 1, maxRetryAfterSeconds: 60, concurrency: 8 }),
  [AbusePolicyClass.CONSUMER_BATCH_RESOLVE]: Object.freeze({ capacity: 60, refillEveryMs: 1_000, minRetryAfterSeconds: 1, maxRetryAfterSeconds: 60, concurrency: 2 }),
  [AbusePolicyClass.OAUTH_START]: Object.freeze({ capacity: 10, refillEveryMs: 60_000, minRetryAfterSeconds: 60, maxRetryAfterSeconds: 600, concurrency: 2 }),
  [AbusePolicyClass.OAUTH_CALLBACK_INVALID]: Object.freeze({ capacity: 60, refillEveryMs: 1_000, minRetryAfterSeconds: 1, maxRetryAfterSeconds: 60, concurrency: 0 }),
  [AbusePolicyClass.OAUTH_CALLBACK_VALID]: Object.freeze({ capacity: 30, refillEveryMs: 20_000, minRetryAfterSeconds: 20, maxRetryAfterSeconds: 600, concurrency: 2 }),
  [AbusePolicyClass.PROVIDER_HEALTH_OR_EXPENSIVE_MANAGEMENT]: Object.freeze({ capacity: 20, refillEveryMs: 3_000, minRetryAfterSeconds: 3, maxRetryAfterSeconds: 60, concurrency: 2 }),
  [AbusePolicyClass.GLOBAL_EMERGENCY_BOUND]: Object.freeze({ capacity: 1_000, refillEveryMs: 1_000 / 17, minRetryAfterSeconds: 1, maxRetryAfterSeconds: 60, concurrency: DEFAULT_MAX_CONCURRENCY_LEASES })
});

const POLICY_KEYS = Object.freeze(new Set(Object.values(AbusePolicyClass)));
const POLICY_CONFIG_FIELDS = Object.freeze([
  ['CAPACITY', 'capacity', { min: 1, max: 1_000_000, integer: true }],
  ['REFILL_EVERY_MS', 'refillEveryMs', { min: 1, max: MAX_SAFE_DURATION_MS }],
  ['MIN_RETRY_AFTER_SECONDS', 'minRetryAfterSeconds', { min: 1, max: 3_600, integer: true }],
  ['MAX_RETRY_AFTER_SECONDS', 'maxRetryAfterSeconds', { min: 1, max: 86_400, integer: true }],
  ['CONCURRENCY', 'concurrency', { min: 0, max: DEFAULT_MAX_CONCURRENCY_LEASES, integer: true }],
  ['CONTAINMENT_CAPACITY', 'containmentCapacity', { min: 1, max: 1_000_000, integer: true }],
  ['CONTAINMENT_REFILL_EVERY_MS', 'containmentRefillEveryMs', { min: 1, max: MAX_SAFE_DURATION_MS }]
]);
const DOMAIN_NAMES = Object.freeze(['source', 'actor', 'consumer', 'token', 'provider', 'global', 'containment']);

function finiteNumber(value, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER, integer = false } = {}) {
  const number = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(number) || number < min || number > max || (integer && !Number.isInteger(number))) return fallback;
  return number;
}

function configuredNumber(config, key, fallback, bounds) {
  const raw = config?.get?.(key, undefined);
  if (raw === undefined || raw === null || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < bounds.min || value > bounds.max || (bounds.integer && !Number.isInteger(value))) {
    throw new Error(`INVALID_ABUSE_CONFIGURATION: ${key}`);
  }
  return value;
}

export function abuseAdmissionOptionsFromConfig(config) {
  const maxTotalKeys = configuredNumber(config, 'ABUSE_MAX_TOTAL_KEYS', DEFAULT_MAX_TOTAL_KEYS, { min: 1, max: 1_000_000, integer: true });
  const options = {
    maxTotalKeys,
    idleTtlMs: configuredNumber(config, 'ABUSE_IDLE_TTL_MS', DEFAULT_IDLE_TTL_MS, { min: 1, max: MAX_SAFE_DURATION_MS }),
    cleanupIntervalMs: configuredNumber(config, 'ABUSE_CLEANUP_INTERVAL_MS', DEFAULT_CLEANUP_INTERVAL_MS, { min: 1, max: MAX_SAFE_DURATION_MS }),
    maxConcurrencyLeases: configuredNumber(config, 'ABUSE_MAX_CONCURRENCY_LEASES', DEFAULT_MAX_CONCURRENCY_LEASES, { min: 1, max: 1_000_000, integer: true }),
    maxLeaseDurationMs: configuredNumber(config, 'ABUSE_MAX_LEASE_DURATION_MS', DEFAULT_MAX_LEASE_DURATION_MS, { min: 1, max: DEFAULT_MAX_LEASE_DURATION_MS }),
    domainQuotas: {}
  };

  for (const domain of DOMAIN_NAMES) {
    const key = `ABUSE_${domain.toUpperCase()}_QUOTA`;
    const defaultQuota = Math.min(DEFAULT_DOMAIN_QUOTAS[domain] ?? maxTotalKeys, maxTotalKeys);
    options.domainQuotas[domain] = configuredNumber(config, key, defaultQuota, { min: 1, max: maxTotalKeys, integer: true });
  }

  const policyOverrides = {};
  for (const policyClass of Object.values(AbusePolicyClass)) {
    const envPolicyName = policyClass;
    const override = {};
    for (const [suffix, field, bounds] of POLICY_CONFIG_FIELDS) {
      const key = `ABUSE_${envPolicyName}_${suffix}`;
      const value = configuredNumber(config, key, undefined, bounds);
      if (value !== undefined) override[field] = value;
    }
    if (Object.keys(override).length > 0) policyOverrides[policyClass] = override;
  }
  options.policyOverrides = policyOverrides;
  return Object.freeze({ ...options, domainQuotas: Object.freeze(options.domainQuotas), policyOverrides: Object.freeze(policyOverrides) });
}

function normalizeClockValue(value) {
  const number = value instanceof Date ? value.getTime() : Number(value);
  return Number.isFinite(number) ? number : Date.now();
}

function digest(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function boundedIdentity(value, fallback = 'unknown') {
  if (typeof value !== 'string' || value.trim() === '') return fallback;
  const normalized = value.trim();
  return normalized.length <= 256 ? normalized : `${fallback}:${digest(normalized)}`;
}

function policyConfig(policy, override = {}) {
  const source = { ...policy, ...(override ?? {}) };
  const concurrency = finiteNumber(source.concurrency, policy.concurrency, { min: 0, max: DEFAULT_MAX_CONCURRENCY_LEASES, integer: true });
  return Object.freeze({
    capacity: finiteNumber(source.capacity, policy.capacity, { min: 1, max: 1_000_000, integer: true }),
    refillEveryMs: finiteNumber(source.refillEveryMs, policy.refillEveryMs, { min: 1, max: MAX_SAFE_DURATION_MS }),
    minRetryAfterSeconds: finiteNumber(source.minRetryAfterSeconds, policy.minRetryAfterSeconds, { min: 1, max: 3_600, integer: true }),
    maxRetryAfterSeconds: Math.max(
      finiteNumber(source.minRetryAfterSeconds, policy.minRetryAfterSeconds, { min: 1, max: 3_600, integer: true }),
      finiteNumber(source.maxRetryAfterSeconds, policy.maxRetryAfterSeconds, { min: 1, max: 86_400, integer: true })
    ),
    concurrency,
    containmentCapacity: source.containmentCapacity === undefined
      ? policy.containmentCapacity
      : finiteNumber(source.containmentCapacity, policy.containmentCapacity, { min: 1, max: 1_000_000, integer: true }),
    containmentRefillEveryMs: source.containmentRefillEveryMs === undefined
      ? policy.containmentRefillEveryMs
      : finiteNumber(source.containmentRefillEveryMs, policy.containmentRefillEveryMs, { min: 1, max: MAX_SAFE_DURATION_MS })
  });
}

function descriptor(domain, identity, config, policyClass) {
  const normalized = boundedIdentity(identity);
  return {
    domain,
    identity: normalized,
    key: `${domain}:${policyClass}:${digest(`${domain}\u0000${policyClass}\u0000${normalized}`)}`,
    config,
    policyClass
  };
}

export class AbuseAdmission {
  constructor({
    clock = () => Date.now(),
    maxTotalKeys = DEFAULT_MAX_TOTAL_KEYS,
    idleTtlMs = DEFAULT_IDLE_TTL_MS,
    cleanupIntervalMs = DEFAULT_CLEANUP_INTERVAL_MS,
    maxConcurrencyLeases = DEFAULT_MAX_CONCURRENCY_LEASES,
    maxLeaseDurationMs = DEFAULT_MAX_LEASE_DURATION_MS,
    domainQuotas = DEFAULT_DOMAIN_QUOTAS,
    policyOverrides = {}
  } = {}) {
    if (typeof clock !== 'function') throw new Error('AbuseAdmission requires a clock function');
    this.clock = clock;
    this.maxTotalKeys = finiteNumber(maxTotalKeys, DEFAULT_MAX_TOTAL_KEYS, { min: 1, max: 1_000_000, integer: true });
    this.idleTtlMs = finiteNumber(idleTtlMs, DEFAULT_IDLE_TTL_MS, { min: 1, max: MAX_SAFE_DURATION_MS });
    this.cleanupIntervalMs = finiteNumber(cleanupIntervalMs, DEFAULT_CLEANUP_INTERVAL_MS, { min: 1, max: MAX_SAFE_DURATION_MS });
    this.maxConcurrencyLeases = finiteNumber(maxConcurrencyLeases, DEFAULT_MAX_CONCURRENCY_LEASES, { min: 1, max: 1_000_000, integer: true });
    this.maxLeaseDurationMs = Math.min(
      finiteNumber(maxLeaseDurationMs, DEFAULT_MAX_LEASE_DURATION_MS, { min: 1, max: MAX_SAFE_DURATION_MS }),
      DEFAULT_MAX_LEASE_DURATION_MS
    );
    this.domainQuotas = Object.freeze({
      ...DEFAULT_DOMAIN_QUOTAS,
      ...Object.fromEntries(Object.entries(domainQuotas ?? {}).map(([key, value]) => [
        key,
        finiteNumber(value, DEFAULT_DOMAIN_QUOTAS[key] ?? this.maxTotalKeys, { min: 1, max: this.maxTotalKeys, integer: true })
      ]))
    });
    this.policies = Object.freeze(Object.fromEntries(Object.entries(POLICY_DEFAULTS).map(([key, value]) => [key, policyConfig(value, policyOverrides?.[key])] )));
    this.buckets = new Map();
    this.leases = new Map();
    this.activeLeasesByPolicy = new Map();
    this.lastCleanupAt = normalizeClockValue(this.clock());
    this.sequence = 0;
  }

  decide(input = {}) {
    const policyClass = input.policyClass ?? input.operationClass;
    if (!POLICY_KEYS.has(policyClass)) return this.#failure('UNKNOWN_POLICY', 'THROTTLE');

    const now = normalizeClockValue(this.clock());
    this.#cleanup(now);
    const cost = this.#normalizeCost(input.cost);
    const descriptors = this.#descriptors(policyClass, input);
    const pending = [];

    try {
      for (const item of descriptors) {
        const bucket = this.#bucket(item, now);
        const available = this.#available(bucket, item.config, now);
        if (available < cost) {
          return this.#throttled(item.config, this.#waitMs(available, cost, item.config), policyClass, item.domain);
        }
        pending.push({ bucket, item });
      }

      for (const { bucket, item } of pending) {
        bucket.tokens = Math.max(0, this.#available(bucket, item.config, now) - cost);
        bucket.lastUsedAt = now;
        bucket.lastRefillAt = now;
      }
      return {
        result: AbuseAdmissionResult.ALLOW,
        decision: AbuseAdmissionResult.ALLOW,
        retryAfterSeconds: 0,
        policyClass,
        reasonClass: 'ADMITTED',
        cost
      };
    } catch (error) {
      return this.#failure(error.code === 'ADMISSION_STATE_CAPACITY_EXHAUSTED' ? error.code : 'INTERNAL_ADMISSION_FAILURE', 'THROTTLE', policyClass);
    }
  }

  admit(input = {}) {
    const decision = this.decide(input);
    if (decision.result !== AbuseAdmissionResult.ALLOW) return decision;

    const policyClass = input.policyClass ?? input.operationClass;
    const descriptors = this.#descriptors(policyClass, input);
    const concurrency = this.#acquireLease(descriptors, normalizeClockValue(this.clock()), policyClass);
    if (concurrency.result !== AbuseAdmissionResult.ALLOW) return concurrency;
    return { ...decision, ...concurrency };
  }

  reserve(input = {}) {
    const policyClass = input.policyClass ?? input.operationClass;
    if (!POLICY_KEYS.has(policyClass)) return this.#failure('UNKNOWN_POLICY', 'THROTTLE');
    const now = normalizeClockValue(this.clock());
    this.#cleanup(now);
    return this.#acquireLease(this.#descriptors(policyClass, input), now, policyClass);
  }

  release(leaseId) {
    const lease = this.leases.get(leaseId);
    if (!lease) return false;
    this.leases.delete(leaseId);
    for (const policyClass of lease.policyClasses) {
      const count = this.activeLeasesByPolicy.get(policyClass) ?? 0;
      this.activeLeasesByPolicy.set(policyClass, Math.max(0, count - 1));
    }
    return true;
  }

  reset() {
    this.buckets.clear();
    for (const leaseId of [...this.leases.keys()]) this.release(leaseId);
    this.activeLeasesByPolicy.clear();
    this.lastCleanupAt = normalizeClockValue(this.clock());
  }

  snapshot() {
    return Object.freeze({
      totalKeys: this.buckets.size,
      activeLeases: this.leases.size,
      buckets: [...this.buckets.entries()].map(([key, value]) => Object.freeze({ key, domain: value.domain, tokens: value.tokens, lastUsedAt: value.lastUsedAt })),
      activeLeasesByPolicy: Object.fromEntries(this.activeLeasesByPolicy)
    });
  }

  #descriptors(policyClass, input) {
    const config = this.policies[policyClass];
    const source = input.sourceIdentity ?? input.source ?? 'unknown';
    const actor = input.actorIdentity ?? input.actorUserId ?? 'unknown';
    const consumer = input.consumerIdentity ?? input.consumerId ?? input.apiTokenIdentity ?? 'unknown';
    const token = input.apiTokenIdentity ?? input.apiTokenId ?? 'unknown';
    const provider = input.providerIdentity ?? input.providerKey ?? 'unknown';
    const descriptors = [];
    const isPreAuth = input.phase === 'PRE_AUTH'
      || policyClass === AbusePolicyClass.PRE_AUTH_FAILURE
      || policyClass === AbusePolicyClass.BOOTSTRAP
      || policyClass === AbusePolicyClass.OAUTH_CALLBACK_INVALID;

    switch (policyClass) {
      case AbusePolicyClass.PRE_AUTH_FAILURE:
      case AbusePolicyClass.OAUTH_CALLBACK_INVALID:
        descriptors.push(descriptor('source', source, config, policyClass));
        break;
      case AbusePolicyClass.BOOTSTRAP:
        descriptors.push(descriptor('source', source, config, policyClass));
        break;
      case AbusePolicyClass.MANAGEMENT_AUTHENTICATED:
      case AbusePolicyClass.MANAGEMENT_MUTATION:
      case AbusePolicyClass.API_TOKEN_CREATE:
      case AbusePolicyClass.API_TOKEN_REVOKE:
        descriptors.push(descriptor('source', source, config, policyClass));
        descriptors.push(descriptor('actor', actor, config, policyClass));
        if (policyClass === AbusePolicyClass.API_TOKEN_REVOKE) descriptors.push(descriptor('token', token, config, policyClass));
        break;
      case AbusePolicyClass.SECURITY_CONTAINMENT:
        descriptors.push(descriptor('source', source, config, policyClass));
        descriptors.push(descriptor('actor', actor, config, policyClass));
        descriptors.push(descriptor('containment', 'global-containment', { ...config, capacity: config.containmentCapacity, refillEveryMs: config.containmentRefillEveryMs }, policyClass));
        break;
      case AbusePolicyClass.CONSUMER_DISCOVERY:
        descriptors.push(descriptor('source', source, config, policyClass));
        descriptors.push(descriptor('consumer', consumer, config, policyClass));
        break;
      case AbusePolicyClass.CONSUMER_RESOLVE:
      case AbusePolicyClass.CONSUMER_BATCH_RESOLVE:
        descriptors.push(descriptor('source', source, config, policyClass));
        descriptors.push(descriptor('consumer', consumer, config, policyClass));
        descriptors.push(descriptor('token', token, config, policyClass));
        break;
      case AbusePolicyClass.OAUTH_START:
      case AbusePolicyClass.OAUTH_CALLBACK_VALID:
        descriptors.push(descriptor('source', source, config, policyClass));
        descriptors.push(descriptor('actor', actor, config, policyClass));
        descriptors.push(descriptor('provider', provider, config, policyClass));
        break;
      case AbusePolicyClass.PROVIDER_HEALTH_OR_EXPENSIVE_MANAGEMENT:
        descriptors.push(descriptor('source', source, config, policyClass));
        descriptors.push(descriptor('actor', actor, config, policyClass));
        descriptors.push(descriptor('provider', provider, config, policyClass));
        break;
      case AbusePolicyClass.GLOBAL_EMERGENCY_BOUND:
        break;
      default:
        break;
    }

    if (isPreAuth) {
      descriptors.push(descriptor('global', 'pre-auth-global', this.policies[AbusePolicyClass.GLOBAL_EMERGENCY_BOUND], AbusePolicyClass.GLOBAL_EMERGENCY_BOUND));
    } else if (policyClass !== AbusePolicyClass.SECURITY_CONTAINMENT && policyClass !== AbusePolicyClass.GLOBAL_EMERGENCY_BOUND) {
      descriptors.push(descriptor('global', 'authenticated-operational-global', this.policies[AbusePolicyClass.GLOBAL_EMERGENCY_BOUND], AbusePolicyClass.GLOBAL_EMERGENCY_BOUND));
    }
    return descriptors;
  }

  #normalizeCost(cost) {
    return finiteNumber(cost, 1, { min: 1, max: 20, integer: true });
  }

  #bucket(item, now) {
    const existing = this.buckets.get(item.key);
    if (existing) {
      existing.lastUsedAt = now;
      return existing;
    }

    const domainCount = [...this.buckets.values()].filter((bucket) => bucket.domain === item.domain).length;
    const domainQuota = this.domainQuotas[item.domain] ?? this.maxTotalKeys;
    if (domainCount >= domainQuota || this.buckets.size >= this.maxTotalKeys) {
      const overflowKey = `${item.domain}:${item.policyClass}:overflow`;
      const overflow = this.buckets.get(overflowKey);
      if (overflow) return overflow;
      if (this.buckets.size >= this.maxTotalKeys) {
        const error = new Error('Admission state capacity exhausted');
        error.code = 'ADMISSION_STATE_CAPACITY_EXHAUSTED';
        throw error;
      }
      const bucket = { domain: item.domain, tokens: item.config.capacity, lastRefillAt: now, lastUsedAt: now };
      this.buckets.set(overflowKey, bucket);
      return bucket;
    }

    const bucket = { domain: item.domain, tokens: item.config.capacity, lastRefillAt: now, lastUsedAt: now };
    this.buckets.set(item.key, bucket);
    return bucket;
  }

  #available(bucket, config, now) {
    const elapsed = Math.max(0, now - bucket.lastRefillAt);
    const refill = elapsed / config.refillEveryMs;
    return Math.min(config.capacity, bucket.tokens + refill);
  }

  #waitMs(available, cost, config) {
    const missing = Math.max(0, cost - available);
    return Math.max(1, missing * config.refillEveryMs);
  }

  #throttled(config, waitMs, policyClass, domain) {
    const seconds = Math.min(
      config.maxRetryAfterSeconds,
      Math.max(config.minRetryAfterSeconds, Math.ceil(waitMs / 1000))
    );
    return {
      result: AbuseAdmissionResult.THROTTLE,
      decision: AbuseAdmissionResult.THROTTLE,
      retryAfterSeconds: Math.max(1, seconds),
      policyClass,
      reasonClass: domain === 'global' ? 'GLOBAL_EMERGENCY_BOUND' : 'NORMAL_THROTTLE'
    };
  }

  #acquireLease(descriptors, now, policyClass) {
    const policies = [...new Set(descriptors.map((item) => item.policyClass))]
      .map((key) => ({ key, config: this.policies[key] ?? this.policies[policyClass] }))
      .filter(({ config }) => config.concurrency > 0);
    const containmentPolicy = AbusePolicyClass.SECURITY_CONTAINMENT;
    const containmentReserve = Math.min(
      Math.max(0, this.maxConcurrencyLeases - 1),
      this.policies[containmentPolicy].concurrency
    );
    const preAuthLeasePolicy = AbusePolicyClass.BOOTSTRAP;
    const preAuthReserve = Math.min(
      Math.max(0, this.maxConcurrencyLeases - containmentReserve - 1),
      this.policies[preAuthLeasePolicy].concurrency
    );
    const activeContainment = this.activeLeasesByPolicy.get(containmentPolicy) ?? 0;
    const activePreAuth = this.activeLeasesByPolicy.get(preAuthLeasePolicy) ?? 0;
    const activeOperational = this.leases.size - activeContainment - activePreAuth;
    const isContainment = policyClass === containmentPolicy;
    const isPreAuthLease = policyClass === preAuthLeasePolicy;
    if ((isContainment && containmentReserve > 0 && activeContainment >= containmentReserve)
      || (isPreAuthLease && preAuthReserve > 0 && activePreAuth >= preAuthReserve)
      || (!isContainment && !isPreAuthLease && activeOperational >= this.maxConcurrencyLeases - containmentReserve - preAuthReserve)) {
      return {
        result: AbuseAdmissionResult.CONCURRENCY_BLOCK,
        decision: AbuseAdmissionResult.CONCURRENCY_BLOCK,
        retryAfterSeconds: 1,
        policyClass,
        reasonClass: 'CONCURRENCY_EXHAUSTION'
      };
    }
    for (const { key, config } of policies) {
      if ((this.activeLeasesByPolicy.get(key) ?? 0) >= Math.min(config.concurrency, this.maxConcurrencyLeases)) {
        return {
          result: AbuseAdmissionResult.CONCURRENCY_BLOCK,
          decision: AbuseAdmissionResult.CONCURRENCY_BLOCK,
          retryAfterSeconds: 1,
          policyClass,
          reasonClass: 'CONCURRENCY_EXHAUSTION'
        };
      }
    }
    const leaseId = `lease-${++this.sequence}-${digest(`${policyClass}\u0000${now}\u0000${this.sequence}`).slice(0, 16)}`;
    const lease = {
      policyClasses: policies.map(({ key }) => key),
      expiresAt: now + this.maxLeaseDurationMs
    };
    this.leases.set(leaseId, lease);
    for (const { key } of policies) this.activeLeasesByPolicy.set(key, (this.activeLeasesByPolicy.get(key) ?? 0) + 1);
    return { result: AbuseAdmissionResult.ALLOW, decision: AbuseAdmissionResult.ALLOW, leaseId, leaseExpiresAt: lease.expiresAt };
  }

  #cleanup(now) {
    for (const [leaseId, lease] of this.leases.entries()) {
      if (lease.expiresAt <= now) this.release(leaseId);
    }
    if (now - this.lastCleanupAt < this.cleanupIntervalMs) return;
    this.lastCleanupAt = now;
    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastUsedAt > this.idleTtlMs) this.buckets.delete(key);
    }
  }

  #failure(reasonClass, result = AbuseAdmissionResult.THROTTLE, policyClass = null) {
    return {
      result,
      decision: result,
      retryAfterSeconds: 1,
      policyClass,
      reasonClass
    };
  }
}

export const ABUSE_ADMISSION_DEFAULTS = Object.freeze({
  maxTotalKeys: DEFAULT_MAX_TOTAL_KEYS,
  idleTtlMs: DEFAULT_IDLE_TTL_MS,
  cleanupIntervalMs: DEFAULT_CLEANUP_INTERVAL_MS,
  maxConcurrencyLeases: DEFAULT_MAX_CONCURRENCY_LEASES,
  maxLeaseDurationMs: DEFAULT_MAX_LEASE_DURATION_MS,
  policies: POLICY_DEFAULTS
});
