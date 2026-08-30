import crypto from 'node:crypto';
import { ApiTokenStatus } from './api-token-status.js';

function toDate(value, fieldName) {
  if (value === null || value === undefined) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`ApiToken: '${fieldName}' must be a valid date`);
  }
  return date;
}

function normalizeScopes(scopes) {
  if (!Array.isArray(scopes)) {
    throw new Error("ApiToken: 'scopes' must be an array");
  }

  const normalized = scopes.map((scope) => {
    if (typeof scope !== 'string' || scope.trim() === '') {
      throw new Error("ApiToken: 'scopes' must contain non-empty strings");
    }
    return scope.trim();
  });

  return Object.freeze([...new Set(normalized)]);
}

export class ApiToken {
  constructor({
    id = crypto.randomUUID(),
    name,
    tokenPrefix,
    tokenHash,
    userId,
    principalGeneration = `legacy:${userId}`,
    scopes = [],
    createdAt = new Date(),
    expiresAt = null,
    revokedAt = null,
    lastUsedAt = null,
    createdBy,
    version = 1
  }) {
    if (!id) throw new Error("ApiToken: 'id' is required");
    if (!name) throw new Error("ApiToken: 'name' is required");
    if (!tokenPrefix) throw new Error("ApiToken: 'tokenPrefix' is required");
    if (!tokenHash) throw new Error("ApiToken: 'tokenHash' is required");
    if (!userId) throw new Error("ApiToken: 'userId' is required");
    if (typeof principalGeneration !== 'string' || principalGeneration.trim() === '') {
      throw new Error("ApiToken: 'principalGeneration' is required");
    }
    if (!createdBy) throw new Error("ApiToken: 'createdBy' is required");

    this.id = id;
    this.name = name;
    this.tokenPrefix = tokenPrefix;
    this.tokenHash = tokenHash;
    this.userId = userId;
    this.principalGeneration = principalGeneration.trim();
    this.scopes = normalizeScopes(scopes);
    this.createdAt = toDate(createdAt, 'createdAt');
    this.expiresAt = toDate(expiresAt, 'expiresAt');
    this.revokedAt = toDate(revokedAt, 'revokedAt');
    this.lastUsedAt = toDate(lastUsedAt, 'lastUsedAt');
    this.createdBy = createdBy;
    this.version = version;

    Object.freeze(this);
  }

  get status() {
    if (this.revokedAt) return ApiTokenStatus.REVOKED;
    if (this.isExpired()) return ApiTokenStatus.EXPIRED;
    return ApiTokenStatus.ACTIVE;
  }

  get isRevoked() {
    return Boolean(this.revokedAt);
  }

  isExpired(referenceDate = new Date()) {
    const date = referenceDate instanceof Date ? referenceDate : new Date(referenceDate);
    if (Number.isNaN(date.getTime())) {
      throw new Error("ApiToken: 'referenceDate' must be a valid date");
    }
    return Boolean(this.expiresAt && this.expiresAt.getTime() <= date.getTime());
  }

  hasScope(scope) {
    return this.scopes.includes(scope);
  }

  withRevokedAt(revokedAt = new Date()) {
    return new ApiToken({
      ...this.toJSON(),
      revokedAt,
      version: this.version + 1
    });
  }

  withLastUsedAt(lastUsedAt = new Date()) {
    return new ApiToken({
      ...this.toJSON(),
      lastUsedAt,
      version: this.version + 1
    });
  }

  toJSON() {
    return {
      id: this.id,
      name: this.name,
      tokenPrefix: this.tokenPrefix,
      tokenHash: this.tokenHash,
      userId: this.userId,
      principalGeneration: this.principalGeneration,
      scopes: [...this.scopes],
      createdAt: this.createdAt.toISOString(),
      expiresAt: this.expiresAt ? this.expiresAt.toISOString() : null,
      revokedAt: this.revokedAt ? this.revokedAt.toISOString() : null,
      lastUsedAt: this.lastUsedAt ? this.lastUsedAt.toISOString() : null,
      createdBy: this.createdBy,
      version: this.version
    };
  }

  toPublicJSON() {
    return {
      id: this.id,
      name: this.name,
      tokenPrefix: this.tokenPrefix,
      userId: this.userId,
      scopes: [...this.scopes],
      createdAt: this.createdAt.toISOString(),
      expiresAt: this.expiresAt ? this.expiresAt.toISOString() : null,
      revokedAt: this.revokedAt ? this.revokedAt.toISOString() : null,
      lastUsedAt: this.lastUsedAt ? this.lastUsedAt.toISOString() : null,
      createdBy: this.createdBy,
      status: this.status,
      version: this.version
    };
  }

  static from(data) {
    if (data instanceof ApiToken) return data;
    return new ApiToken(data);
  }
}
