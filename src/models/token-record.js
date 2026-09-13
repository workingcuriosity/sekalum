import crypto from 'node:crypto';
import { validateNamedIdentifier } from '../security/authorization-identifier.js';

export class TokenRecord {
  constructor(input = {}) {
    const {
    id = crypto.randomUUID(),

    providerId,
    provider,
    accountId,
    accountName = null,
    credentialGeneration = null,

    accessToken,
    refreshToken = null,

    expiresAt = null,
    scopes = [],

    metadata = {},

    createdAt = new Date(),
    updatedAt = new Date(),
    lastRefreshAt = null,
    lastHealthCheckAt = null,

    version = 1
    } = input;
    const credentialKey = Object.hasOwn(input, 'credentialKey')
      ? input.credentialKey
      : crypto.randomUUID();

    if (typeof credentialKey !== 'string' || credentialKey.trim() === '') {
      throw new Error("TokenRecord: 'credentialKey' is required");
    }
    validateNamedIdentifier('credentialId', id);
    validateNamedIdentifier('credentialKey', credentialKey);
    // Legacy TokenRecord provider IDs are provider-owned references and may
    // include a provider-local suffix (for example `google:main`).
    validateNamedIdentifier('externalReference', providerId);

    if (!provider) {
      throw new Error("TokenRecord: 'provider' is required");
    }

    validateNamedIdentifier('externalReference', accountId);

    if (!accessToken) {
      throw new Error("TokenRecord: 'accessToken' is required");
    }

    this.id = id;
    this.credentialKey = credentialKey;

    this.providerId = providerId;
    this.provider = provider;
    this.accountId = accountId;
    this.accountName = accountName;
    this.credentialGeneration = credentialGeneration;

    this.accessToken = accessToken;
    this.refreshToken = refreshToken;

    this.expiresAt = expiresAt;
    this.scopes = [...scopes];
    this.metadata = { ...metadata };

    this.createdAt = createdAt;
    this.updatedAt = updatedAt;
    this.lastRefreshAt = lastRefreshAt;
    this.lastHealthCheckAt = lastHealthCheckAt;

    this.version = version;

    Object.freeze(this.scopes);
    Object.freeze(this.metadata);
    Object.freeze(this);
  }
}
