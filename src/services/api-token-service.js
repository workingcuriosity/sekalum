import crypto from 'node:crypto';

import { ApiToken } from '../models/api-token.js';
import { ApiTokenStatus } from '../models/api-token-status.js';
import { SerializedMutationQueue } from '../storage/serialized-mutation-queue.js';

const TOKEN_PREFIX = 'cht_';
const TOKEN_BYTES = 32;
const HASH_ALGORITHM = 'sha256';
const HASH_PREFIX = `${HASH_ALGORITHM}:`;
const PREFIX_LENGTH = 16;
const PRE_AUTH_FAILURE_WINDOW_MS = 60_000;

function sha256(value) {
  return `${HASH_PREFIX}${crypto.createHash(HASH_ALGORITHM).update(value, 'utf8').digest('hex')}`;
}

function timingSafeEqualString(left, right) {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function normalizeScopes(scopes) {
  if (!Array.isArray(scopes)) {
    throw new Error("ApiTokenService: 'scopes' must be an array");
  }

  const normalized = scopes.map((scope) => {
    if (typeof scope !== 'string' || scope.trim() === '') {
      throw new Error("ApiTokenService: 'scopes' must contain non-empty strings");
    }
    return scope.trim();
  });

  return [...new Set(normalized)];
}

function toDate(value, fieldName) {
  if (value === null || value === undefined) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`ApiTokenService: '${fieldName}' must be a valid date`);
  }
  return date;
}

export class ApiTokenService {
  constructor({ store, auditLogService = null, clock = () => new Date(), randomBytes = crypto.randomBytes, logger = null, userIdentityProvider = null } = {}) {
    if (!store?.list || !store?.load || !store?.save || !store?.findByPrefix) {
      throw new Error('ApiTokenService requires ApiTokenStore');
    }

    this.store = store;
    this.auditLogService = auditLogService;
    this.clock = clock;
    this.randomBytes = randomBytes;
    this.logger = logger;
    this.userIdentityProvider = userIdentityProvider;
    this.preAuthFailureWindows = new Map();
    this.mutationQueue = new SerializedMutationQueue();
  }

  async createToken({ name, userId, scopes = [], expiresAt = null, createdBy }) {
    return this.mutationQueue.run(() => this.#createToken({ name, userId, scopes, expiresAt, createdBy }));
  }

  async #createToken({ name, userId, scopes = [], expiresAt = null, createdBy }) {
    if (!name) throw new Error("ApiTokenService: 'name' is required");
    if (!userId) throw new Error("ApiTokenService: 'userId' is required");
    if (!createdBy) throw new Error("ApiTokenService: 'createdBy' is required");

    const principal = await this.#currentPrincipal(userId);

    const plaintextToken = this.#generatePlaintextToken();
    const tokenPrefix = this.#extractPrefix(plaintextToken);
    const apiToken = new ApiToken({
      name,
      tokenPrefix,
      tokenHash: sha256(plaintextToken),
      userId,
      principalGeneration: principal?.principalGeneration,
      scopes: normalizeScopes(scopes),
      createdAt: this.clock(),
      expiresAt: toDate(expiresAt, 'expiresAt'),
      createdBy
    });

    await this.store.save(apiToken);
    await this.#recordAudit('api-token.created', {
      actorType: this.#actorTypeForUser(createdBy),
      userId: createdBy,
      targetId: apiToken.id,
      details: this.#auditDetails(apiToken, { ownerUserId: apiToken.userId })
    });

    return Object.freeze({
      token: plaintextToken,
      apiToken,
      publicToken: apiToken.toPublicJSON()
    });
  }

  async listTokens() {
    return (await this.store.list()).map((apiToken) => apiToken.toPublicJSON());
  }

  async getToken(tokenId) {
    return (await this.store.load(tokenId)).toPublicJSON();
  }

  async revokeToken(tokenId, { revokedAt = this.clock(), revokedBy = null } = {}) {
    return this.mutationQueue.run(() => this.#revokeToken(tokenId, { revokedAt, revokedBy }));
  }

  async revokeTokensForUser(userId, { revokedAt = this.clock(), revokedBy = 'system' } = {}) {
    return this.mutationQueue.run(async () => {
      const tokens = await this.store.list();
      let count = 0;
      for (const token of tokens.filter((candidate) => candidate.userId === userId && !candidate.revokedAt)) {
        await this.store.save(token.withRevokedAt(revokedAt));
        count += 1;
      }
      if (count > 0) {
        await this.#recordAudit('api-token.revoked-for-user', {
          actorType: this.#actorTypeForUser(revokedBy),
          userId: revokedBy,
          details: { ownerUserId: userId, count }
        });
      }
      return count;
    });
  }

  async #revokeToken(tokenId, { revokedAt = this.clock(), revokedBy = null } = {}) {
    const apiToken = await this.store.load(tokenId);

    if (apiToken.revokedAt) {
      await this.#recordAudit('api-token.revoke.noop', {
        actorType: this.#actorTypeForUser(revokedBy),
        userId: revokedBy ?? 'system',
        targetId: apiToken.id,
        details: this.#auditDetails(apiToken, { reason: 'already-revoked' })
      });
      return apiToken.toPublicJSON();
    }

    const revoked = apiToken.withRevokedAt(revokedAt);
    await this.store.save(revoked);
    await this.#recordAudit('api-token.revoked', {
      actorType: this.#actorTypeForUser(revokedBy),
      userId: revokedBy ?? 'system',
      targetId: revoked.id,
      details: this.#auditDetails(revoked)
    });
    return revoked.toPublicJSON();
  }

  async authenticate(plaintextToken, { updateLastUsed = true } = {}) {
    if (typeof plaintextToken !== 'string' || !plaintextToken.startsWith(TOKEN_PREFIX)) {
      await this.#recordPreAuthFailure('invalid-format');
      return this.#authenticationFailure('invalid-format');
    }

    const tokenPrefix = this.#extractPrefix(plaintextToken);
    const candidates = await this.store.findByPrefix(tokenPrefix);
    const tokenHash = sha256(plaintextToken);
    const apiToken = candidates.find((candidate) => timingSafeEqualString(candidate.tokenHash, tokenHash));

    if (!apiToken) {
      await this.#recordPreAuthFailure('not-found');
      return this.#authenticationFailure('not-found');
    }

    return this.mutationQueue.run(() => this.#authenticateMatched({
      tokenId: apiToken.id,
      tokenHash,
      tokenPrefix,
      updateLastUsed
    }));
  }

  async #authenticateMatched({ tokenId, tokenHash, tokenPrefix, updateLastUsed }) {
    let apiToken;
    try {
      apiToken = await this.store.load(tokenId);
    } catch (error) {
      if (error?.code !== 'NOT_FOUND') throw error;
      await this.#recordPreAuthFailure('not-found');
      return this.#authenticationFailure('not-found');
    }

    if (!timingSafeEqualString(apiToken.tokenHash, tokenHash)) {
      await this.#recordPreAuthFailure('not-found');
      return this.#authenticationFailure('not-found');
    }

    if (apiToken.revokedAt) {
      await this.#recordAudit('api-token.invalid', {
        actorType: 'api-token',
        userId: null,
        apiTokenId: apiToken.id,
        targetId: apiToken.id,
        result: 'failure',
        details: this.#auditDetails(apiToken, { reason: 'revoked' })
      });
      return this.#authenticationFailure('revoked', apiToken.toPublicJSON());
    }

    if (apiToken.isExpired(this.clock())) {
      await this.#recordAudit('api-token.expired', {
        actorType: 'api-token',
        userId: null,
        apiTokenId: apiToken.id,
        targetId: apiToken.id,
        result: 'failure',
        details: this.#auditDetails(apiToken, { reason: 'expired' })
      });
      return this.#authenticationFailure('expired', apiToken.toPublicJSON());
    }

    const principal = await this.#currentPrincipal(apiToken.userId);
    if (this.userIdentityProvider && (!principal || principal.principalGeneration !== apiToken.principalGeneration)) {
      await this.#recordAudit('api-token.invalid', {
        actorType: 'api-token',
        userId: null,
        apiTokenId: apiToken.id,
        targetId: apiToken.id,
        result: 'failure',
        details: this.#auditDetails(apiToken, { reason: principal ? 'principal-rebound' : 'principal-missing' })
      });
      return this.#authenticationFailure(principal ? 'principal-rebound' : 'principal-missing', apiToken.toPublicJSON());
    }

    const authenticatedToken = updateLastUsed
      ? await this.#updateLastUsed(apiToken)
      : apiToken;

    if (authenticatedToken.revokedAt) {
      await this.#recordAudit('api-token.invalid', {
        actorType: 'api-token',
        userId: null,
        apiTokenId: authenticatedToken.id,
        targetId: authenticatedToken.id,
        result: 'failure',
        details: this.#auditDetails(authenticatedToken, { reason: 'revoked' })
      });
      return this.#authenticationFailure('revoked', authenticatedToken.toPublicJSON());
    }

    await this.#recordAudit('api-token.used', {
      actorType: 'api-token',
      userId: null,
      apiTokenId: authenticatedToken.id,
      targetId: authenticatedToken.id,
      details: this.#auditDetails(authenticatedToken)
    });

    return Object.freeze({
      authenticated: true,
      apiToken: authenticatedToken.toPublicJSON(),
      userId: authenticatedToken.userId,
      scopes: [...authenticatedToken.scopes],
      status: ApiTokenStatus.ACTIVE
    });
  }

  async #updateLastUsed(apiToken) {
    const updated = apiToken.withLastUsedAt(this.clock());
    return this.store.save(updated);
  }

  async #recordPreAuthFailure(reason) {
    const nowValue = this.clock();
    const now = nowValue instanceof Date ? nowValue.getTime() : new Date(nowValue).getTime();
    const previous = this.preAuthFailureWindows.get(reason);

    if (!previous || now - previous.startedAt >= PRE_AUTH_FAILURE_WINDOW_MS) {
      this.preAuthFailureWindows.set(reason, { startedAt: now, count: 1 });
      await this.#recordAudit('api-token.invalid', {
        actorType: 'service',
        result: 'failure',
        details: { reason, preAuth: true }
      });
      return;
    }

    previous.count += 1;
    if (previous.count === 2) {
      this.logger?.warn?.('Repeated pre-authentication failures are being coalesced', {
        reason,
        windowSeconds: PRE_AUTH_FAILURE_WINDOW_MS / 1000,
        count: previous.count
      });
    }
  }


  async #recordAudit(action, { actorType = null, userId = 'system', consumerId = null, apiTokenId = null, targetId = null, result = 'success', details = null } = {}) {
    if (!this.auditLogService?.record) return;

    await this.auditLogService.record({
      actorType: actorType ?? this.#actorTypeForUser(userId),
      userId,
      consumerId,
      apiTokenId,
      action,
      targetType: 'api-token',
      targetId,
      result,
      details
    });
  }

  #actorTypeForUser(userId) {
    return userId && userId !== 'system' ? 'user' : 'service';
  }

  #auditDetails(apiToken, extraDetails = {}) {
    return {
      tokenPrefix: apiToken.tokenPrefix,
      status: apiToken.status,
      scopes: [...apiToken.scopes],
      ...extraDetails
    };
  }

  #generatePlaintextToken() {
    return `${TOKEN_PREFIX}${this.randomBytes(TOKEN_BYTES).toString('base64url')}`;
  }

  async #currentPrincipal(userId) {
    if (!this.userIdentityProvider) return null;
    try {
      return await this.userIdentityProvider(userId);
    } catch (error) {
      if (error?.code === 'UNAUTHORIZED' || error?.code === 'FORBIDDEN' || error?.code === 'NOT_FOUND') return null;
      throw error;
    }
  }

  #extractPrefix(plaintextToken) {
    return plaintextToken.slice(0, TOKEN_PREFIX.length + PREFIX_LENGTH);
  }

  #authenticationFailure(reason, apiToken = null) {
    return Object.freeze({
      authenticated: false,
      reason,
      apiToken
    });
  }
}

export const ApiTokenServiceConstants = Object.freeze({
  TOKEN_PREFIX,
  TOKEN_BYTES,
  HASH_ALGORITHM,
  HASH_PREFIX,
  PREFIX_LENGTH
});
