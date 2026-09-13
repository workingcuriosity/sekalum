import crypto from 'node:crypto';

import {
  OAuthSecurityRequirement,
  OAuthSecurityRequirements
} from '../models/oauth-security-requirements.js';
import {
  OAuthClientBindingIdentity,
  OAuthCredentialBinding,
  normalizeScopes
} from '../models/oauth-context-binding.js';

const DEFAULT_TTL_MS = 10 * 60 * 1000;
const DEFAULT_MAX_CONTEXTS = 10_000;
const DEFAULT_MAX_CONTEXTS_PER_ACTOR = 2_000;
const DEFAULT_CLEANUP_INTERVAL_MS = 60 * 1000;

export class OAuthSecurityService {
  constructor({
    ttlMs = DEFAULT_TTL_MS,
    maxContexts = DEFAULT_MAX_CONTEXTS,
    maxContextsPerActor = DEFAULT_MAX_CONTEXTS_PER_ACTOR,
    cleanupIntervalMs = DEFAULT_CLEANUP_INTERVAL_MS,
    random = crypto.randomBytes,
    now = () => Date.now(),
    schedule = setInterval,
    cancelSchedule = clearInterval
  } = {}) {
    this.ttlMs = ttlMs;
    this.maxContexts = this.#boundedPositiveInteger(maxContexts, DEFAULT_MAX_CONTEXTS);
    this.maxContextsPerActor = this.#boundedPositiveInteger(maxContextsPerActor, DEFAULT_MAX_CONTEXTS_PER_ACTOR);
    this.cleanupIntervalMs = this.#boundedPositiveInteger(cleanupIntervalMs, DEFAULT_CLEANUP_INTERVAL_MS);
    this.random = random;
    this.now = now;
    this.contexts = new Map();
    this.cancelSchedule = cancelSchedule;
    this.cleanupTimer = schedule(() => this.purgeExpiredContexts(), this.cleanupIntervalMs);
    this.cleanupTimer?.unref?.();
  }

  createAuthorizationContext({
    provider,
    requirements = OAuthSecurityRequirements.default(),
    state = null,
    scopes = null,
    account = null,
    providerConfiguration = null,
    providerConfigurationId = null,
    providerConfigurationTemporary = false,
    actorUserId = null,
    providerProfile = null,
    credentialMethodKey = null,
    publicOrigin = null,
    redirectUri = null,
    clientId = null,
    clientIdentity = null,
    requiredScopes = [],
    credentialBinding = null,
    transactionId = crypto.randomUUID(),
    now = this.now()
  } = {}) {
    if (!provider) {
      throw new Error('OAuth provider is required');
    }

    const securityRequirements = OAuthSecurityRequirements.from(requirements);
    const finalState = this.#resolveState({ state, requirements: securityRequirements });
    const expiresAt = new Date(now + this.ttlMs);
    const requestedScopes = normalizeScopes(scopes ?? []);
    const normalizedRequiredScopes = normalizeScopes(requiredScopes ?? []);
    const clientBinding = new OAuthClientBindingIdentity({
      providerKey: provider,
      providerProfile,
      credentialMethodKey: credentialMethodKey ?? 'oauth2',
      providerConfigurationId,
      clientId: clientId ?? providerConfiguration?.clientId ?? 'environment-client',
      clientIdentity,
      redirectUri: redirectUri ?? providerConfiguration?.redirectUri ?? 'https://invalid.invalid/oauth/callback',
      publicOrigin: publicOrigin ?? redirectUri ?? providerConfiguration?.redirectUri ?? 'https://invalid.invalid'
    });

    const context = {
      provider,
      account,
      providerConfigurationId,
      providerConfigurationTemporary: Boolean(providerConfigurationTemporary),
      actorUserId: actorUserId ?? null,
      providerProfile: providerProfile?.identity?.() ?? providerProfile ?? null,
      credentialMethodKey,
      scopes: requestedScopes,
      requestedScopes,
      requiredScopes: normalizedRequiredScopes,
      publicOrigin: clientBinding.publicOrigin,
      redirectUri: clientBinding.redirectUri,
      clientBindingFingerprint: clientBinding.clientBindingFingerprint,
      transactionId,
      credentialBinding: OAuthCredentialBinding.from(credentialBinding)?.toJSON?.() ?? null,
      state: finalState,
      nonce: null,
      codeVerifier: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      createdAt: new Date(now),
      expiresAt,
      securityRequirements
    };

    if (securityRequirements.requiresPkce()) {
      context.codeVerifier = this.createCodeVerifier();
      context.codeChallenge = this.createCodeChallenge(context.codeVerifier);
      context.codeChallengeMethod = 'S256';
    }

    if (securityRequirements.requiresNonce()) {
      context.nonce = this.#randomUrlSafe(16);
    }

    if (finalState) {
      this.purgeExpiredContexts(now);
      this.#assertContextCapacity(context.actorUserId);
      this.contexts.set(finalState, context);
    }

    return this.#publicContext(context);
  }

  consumeCallbackContext({
    provider,
    state,
    providerProfile = null,
    expectedActorUserId = null,
    now = this.now()
  } = {}) {
    if (!state) {
      return null;
    }

    const context = this.contexts.get(state);

    if (!context) {
      throw this.#stateError('OAuth state is unknown or expired');
    }

    if (context.provider !== provider) {
      throw this.#stateError('OAuth state provider mismatch');
    }

    if (providerProfile && context.providerProfile
      && providerProfile.digest !== context.providerProfile.digest) {
      throw this.#stateError('OAuth state provider profile mismatch');
    }

    if (context.actorUserId !== null && context.actorUserId !== expectedActorUserId) {
      throw this.#stateError('OAuth state actor mismatch');
    }

    if (context.expiresAt.getTime() <= now) {
      this.contexts.delete(state);
      throw this.#stateError('OAuth state expired', context);
    }

    this.contexts.delete(state);
    return this.#publicContext(context);
  }

  purgeExpiredContexts(now = this.now()) {
    const expired = [];
    for (const [state, context] of this.contexts.entries()) {
      if (context.expiresAt.getTime() <= now) {
        this.contexts.delete(state);
        expired.push(this.#publicContext(context));
      }
    }
    return expired;
  }

  discardAuthorizationContext(state) {
    if (!state) return false;
    return this.contexts.delete(state);
  }

  dispose() {
    if (!this.cleanupTimer) return;
    this.cancelSchedule(this.cleanupTimer);
    this.cleanupTimer = null;
  }

  createCodeVerifier() {
    return this.#randomUrlSafe(32);
  }

  createCodeChallenge(codeVerifier) {
    if (!codeVerifier) {
      throw new Error('PKCE code_verifier is required');
    }

    return crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
  }

  #resolveState({ state, requirements }) {
    if (state) {
      return state;
    }

    if (requirements.state === OAuthSecurityRequirement.DISABLED) {
      return null;
    }

    return crypto.randomUUID();
  }

  #randomUrlSafe(byteLength) {
    return this.random(byteLength).toString('base64url');
  }

  #stateError(message, context = null) {
    const error = new Error(message);
    error.code = 'OAUTH_STATE_INVALID';
    error.statusCode = 400;
    error.providerConfigurationId = context?.providerConfigurationId ?? null;
    error.providerKey = context?.provider ?? null;
    return error;
  }

  #assertContextCapacity(actorUserId) {
    if (this.contexts.size >= this.maxContexts) {
      throw this.#stateError('OAuth state capacity exceeded');
    }
    const actor = actorUserId ?? 'anonymous';
    let actorContexts = 0;
    for (const context of this.contexts.values()) {
      if ((context.actorUserId ?? 'anonymous') === actor) actorContexts += 1;
    }
    if (actorContexts >= this.maxContextsPerActor) {
      throw this.#stateError('OAuth state actor capacity exceeded');
    }
  }

  #boundedPositiveInteger(value, fallback) {
    const number = Number(value);
    return Number.isInteger(number) && number > 0 ? number : fallback;
  }

  #publicContext(context) {
    return Object.freeze({
      provider: context.provider,
      account: context.account,
      scopes: Array.isArray(context.scopes) ? Object.freeze([...context.scopes]) : null,
      requestedScopes: Object.freeze([...(context.requestedScopes ?? context.scopes ?? [])]),
      requiredScopes: Object.freeze([...(context.requiredScopes ?? [])]),
      transactionId: context.transactionId,
      publicOrigin: context.publicOrigin,
      redirectUri: context.redirectUri,
      clientBindingFingerprint: context.clientBindingFingerprint,
      credentialBinding: context.credentialBinding,
      state: context.state,
      nonce: context.nonce,
      codeVerifier: context.codeVerifier,
      codeChallenge: context.codeChallenge,
      codeChallengeMethod: context.codeChallengeMethod,
      createdAt: context.createdAt,
      expiresAt: context.expiresAt,
      securityRequirements: context.securityRequirements,
      providerConfigurationId: context.providerConfigurationId,
      providerConfigurationTemporary: context.providerConfigurationTemporary,
      providerProfile: context.providerProfile,
      credentialMethodKey: context.credentialMethodKey
    });
  }
}
