import crypto from 'node:crypto';

import {
  OAuthSecurityRequirement,
  OAuthSecurityRequirements
} from '../models/oauth-security-requirements.js';

const DEFAULT_TTL_MS = 10 * 60 * 1000;

export class OAuthSecurityService {
  constructor({ ttlMs = DEFAULT_TTL_MS, random = crypto.randomBytes, now = () => Date.now() } = {}) {
    this.ttlMs = ttlMs;
    this.random = random;
    this.now = now;
    this.contexts = new Map();
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
    now = this.now()
  } = {}) {
    if (!provider) {
      throw new Error('OAuth provider is required');
    }

    const securityRequirements = OAuthSecurityRequirements.from(requirements);
    const finalState = this.#resolveState({ state, requirements: securityRequirements });
    const expiresAt = new Date(now + this.ttlMs);

    const context = {
      provider,
      account,
      providerConfiguration: providerConfiguration ? { ...providerConfiguration } : null,
      providerConfigurationId,
      providerConfigurationTemporary: Boolean(providerConfigurationTemporary),
      actorUserId: actorUserId ?? null,
      providerProfile: providerProfile?.identity?.() ?? providerProfile ?? null,
      credentialMethodKey,
      scopes: Array.isArray(scopes) ? [...scopes] : null,
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
      throw this.#stateError('OAuth state expired', context);
    }

    this.contexts.delete(state);
    return this.#publicContext(context, { includeProviderConfiguration: true });
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

  #publicContext(context, { includeProviderConfiguration = false } = {}) {
    return Object.freeze({
      provider: context.provider,
      account: context.account,
      scopes: Array.isArray(context.scopes) ? Object.freeze([...context.scopes]) : null,
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
      credentialMethodKey: context.credentialMethodKey,
      ...(includeProviderConfiguration
        ? { providerConfiguration: Object.freeze({ ...(context.providerConfiguration ?? {}) }) }
        : {})
    });
  }
}
