import crypto from 'node:crypto';

const PROVIDERS = Object.freeze([
  'x', 'kick', 'twitch', 'google', 'discord', 'threads', 'facebook', 'instagram'
]);

export const OAuthEvidenceDisposition = Object.freeze({
  PROVEN: 'PROVEN',
  TRANSACTION_BOUND: 'TRANSACTION_BOUND',
  IF_PRESENT_VERIFY: 'IF_PRESENT_VERIFY',
  NOT_AVAILABLE: 'NOT_AVAILABLE',
  NOT_APPLICABLE: 'NOT_APPLICABLE'
});

export const OAuthEvidenceRequirement = Object.freeze({
  REQUIRED: 'REQUIRED',
  OPTIONAL_IF_PRESENT: 'OPTIONAL_IF_PRESENT',
  NOT_REQUIRED: 'NOT_REQUIRED',
  NOT_APPLICABLE: 'NOT_APPLICABLE'
});

const EVIDENCE_DIMENSIONS = Object.freeze([
  'STATE', 'PKCE', 'NONCE', 'CLIENT', 'ISSUER', 'AUDIENCE', 'ACCOUNT',
  'SCOPES', 'PROFILE', 'METHOD', 'REDIRECT', 'CREDENTIAL_BINDING'
]);

const providerPolicy = ({ pkce = OAuthEvidenceRequirement.NOT_REQUIRED, client = OAuthEvidenceDisposition.TRANSACTION_BOUND } = {}) => Object.freeze(
  Object.fromEntries(EVIDENCE_DIMENSIONS.map((dimension) => [dimension, {
    capability: dimension === 'STATE' || dimension === 'PROFILE' || dimension === 'METHOD'
      || dimension === 'REDIRECT' || dimension === 'CREDENTIAL_BINDING'
      ? OAuthEvidenceDisposition.TRANSACTION_BOUND
      : dimension === 'ACCOUNT' ? OAuthEvidenceDisposition.PROVEN
        : dimension === 'SCOPES' ? OAuthEvidenceDisposition.IF_PRESENT_VERIFY
          : dimension === 'PKCE' ? (pkce === OAuthEvidenceRequirement.REQUIRED
            ? OAuthEvidenceDisposition.PROVEN : OAuthEvidenceDisposition.NOT_APPLICABLE)
            : dimension === 'CLIENT' ? client
              : OAuthEvidenceDisposition.NOT_AVAILABLE,
    requirement: dimension === 'STATE' || dimension === 'CLIENT' || dimension === 'ACCOUNT'
      || dimension === 'SCOPES' || dimension === 'PROFILE' || dimension === 'METHOD'
      || dimension === 'REDIRECT' || dimension === 'CREDENTIAL_BINDING'
      ? OAuthEvidenceRequirement.REQUIRED
      : dimension === 'PKCE' ? pkce : OAuthEvidenceRequirement.NOT_REQUIRED,
    source: dimension === 'STATE' ? 'OAuthSecurityService + browser binding'
      : dimension === 'PROFILE' ? 'ProviderRegistry current profile'
        : dimension === 'METHOD' ? 'Provider Method binding'
          : dimension === 'REDIRECT' ? 'canonical callback URI and public origin'
            : dimension === 'CREDENTIAL_BINDING' ? 'Credential target and durable binding'
              : dimension === 'ACCOUNT' ? 'provider profile/account response'
                : dimension === 'SCOPES' ? 'provider response scope evidence'
                  : dimension === 'CLIENT' ? 'current configuration and provider response'
                    : 'provider-specific adapter'
  }]))
);

export const OAUTH_PROVIDER_EVIDENCE_POLICIES = Object.freeze({
  x: providerPolicy({ pkce: OAuthEvidenceRequirement.REQUIRED }),
  kick: providerPolicy({ pkce: OAuthEvidenceRequirement.REQUIRED, client: OAuthEvidenceDisposition.PROVEN }),
  twitch: providerPolicy(),
  google: providerPolicy(),
  discord: providerPolicy(),
  threads: providerPolicy(),
  facebook: providerPolicy(),
  instagram: providerPolicy()
});

function clone(value) {
  if (Array.isArray(value)) return value.map(clone);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, clone(entry)]));
  return value;
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function text(value, field, { required = false } = {}) {
  if (value === null || value === undefined || value === '') {
    if (required) throw new Error(`OAuth context binding: ${field} is required`);
    return null;
  }
  if (typeof value !== 'string') throw new Error(`OAuth context binding: ${field} must be a string`);
  const normalized = value.trim();
  if (required && !normalized) throw new Error(`OAuth context binding: ${field} is required`);
  return normalized || null;
}

export function normalizeScopes(scopes = []) {
  if (!Array.isArray(scopes)) throw new Error('OAuth context binding: scopes must be an array');
  return [...new Set(scopes.map((scope) => text(scope, 'scope', { required: true })))].sort();
}

function profileIdentity(profile) {
  if (!profile) return null;
  const identity = profile.identity?.() ?? profile;
  return freeze({
    ...(identity.providerKey ? { providerKey: identity.providerKey } : {}),
    ...(identity.version ? { version: identity.version } : {}),
    ...(identity.providerKind ? { providerKind: identity.providerKind } : {}),
    ...(identity.digest ? { digest: identity.digest } : {})
  });
}

function publicOriginIdentity(publicOrigin) {
  if (!publicOrigin) return null;
  try {
    return new URL(publicOrigin).origin;
  } catch {
    return text(publicOrigin, 'publicOrigin', { required: true });
  }
}

export class OAuthClientBindingIdentity {
  constructor({
    providerKey,
    providerProfile,
    credentialMethodKey,
    providerConfigurationId = null,
    clientId = null,
    clientIdentity = null,
    redirectUri,
    publicOrigin
  } = {}) {
    this.providerKey = text(providerKey, 'providerKey', { required: true });
    this.providerProfile = profileIdentity(providerProfile);
    this.credentialMethodKey = text(credentialMethodKey, 'credentialMethodKey', { required: true });
    this.providerConfigurationId = text(providerConfigurationId, 'providerConfigurationId');
    this.clientId = text(clientId, 'clientId', { required: true });
    this.clientIdentity = clientIdentity === null || clientIdentity === undefined
      ? null : freeze(clone(clientIdentity));
    this.redirectUri = text(redirectUri, 'redirectUri', { required: true });
    this.publicOrigin = publicOriginIdentity(publicOrigin);
    this._canonical = freeze(canonicalize({
      providerKey: this.providerKey,
      providerProfile: this.providerProfile,
      credentialMethodKey: this.credentialMethodKey,
      providerConfigurationId: this.providerConfigurationId,
      clientId: this.clientId,
      clientIdentity: this.clientIdentity,
      redirectUri: this.redirectUri,
      publicOrigin: this.publicOrigin
    }));
    this.clientBindingFingerprint = crypto.createHash('sha256')
      .update(JSON.stringify(this._canonical))
      .digest('hex');
    Object.freeze(this);
  }

  toJSON() {
    return {
      providerKey: this.providerKey,
      providerProfile: clone(this.providerProfile),
      credentialMethodKey: this.credentialMethodKey,
      providerConfigurationId: this.providerConfigurationId,
      clientBindingFingerprint: this.clientBindingFingerprint,
      redirectUri: this.redirectUri,
      publicOrigin: this.publicOrigin
    };
  }

  static from(value) {
    if (value instanceof OAuthClientBindingIdentity) return value;
    return new OAuthClientBindingIdentity(value);
  }
}

export class OAuthCredentialBinding {
  constructor({
    providerKey,
    providerProfile,
    credentialMethodKey,
    providerConfigurationId = null,
    clientBindingFingerprint,
    accountId,
    grantedScopes = [],
    redirectUri = null,
    publicOrigin = null
  } = {}) {
    this.providerKey = text(providerKey, 'providerKey', { required: true });
    this.providerProfile = profileIdentity(providerProfile);
    this.credentialMethodKey = text(credentialMethodKey, 'credentialMethodKey', { required: true });
    this.providerConfigurationId = text(providerConfigurationId, 'providerConfigurationId');
    this.clientBindingFingerprint = text(clientBindingFingerprint, 'clientBindingFingerprint', { required: true });
    if (!/^[a-f0-9]{64}$/.test(this.clientBindingFingerprint)) throw new Error('OAuth context binding: invalid clientBindingFingerprint');
    this.accountId = text(accountId, 'accountId', { required: true });
    this.grantedScopes = freeze(normalizeScopes(grantedScopes));
    this.redirectUri = text(redirectUri, 'redirectUri');
    this.publicOrigin = publicOriginIdentity(publicOrigin);
    Object.freeze(this);
  }

  toJSON() {
    return {
      providerKey: this.providerKey,
      providerProfile: clone(this.providerProfile),
      credentialMethodKey: this.credentialMethodKey,
      providerConfigurationId: this.providerConfigurationId,
      clientBindingFingerprint: this.clientBindingFingerprint,
      accountId: this.accountId,
      grantedScopes: [...this.grantedScopes],
      ...(this.redirectUri ? { redirectUri: this.redirectUri } : {}),
      ...(this.publicOrigin ? { publicOrigin: this.publicOrigin } : {})
    };
  }

  static from(value) {
    if (!value) return null;
    if (value instanceof OAuthCredentialBinding) return value;
    return new OAuthCredentialBinding(value);
  }
}

export class OAuthTransactionBinding {
  constructor({
    transactionId = crypto.randomUUID(),
    state,
    actorUserId = null,
    providerKey,
    providerProfile,
    credentialMethodKey,
    providerConfigurationId = null,
    clientBindingFingerprint,
    publicOrigin,
    redirectUri,
    requestedScopes = [],
    requiredScopes = [],
    credentialBinding = null,
    createdAt,
    expiresAt,
    nonce = null,
    codeChallenge = null,
    codeChallengeMethod = null
  } = {}) {
    this.transactionId = text(transactionId, 'transactionId', { required: true });
    this.state = text(state, 'state');
    this.actorUserId = text(actorUserId, 'actorUserId');
    this.providerKey = text(providerKey, 'providerKey', { required: true });
    this.providerProfile = profileIdentity(providerProfile);
    this.credentialMethodKey = text(credentialMethodKey, 'credentialMethodKey', { required: true });
    this.providerConfigurationId = text(providerConfigurationId, 'providerConfigurationId');
    this.clientBindingFingerprint = text(clientBindingFingerprint, 'clientBindingFingerprint', { required: true });
    this.publicOrigin = publicOriginIdentity(publicOrigin);
    this.redirectUri = text(redirectUri, 'redirectUri', { required: true });
    this.requestedScopes = freeze(normalizeScopes(requestedScopes));
    this.requiredScopes = freeze(normalizeScopes(requiredScopes));
    this.credentialBinding = OAuthCredentialBinding.from(credentialBinding)?.toJSON?.() ?? null;
    this.createdAt = createdAt instanceof Date ? new Date(createdAt) : new Date(createdAt);
    this.expiresAt = expiresAt instanceof Date ? new Date(expiresAt) : new Date(expiresAt);
    this.nonce = text(nonce, 'nonce');
    this.codeChallenge = text(codeChallenge, 'codeChallenge');
    this.codeChallengeMethod = text(codeChallengeMethod, 'codeChallengeMethod');
    Object.freeze(this);
  }

  toJSON() {
    return {
      transactionId: this.transactionId,
      state: this.state,
      actorUserId: this.actorUserId,
      providerKey: this.providerKey,
      providerProfile: clone(this.providerProfile),
      credentialMethodKey: this.credentialMethodKey,
      providerConfigurationId: this.providerConfigurationId,
      clientBindingFingerprint: this.clientBindingFingerprint,
      publicOrigin: this.publicOrigin,
      redirectUri: this.redirectUri,
      requestedScopes: [...this.requestedScopes],
      requiredScopes: [...this.requiredScopes],
      credentialBinding: clone(this.credentialBinding),
      createdAt: this.createdAt.toISOString(),
      expiresAt: this.expiresAt.toISOString(),
      nonce: this.nonce,
      codeChallenge: this.codeChallenge,
      codeChallengeMethod: this.codeChallengeMethod
    };
  }
}

export class OAuthContextEvidence {
  constructor({ dimension, capability, requirement, source, value = null, comparison = 'exact', absenceBehavior = 'BLOCK' } = {}) {
    if (!EVIDENCE_DIMENSIONS.includes(dimension)) throw new Error(`OAuth evidence: unsupported dimension '${dimension}'`);
    this.dimension = dimension;
    this.capability = capability;
    this.requirement = requirement;
    this.source = text(source, 'evidence source', { required: true });
    this.value = freeze(clone(value));
    this.comparison = comparison;
    this.absenceBehavior = absenceBehavior;
    Object.freeze(this);
  }

  toJSON() { return { ...this, value: clone(this.value) }; }
}

export function providerEvidencePolicy(providerKey) {
  return OAUTH_PROVIDER_EVIDENCE_POLICIES[providerKey] ?? OAUTH_PROVIDER_EVIDENCE_POLICIES.google;
}

function evidenceError(code, message) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = 400;
  return error;
}

export function compareOAuthContextEvidence({ providerKey, binding, currentBinding = binding, oauthResult, providerEvidence = {} } = {}) {
  const result = oauthResult ?? {};
  const failures = [];
  const evidence = [];
  const policy = providerEvidencePolicy(providerKey);
  const add = (dimension, capability, requirement, source, value, comparison = 'exact') => {
    evidence.push(new OAuthContextEvidence({ dimension, capability, requirement, source, value, comparison }));
  };

  if (result.provider !== providerKey) failures.push(evidenceError('OAUTH_PROVIDER_MISMATCH', 'OAuth provider does not match the transaction'));
  if (!result.accountId) failures.push(evidenceError('OAUTH_EVIDENCE_UNAVAILABLE', 'OAuth provider account evidence is unavailable'));
  if (!binding?.clientBindingFingerprint) failures.push(evidenceError('OAUTH_EVIDENCE_UNAVAILABLE', 'OAuth client binding evidence is unavailable'));
  else add('STATE', policy.STATE.capability, policy.STATE.requirement, policy.STATE.source, 'transaction-bound');
  if (binding?.providerProfile?.digest && result.metadata?.providerProfile?.digest
    && binding.providerProfile.digest !== result.metadata.providerProfile.digest) {
    failures.push(evidenceError('OAUTH_PROFILE_MISMATCH', 'OAuth provider profile does not match the transaction'));
  }
  add('PROFILE', policy.PROFILE.capability, policy.PROFILE.requirement, policy.PROFILE.source, result.metadata?.providerProfile ?? binding?.providerProfile);
  if (binding?.credentialMethodKey && result.metadata?.credentialMethodKey
    && binding.credentialMethodKey !== result.metadata.credentialMethodKey) {
    failures.push(evidenceError('OAUTH_METHOD_MISMATCH', 'OAuth credential method does not match the transaction'));
  }
  add('METHOD', policy.METHOD.capability, policy.METHOD.requirement, policy.METHOD.source, binding?.credentialMethodKey);
  if (binding?.clientBindingFingerprint !== currentBinding?.clientBindingFingerprint) {
    failures.push(evidenceError('OAUTH_CLIENT_MISMATCH', 'OAuth client binding changed during the transaction'));
  }
  if (providerEvidence.clientBindingFingerprint
    && providerEvidence.clientBindingFingerprint !== binding?.clientBindingFingerprint) {
    failures.push(evidenceError('OAUTH_CLIENT_MISMATCH', 'Provider client evidence does not match the transaction'));
  }
  add('CLIENT', policy.CLIENT.capability, policy.CLIENT.requirement, policy.CLIENT.source, binding?.clientBindingFingerprint);
  if (binding?.redirectUri && currentBinding?.redirectUri && binding.redirectUri !== currentBinding.redirectUri) {
    failures.push(evidenceError('OAUTH_REDIRECT_URI_MISMATCH', 'OAuth redirect URI changed during the transaction'));
  }
  add('REDIRECT', policy.REDIRECT.capability, policy.REDIRECT.requirement, policy.REDIRECT.source, binding?.redirectUri);
  if (binding?.accountId && result.accountId !== binding.accountId) {
    failures.push(evidenceError('OAUTH_ACCOUNT_MISMATCH', 'OAuth account does not match the transaction'));
  }
  add('ACCOUNT', policy.ACCOUNT.capability, policy.ACCOUNT.requirement, policy.ACCOUNT.source, result.accountId);
  const grantedScopes = normalizeScopes(result.scopes ?? providerEvidence.grantedScopes ?? []);
  const requiredScopes = normalizeScopes(binding?.requiredScopes ?? []);
  const missingScopes = requiredScopes.filter((scope) => !grantedScopes.includes(scope));
  if (missingScopes.length > 0) failures.push(evidenceError('OAUTH_SCOPE_MISMATCH', 'OAuth result does not prove the required scopes'));
  add('SCOPES', policy.SCOPES.capability, policy.SCOPES.requirement, policy.SCOPES.source, {
    requestedScopes: normalizeScopes(binding?.requestedScopes ?? []),
    grantedScopes,
    requiredScopes
  });

  for (const dimension of ['ISSUER', 'AUDIENCE']) {
    const value = providerEvidence[dimension.toLowerCase()];
    add(dimension, policy[dimension].capability, policy[dimension].requirement, policy[dimension].source, value);
  }
  return Object.freeze({
    pass: failures.length === 0,
    failures: Object.freeze(failures),
    evidence: Object.freeze(evidence),
    grantedScopes: Object.freeze(grantedScopes),
    requiredScopes: Object.freeze(requiredScopes)
  });
}

export { PROVIDERS };
