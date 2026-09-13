export class OAuthResult {
  constructor({
    providerId,
    provider,
    accountId,
    accountName = null,

    accessToken,
    refreshToken = null,

    expiresAt = null,
    scopes = [],
    metadata = {},
    contextBinding = null,
    evidence = []
  }) {
    if (!providerId) {
      throw new Error("OAuthResult: 'providerId' is required");
    }

    if (!provider) {
      throw new Error("OAuthResult: 'provider' is required");
    }

    if (!accountId) {
      throw new Error("OAuthResult: 'accountId' is required");
    }

    if (!accessToken) {
      throw new Error("OAuthResult: 'accessToken' is required");
    }

    this.providerId = providerId;
    this.provider = provider;
    this.accountId = accountId;
    this.accountName = accountName;

    this.accessToken = accessToken;
    this.refreshToken = refreshToken;

    this.expiresAt = expiresAt;
    this.scopes = [...scopes];
    this.metadata = { ...metadata };
    // These are secret-free admission facts only. Tokens remain transient
    // fields and are never copied into the binding or evidence projections.
    this.contextBinding = contextBinding ? structuredClone(contextBinding) : null;
    this.evidence = Array.isArray(evidence) ? structuredClone(evidence) : [];

    Object.freeze(this.scopes);
    Object.freeze(this.metadata);
    Object.freeze(this.contextBinding);
    Object.freeze(this.evidence);
    Object.freeze(this);
  }
}
