import crypto from 'node:crypto';

export class CredentialSecretVersion {
  constructor({
    versionId = crypto.randomUUID(),
    credentialId,
    version,
    secrets = [],
    reason = 'manual-update',
    createdAt = new Date(),
    createdBy = 'system',
    metadata = {},
    invalidatedAt = null,
    invalidationReason = null
  }) {
    if (!versionId) throw new Error("CredentialSecretVersion: 'versionId' is required");
    if (!credentialId) throw new Error("CredentialSecretVersion: 'credentialId' is required");
    if (!Number.isInteger(version) || version < 1) {
      throw new Error("CredentialSecretVersion: 'version' must be a positive integer");
    }
    if (!Array.isArray(secrets)) {
      throw new Error("CredentialSecretVersion: 'secrets' must be an array");
    }

    this.versionId = versionId;
    this.credentialId = credentialId;
    this.version = version;
    this.secrets = Object.freeze(secrets.map((secret) => ({ ...secret })));
    this.reason = reason;
    this.createdAt = createdAt instanceof Date ? createdAt : new Date(createdAt);
    this.createdBy = createdBy;
    this.metadata = Object.freeze({ ...metadata });
    this.invalidatedAt = invalidatedAt === null || invalidatedAt === undefined
      ? null
      : (invalidatedAt instanceof Date ? invalidatedAt : new Date(invalidatedAt));
    this.invalidationReason = invalidationReason;

    Object.freeze(this);
  }

  toJSON() {
    return {
      versionId: this.versionId,
      credentialId: this.credentialId,
      version: this.version,
      secrets: this.secrets.map((secret) => ({ ...secret })),
      reason: this.reason,
      createdAt: this.createdAt.toISOString(),
      createdBy: this.createdBy,
      metadata: this.metadata,
      invalidatedAt: this.invalidatedAt?.toISOString() ?? null,
      invalidationReason: this.invalidationReason
    };
  }

  static from(data) {
    if (data instanceof CredentialSecretVersion) return data;
    return new CredentialSecretVersion(data);
  }
}
