// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

function assertUniqueCredentialKeys(credentials) {
  const byKey = new Map();
  for (const credential of credentials) {
    const existing = byKey.get(credential.credentialKey);
    if (existing && existing.credentialId !== credential.credentialId) {
      const error = new Error(`Credential key '${credential.credentialKey}' is assigned to credentials '${existing.credentialId}' and '${credential.credentialId}'`);
      error.code = 'CREDENTIAL_KEY_DUPLICATE';
      throw error;
    }
    byKey.set(credential.credentialKey, credential);
  }
}

export class CompositeCredentialStoreAdapter {
  constructor({ primary, legacy = null }) {
    if (!primary) throw new Error('CompositeCredentialStoreAdapter requires a primary adapter');
    this.primary = primary;
    this.legacy = legacy;
  }

  async load(credentialId) {
    try {
      return await this.primary.load(credentialId);
    } catch (error) {
      if (error.code !== 'NOT_FOUND' || !this.legacy) throw error;
      return this.legacy.load(credentialId);
    }
  }

  async save(credential) {
    return this.primary.save(credential);
  }

  async delete(credentialId) {
    if (await this.primary.delete(credentialId)) return true;
    return this.legacy?.delete?.(credentialId) ?? false;
  }

  async exists(credentialId) {
    return await this.primary.exists(credentialId) || Boolean(await this.legacy?.exists?.(credentialId));
  }

  async list() {
    const primary = await this.primary.list();
    const legacy = this.legacy?.list ? await this.legacy.list() : [];
    const seen = new Set(primary.map((credential) => credential.credentialId));
    const combined = [...primary, ...legacy.filter((credential) => !seen.has(credential.credentialId))];
    assertUniqueCredentialKeys(combined);
    return combined;
  }

  async listLegacyTokens() {
    if (!this.legacy?.listLegacyTokens) {
      throw new Error('CompositeCredentialStoreAdapter requires a legacy adapter for token workflows');
    }
    return this.legacy.listLegacyTokens();
  }
}
