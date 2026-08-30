import crypto from 'node:crypto';
import { assertResolvedValue } from '../oauth/oauth-provider-configuration.js';

export const PROVIDER_CONFIGURATION_LIFECYCLE = Object.freeze({
  TEMPORARY_OAUTH_FLOW: 'temporary_oauth_flow'
});

export class ProviderConfigurationService {
  constructor({ store, providerRegistry = null }) {
    if (!store?.load || !store?.save) {
      throw new Error('ProviderConfigurationService requires ProviderConfigurationStore');
    }
    this.store = store;
    this.providerRegistry = providerRegistry;
  }

  async prepare({
    providerKey,
    fields = [],
    values,
    configurationId = null,
    providerProfile = null,
    temporary = false,
    expiresAt = null
  }) {
    const definitions = fields.filter((field) => field.section === 'providerConfiguration');
    const input = values && typeof values === 'object' && !Array.isArray(values)
      ? values
      : {};
    const allowedKeys = new Set(definitions.map((field) => field.key));
    const configuration = {};
    const missing = [];

    for (const field of definitions) {
      const value = input[field.key];
      if (field.required && (value === undefined || value === null || String(value).trim() === '')) {
        missing.push(field.key);
        continue;
      }
      if (value !== undefined && value !== null && String(value).trim() !== '') {
        assertResolvedValue(value, field.key);
        configuration[field.key] = typeof value === 'string' ? value.trim() : value;
      }
    }

    if (missing.length > 0) {
      throw this.#configurationError(missing);
    }

    for (const key of Object.keys(input)) {
      if (!allowedKeys.has(key)) {
        const error = new Error('Provider configuration contains unsupported fields');
        error.code = 'PROVIDER_CONFIGURATION_INVALID';
        error.statusCode = 400;
        throw error;
      }
    }

    const now = new Date().toISOString();
    const record = {
      configurationId: configurationId ?? crypto.randomUUID(),
      providerKey,
      providerProfile: providerProfile?.identity?.() ?? providerProfile ?? null,
      configuration,
      createdAt: now,
      updatedAt: now,
      ...(temporary
        ? {
            lifecycle: PROVIDER_CONFIGURATION_LIFECYCLE.TEMPORARY_OAUTH_FLOW,
            expiresAt: expiresAt ?? null
          }
        : {})
    };

    await this.store.save(record);
    return record;
  }

  async load(configurationId, providerKey = null, providerProfile = null) {
    const record = await this.store.load(configurationId);
    if (providerKey && record.providerKey !== providerKey) {
      const error = new Error('Provider configuration does not match provider');
      error.code = 'PROVIDER_CONFIGURATION_INVALID';
      error.statusCode = 400;
      throw error;
    }
    if (providerProfile && (!record.providerProfile || record.providerProfile.digest !== providerProfile.digest)) {
      const error = new Error('Provider configuration does not match provider profile');
      error.code = 'PROVIDER_PROFILE_MISMATCH';
      error.statusCode = 409;
      throw error;
    }
    return record;
  }

  async migrateLegacyProviderProfiles() {
    if (typeof this.store.list !== 'function') return [];
    const records = await this.store.list();
    const migrated = [];
    for (const record of records) {
      if (record.providerProfile) continue;
      const profile = this.providerRegistry?.get?.(record.providerKey)?.providerProfile;
      if (!profile) {
        const error = new Error(`Provider configuration '${record.configurationId}' has no resolvable provider profile`);
        error.code = 'PROVIDER_PROFILE_MIGRATION_UNAVAILABLE';
        error.statusCode = 409;
        throw error;
      }
      await this.store.save({ ...record, providerProfile: profile.identity?.() ?? profile });
      migrated.push(record.configurationId);
    }
    return migrated;
  }

  async remove(configurationId, providerKey = null) {
    if (!configurationId) return false;
    await this.load(configurationId, providerKey);
    return this.store.delete(configurationId);
  }

  async removeExpiredTemporaryFlowConfigurations(referencedConfigurationIds = [], now = new Date()) {
    if (typeof this.store.list !== 'function' || typeof this.store.delete !== 'function') {
      return { removed: [], failed: [] };
    }

    const referenced = new Set(referencedConfigurationIds.filter(Boolean));
    const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
    const removed = [];
    const failed = [];
    for (const record of await this.store.list()) {
      if (referenced.has(record.configurationId)) continue;
      if (record.lifecycle !== PROVIDER_CONFIGURATION_LIFECYCLE.TEMPORARY_OAUTH_FLOW) continue;
      const expiresAtMs = new Date(record.expiresAt).getTime();
      if (!Number.isFinite(expiresAtMs) || !Number.isFinite(nowMs) || expiresAtMs > nowMs) continue;
      try {
        if (await this.store.delete(record.configurationId)) removed.push(record.configurationId);
      } catch (error) {
        failed.push({ configurationId: record.configurationId, code: error.code ?? 'PROVIDER_CONFIGURATION_CLEANUP_FAILED' });
      }
    }
    return { removed, failed };
  }

  toPublicJSON(record, fields = []) {
    const secretKeys = new Set(
      fields.filter((field) => field.section === 'providerConfiguration' && field.secret)
        .map((field) => field.key)
    );
    const configuredFields = Object.keys(record.configuration);
    return {
      configurationId: record.configurationId,
      providerKey: record.providerKey,
      configuredFields,
      maskedFields: configuredFields.filter((key) => secretKeys.has(key))
    };
  }

  #configurationError(missingFields) {
    const error = new Error('Required provider configuration is missing');
    error.code = 'PROVIDER_CONFIGURATION_MISSING';
    error.statusCode = 400;
    error.missingFields = [...missingFields];
    return error;
  }
}
