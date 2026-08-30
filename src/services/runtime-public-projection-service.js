import { isProviderProfileMigrationVerified } from '../models/credential.js';

const FORBIDDEN_KEYS = new Set([
  'adapter',
  'adapterKey',
  'credentialId',
  'credentialMethodKey',
  'providerAdapter',
  'providerConfigurationId',
  'providerKey',
  'route',
  'routing'
]);

const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const isRuntimePublicValue = (value) => {
  if (typeof value === 'string') return value.trim() !== '';
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'boolean') return true;
  if (Array.isArray(value)) {
    return value.length > 0 && value.every((entry) => (
      (typeof entry === 'string' && entry.trim() !== '')
      || (typeof entry === 'number' && Number.isFinite(entry))
      || typeof entry === 'boolean'
    ));
  }
  return false;
};

/**
 * Builds the isolated, credential-bound Runtime-Public projection.
 * This service deliberately has no HTTP, Discovery or Consumer dependencies.
 */
export class RuntimePublicProjectionService {
  constructor({ providerConfigurationService, providerRegistry }) {
    if (!providerConfigurationService?.load) {
      throw new Error('RuntimePublicProjectionService requires ProviderConfigurationService');
    }
    if (!providerRegistry?.get) {
      throw new Error('RuntimePublicProjectionService requires ProviderRegistry');
    }

    this.providerConfigurationService = providerConfigurationService;
    this.providerRegistry = providerRegistry;
  }

  async project({ credential } = {}) {
    const binding = this.#binding(credential);
    if (!binding) return null;

    let provider;
    let record;
    try {
      provider = this.providerRegistry.get(binding.providerKey);
      if (provider?.providerProfile && !isProviderProfileMigrationVerified(credential)) return null;
      record = await this.providerConfigurationService.load(
        binding.configurationId,
        binding.providerKey,
        provider.providerProfile ?? null
      );
    } catch {
      return null;
    }

    if (!provider || typeof provider !== 'object') return null;
    if (!this.#validRecord(record, binding)) return null;

    const fields = (provider.credentialFields ?? [])
      .filter((field) => (
        field?.section === 'providerConfiguration'
        && field.runtimePublic === true
        && field.secret !== true
        && !FORBIDDEN_KEYS.has(field.key)
      ));

    const runtimePublic = {};
    for (const field of fields) {
      const value = record.configuration[field.key];
      if (isRuntimePublicValue(value)) {
        runtimePublic[field.key] = Array.isArray(value) ? [...value] : value;
      }
    }

    return Object.keys(runtimePublic).length > 0
      ? { runtimePublic: Object.freeze(runtimePublic) }
      : null;
  }

  #binding(credential) {
    if (!credential || typeof credential.providerKey !== 'string' || credential.providerKey.trim() === '') {
      return null;
    }

    const metadata = credential.metadata?.toJSON?.() ?? credential.metadata ?? {};
    const configurationId = credential.providerConfigurationId
      ?? credential.metadata?.providerConfigurationId
      ?? credential.metadata?.custom?.providerConfigurationId
      ?? metadata.providerConfigurationId
      ?? metadata.custom?.providerConfigurationId;

    if (typeof configurationId !== 'string' || configurationId.trim() === '') return null;

    return {
      configurationId: configurationId.trim(),
      providerKey: credential.providerKey.trim(),
      providerProfile: credential.providerProfile ?? credential.metadata?.custom?.providerProfile ?? null
    };
  }

  #validRecord(record, binding) {
    return isRecord(record)
      && record.configurationId === binding.configurationId
      && record.providerKey === binding.providerKey
      && (!binding.providerProfile || !record.providerProfile || binding.providerProfile.digest === record.providerProfile.digest)
      && isRecord(record.configuration);
  }
}
