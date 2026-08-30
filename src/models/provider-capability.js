export const ProviderCapability = Object.freeze({
  OAUTH: 'oauth',
  REFRESH: 'refresh',
  HEALTH_CHECK: 'health-check',
  REVOKE: 'revoke',
  VALIDATION: 'validation',
  RUNTIME_DERIVATION: 'runtime-derivation',
  BACKUP: 'backup',
  SCHEDULER: 'scheduler'
});

export const ProviderOperationCapabilities = Object.freeze([
  ProviderCapability.OAUTH,
  ProviderCapability.REFRESH,
  ProviderCapability.HEALTH_CHECK,
  ProviderCapability.REVOKE,
  ProviderCapability.VALIDATION,
  ProviderCapability.RUNTIME_DERIVATION
]);

const providerOperationCapabilitySet = new Set(ProviderOperationCapabilities);

export function isProviderOperationCapability(capability) {
  return providerOperationCapabilitySet.has(capability);
}
