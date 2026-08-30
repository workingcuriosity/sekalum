export function oauthConfigurationValue({
  providerConfiguration = {},
  field,
  config,
  environmentKey,
  required = true
}) {
  const configured = providerConfiguration?.[field];
  if (configured !== undefined && configured !== null && String(configured).trim() !== '') {
    assertResolvedValue(configured, field);
    return configured;
  }

  const fallback = config?.get?.(environmentKey)
    ?? (required ? config?.require?.(environmentKey) : null)
    ?? null;
  if (fallback !== null && fallback !== undefined && String(fallback).trim() !== '') {
    assertResolvedValue(fallback, field);
    return fallback;
  }

  if (!required) return null;

  const error = new Error('Required provider configuration is missing');
  error.code = 'PROVIDER_CONFIGURATION_MISSING';
  error.statusCode = 400;
  throw error;
}

export function assertResolvedValue(value, field = 'provider configuration') {
  if (typeof value !== 'string') return value;
  const text = value.trim();
  if (/^\$\{[^}]+\}$/.test(text) || /^\{\{[^}]+\}\}$/.test(text)
    || /^(?:TODO|CHANGEME|REPLACE_ME|REPLACE-?THIS)$/i.test(text)) {
    const error = new Error(`Unresolved placeholder in ${field}`);
    error.code = 'PROVIDER_CONFIGURATION_PLACEHOLDER';
    error.statusCode = 400;
    throw error;
  }
  return value;
}
