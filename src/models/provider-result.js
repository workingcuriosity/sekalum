import { safeError } from '../utils/safe-diagnostics.js';

export class ProviderResult {
  constructor({ success, data = null, error = null }) {
    this.success = Boolean(success);
    this.data = data;
    this.error = error;

    Object.freeze(this);
  }

  static success(data = null) {
    return new ProviderResult({
      success: true,
      data,
      error: null
    });
  }

  static failure(error) {
    return new ProviderResult({
      success: false,
      data: null,
      error: ProviderResult.normalizeError(error)
    });
  }

  static normalizeError(error) {
    const normalized = safeError(error, { fallbackMessage: 'Provider operation failed' });
    const name = error instanceof Error ? normalized.name : 'ProviderError';
    return {
      name: name || 'ProviderError',
      message: normalized.message,
      ...(normalized.code ? { code: normalized.code } : {}),
      ...(normalized.statusCode ? { statusCode: normalized.statusCode } : {}),
      ...(normalized.status ? { status: normalized.status } : {}),
      ...(normalized.classification ? { classification: normalized.classification } : {})
    };
  }
}
