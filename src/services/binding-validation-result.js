/**
 * Secret-free result used by binding-time authorization checks.
 *
 * The result is deliberately a data object rather than an exception: callers
 * can render a safe Reference Check while the write boundary still re-runs
 * the same validation and throws a classified error when it is blocked.
 */
export function bindingValidationResult({
  decision,
  pathId = 'BIND-GRANT-CREATE',
  referenceType = 'Credential',
  referenceOwner = 'Core',
  consumerId = null,
  credentialId = null,
  providerKey = null,
  reasonCode = null,
  reason = null,
  remediationHint = null,
  checkedAt = new Date()
} = {}) {
  return Object.freeze({
    decision,
    pathId,
    referenceType,
    referenceOwner,
    ...(consumerId ? { consumerId } : {}),
    ...(credentialId ? { credentialId } : {}),
    ...(providerKey ? { providerKey } : {}),
    ...(reasonCode ? { reasonCode } : {}),
    ...(reason ? { reason } : {}),
    ...(remediationHint ? { remediationHint } : {}),
    checkedAt: checkedAt instanceof Date ? checkedAt.toISOString() : new Date(checkedAt).toISOString()
  });
}

export function bindingValidationError(result, { statusCode = 400 } = {}) {
  const error = new Error(result.reason ?? 'Binding cannot be authorized');
  error.code = result.reasonCode ?? 'BINDING_NOT_AUTHORIZED';
  error.statusCode = statusCode;
  error.details = { binding: result };
  error.bindingResult = result;
  return error;
}
