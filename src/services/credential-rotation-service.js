import { safeError } from '../utils/safe-diagnostics.js';

export class CredentialRotationService {
  constructor({
    credentialManager,
    credentialPolicyService,
    auditLogService = null,
    lifecycleNotificationService = null,
    providerRotationFramework = null,
    clock = () => new Date()
  } = {}) {
    this.credentialManager = credentialManager;
    this.credentialPolicyService = credentialPolicyService;
    this.auditLogService = auditLogService;
    this.lifecycleNotificationService = lifecycleNotificationService;
    this.providerRotationFramework = providerRotationFramework;
    this.clock = clock;
  }

  async planRotation({ referenceDate = this.clock(), includeWarnings = false } = {}) {
    this.#assertDependencies('planRotation');

    const list = this.credentialManager.listCredentialMetadata ?? this.credentialManager.listCredentials;
    const credentials = await list.call(this.credentialManager);
    const plannedAt = this.#timestamp(referenceDate);
    const candidates = [];
    const skipped = [];

    for (const credential of credentials) {
      const evaluation = await this.credentialPolicyService.evaluateCredential(credential, referenceDate);
      const rotationFindings = this.#rotationFindings(evaluation, includeWarnings);

      if (rotationFindings.length === 0) {
        skipped.push({
          credentialId: this.#credentialId(credential),
          providerKey: this.#providerKey(credential),
          reason: 'rotation-not-required'
        });
        continue;
      }

      candidates.push({
        credentialId: this.#credentialId(credential),
        providerKey: this.#providerKey(credential),
        findings: rotationFindings,
        policies: evaluation.matchedPolicies.map((policy) => ({
          policyId: policy.policyId,
          name: policy.name,
          rotationIntervalDays: policy.rotationIntervalDays,
          criticality: policy.criticality
        }))
      });
    }

    return {
      plannedAt,
      requested: credentials.length,
      candidates: candidates.length,
      skipped: skipped.length,
      items: candidates,
      skippedItems: skipped
    };
  }

  async rotateDueCredentials(options = {}, context = {}) {
    this.#assertDependencies('rotateDueCredentials');

    const plan = await this.planRotation(options);
    const results = [];

    for (const item of plan.items) {
      let committedRotation = null;
      let completionAuditFailure = null;
      try {
        await this.#recordAudit('credential-rotation.started', item, context, 'success');
        const frameworkResult = await this.#rotateWithProviderFramework(item, context);

        if (frameworkResult.skipped) {
          await this.#recordAudit('credential-rotation.skipped', item, context, 'skipped', null, {
            reason: frameworkResult.reason
          });
          results.push(frameworkResult);
          continue;
        }

        committedRotation = frameworkResult;
        try {
          await this.#recordAudit('credential-rotation.completed', item, context, 'success');
        } catch (auditError) {
          completionAuditFailure = auditError;
          throw auditError;
        }
        await this.#recordRotationNotification({ ...item, success: true }, context);
        results.push({
          credentialId: item.credentialId,
          providerKey: item.providerKey,
          success: true,
          skipped: false,
          findings: item.findings,
          credential: this.#toJSON(frameworkResult.credential)
        });
      } catch (error) {
        if (committedRotation && completionAuditFailure) {
          const auditFailure = {
            code: 'AUDIT_PERSISTENCE_FAILED',
            message: 'Credential rotation committed but completion audit persistence failed'
          };
          try {
            await this.#recordAudit('credential-rotation.audit-failed', item, context, 'failure', completionAuditFailure, {
              committed: true,
              auditPersistenceFailed: true
            });
          } catch {
            // Preserve the explicit committed-mutation outcome when audit storage remains unavailable.
          }
          await this.#recordRotationNotification({
            ...item,
            success: true,
            committed: true,
            auditPersistenceFailed: true,
            error: auditFailure
          }, context);
          results.push({
            credentialId: item.credentialId,
            providerKey: item.providerKey,
            success: true,
            committed: true,
            auditPersistenceFailed: true,
            skipped: false,
            findings: item.findings,
            credential: this.#toJSON(committedRotation.credential),
            error: auditFailure
          });
          continue;
        }
        const safe = safeError(error, { fallbackMessage: 'Credential rotation failed' });
        await this.#recordAudit('credential-rotation.failed', item, context, 'failure', error);
        await this.#recordRotationNotification({
          ...item,
          success: false,
          error: {
            code: safe.code ?? 'CREDENTIAL_ROTATION_FAILED',
            message: safe.message
          }
        }, context);
        results.push({
          credentialId: item.credentialId,
          providerKey: item.providerKey,
          success: false,
          findings: item.findings,
          error: {
            code: safe.code ?? 'CREDENTIAL_ROTATION_FAILED',
            message: safe.message
          }
        });
      }
    }

    const succeeded = results.filter((result) => result.success).length;
    const skipped = results.filter((result) => result.skipped).length;
    const failed = results.length - succeeded - skipped;

    return {
      rotatedAt: this.#timestamp(options.referenceDate ?? this.clock()),
      planned: plan.candidates,
      succeeded,
      failed,
      skipped: plan.skipped + skipped,
      results
    };
  }


  async #rotateWithProviderFramework(item, context = {}) {
    if (this.providerRotationFramework?.rotateCredential) {
      return this.providerRotationFramework.rotateCredential(item, context);
    }

    const rotationResult = await this.credentialManager.refresh(item.credentialId);
    const rotatedCredential = this.#normalizeRotationResult(rotationResult);

    return {
      credentialId: item.credentialId,
      providerKey: item.providerKey,
      success: true,
      skipped: false,
      findings: item.findings,
      credential: this.#toJSON(rotatedCredential)
    };
  }

  async #recordRotationNotification(result, context = {}) {
    if (!this.lifecycleNotificationService?.createForRotationResult) return;
    await this.lifecycleNotificationService.createForRotationResult(result, context);
  }

  #normalizeRotationResult(result) {
    if (typeof result?.success === 'boolean') {
      if (!result.success) {
        const error = new Error(result.error?.message ?? 'Credential rotation failed');
        error.code = result.error?.code ?? 'PROVIDER_ROTATION_FAILED';
        throw error;
      }

      return result.data?.credential ?? result.data;
    }

    return result?.credential ?? result;
  }

  #rotationFindings(evaluation, includeWarnings) {
    const violations = evaluation.violations.filter((violation) => violation.type === 'rotation-overdue');
    const warnings = includeWarnings
      ? evaluation.warnings.filter((warning) => warning.type === 'rotation-date-missing')
      : [];
    return [...violations, ...warnings];
  }

  async #recordAudit(action, item, context = {}, result = 'success', error = null, extraDetails = {}) {
    if (!this.auditLogService?.record) return;

    await this.auditLogService.record({
      userId: context.userId,
      roleKey: context.roleKey,
      action,
      targetType: 'credential',
      targetId: item.credentialId,
      result,
      details: {
        providerKey: item.providerKey,
        findings: item.findings,
        error: error ? safeError(error) : null,
        ...extraDetails
      }
    });
  }

  #assertDependencies(operation) {
    if (!(this.credentialManager?.listCredentialMetadata || this.credentialManager?.listCredentials) || !this.credentialManager?.refresh) {
      throw new Error(`CredentialRotationService.${operation}() requires credentialManager with listCredentials and refresh`);
    }

    if (!this.credentialPolicyService?.evaluateCredential) {
      throw new Error(`CredentialRotationService.${operation}() requires credentialPolicyService`);
    }
  }

  #credentialId(credential) {
    return this.#toJSON(credential)?.credentialId ?? null;
  }

  #providerKey(credential) {
    return this.#toJSON(credential)?.providerKey ?? null;
  }

  #toJSON(value) {
    return typeof value?.toJSON === 'function' ? value.toJSON() : value;
  }

  #timestamp(value) {
    const date = value instanceof Date ? value : new Date(value);
    return date.toISOString();
  }
}
