// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

export const RestoreDecision = Object.freeze({
  CAN_RESTORE: 'CAN_RESTORE',
  CONFLICTS: 'CONFLICTS',
  BLOCKED: 'BLOCKED',
  NEEDS_RE_CHECK: 'NEEDS_RE_CHECK'
});

export const RestoreConflictClass = Object.freeze({
  HARD_SECURITY_BLOCK: 'HARD_SECURITY_BLOCK',
  EXPLICIT_ADMIN_RESOLUTION: 'EXPLICIT_ADMIN_RESOLUTION'
});

const TERMINAL_CREDENTIAL_STATES = new Set(['revoked', 'deleted']);

import {
  assertCredentialBindingUnchanged,
  credentialBindingMatches,
  credentialBindingProjection,
  digestCredentialBinding,
  IMMUTABLE_CREDENTIAL_BINDING_FIELDS
} from '../security/credential-binding-guard.js';

export {
  assertCredentialBindingUnchanged,
  credentialBindingMatches,
  credentialBindingProjection,
  IMMUTABLE_CREDENTIAL_BINDING_FIELDS
};

export function digestRestoreValue(value) {
  return digestCredentialBinding(value);
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function userProjection(user = {}) {
  return {
    userId: user.userId,
    principalGeneration: user.principalGeneration ?? `legacy:${user.userId}`,
    displayName: user.displayName ?? null,
    email: user.email ?? null,
    roleKey: user.roleKey ?? null,
    status: user.status ?? null,
    createdAt: user.createdAt ?? null,
    updatedAt: user.updatedAt ?? null
  };
}

function credentialProjection(credential = {}) {
  return {
    credentialId: credential.credentialId,
    credentialGeneration: credential.credentialGeneration ?? `legacy:${credential.credentialId}`,
    credentialKey: credential.credentialKey ?? null,
    providerKey: credential.providerKey ?? null,
    credentialMethodKey: credential.credentialMethodKey ?? null,
    externalReference: credential.externalReference ?? null,
    lifecycleState: credential.lifecycleState ?? null,
    providerProfile: credential.providerProfile ?? null,
    providerConfigurationId: credential.providerConfigurationId ?? null,
    metadata: credential.metadata ?? null,
    version: credential.version ?? null,
    createdAt: credential.createdAt ?? null,
    updatedAt: credential.updatedAt ?? null
  };
}

function tombstoneProjection(tombstone = {}) {
  return {
    credentialId: tombstone.credentialId ?? null,
    credentialKey: tombstone.credentialKey ?? null,
    credentialGeneration: tombstone.credentialGeneration ?? null,
    userId: tombstone.userId ?? null,
    principalGeneration: tombstone.principalGeneration ?? null,
    deletedAt: tombstone.deletedAt ?? null,
    version: tombstone.version ?? null
  };
}

function conflict({ classification, code, resourceType, resourceId, remediation }) {
  return {
    class: classification,
    code,
    resourceType,
    resourceId: resourceId ?? null,
    remediation
  };
}

export class RestoreAdmissionService {
  constructor({ accessManagementService = null, auditLogService = null, clock = () => new Date() } = {}) {
    this.accessManagementService = accessManagementService;
    this.auditLogService = auditLogService;
    this.clock = clock;
  }

  async preflightManagementBackup({ backup, actorUserId = null } = {}) {
    const current = await this.#managementState();
    return this.#evaluateManagementBackup(backup, current, { actorUserId });
  }

  async revalidateManagementBackup({ backup, preflight, actorUserId = null } = {}) {
    const current = await this.#managementState();
    const result = this.#evaluateManagementBackup(backup, current, { actorUserId });
    if (result.decision === RestoreDecision.BLOCKED) return result;
    if (preflight?.candidateDigest && result.candidateDigest !== preflight.candidateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'The restore candidate changed after review');
    }
    if (preflight?.stateDigest && result.stateDigest !== preflight.stateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'Current management state changed after review');
    }
    return result;
  }

  async preflightCredentialImport({ credentials = [], existingCredentials = [], tombstones = [], strategy = 'skip', sourceType = 'credential-import' } = {}) {
    return this.#evaluateCredentialImport({ credentials, existingCredentials, tombstones, strategy, sourceType });
  }

  revalidateCredentialImport({ preflight, credentials = [], currentCredentials = [], tombstones = [], strategy = 'skip', skippedCredentialIds = [] } = {}) {
    const result = this.#evaluateCredentialImport({
      credentials,
      existingCredentials: currentCredentials,
      tombstones,
      strategy,
      sourceType: preflight?.sourceType ?? 'credential-import'
    });
    if (result.decision === RestoreDecision.BLOCKED) return result;
    if (preflight?.candidateDigest && result.candidateDigest !== preflight.candidateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'The restore candidate changed after review');
    }
    if (preflight?.stateDigest && result.stateDigest !== preflight.stateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'Current Credential state changed after review');
    }
    return this.#filterSkipped(result, skippedCredentialIds);
  }

  /**
   * Future API-token restore hook.  There is intentionally no API-token
   * restore route or backup format in RC3-06; callers must still pass this
   * fail-closed admission check before any future writer is added.
   */
  preflightApiTokenRestore({ restoredToken, currentToken = null, currentPrincipal = null } = {}) {
    const conflicts = [];
    if (!currentPrincipal) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_PRINCIPAL_CONFLICT',
        resourceType: 'ApiToken',
        resourceId: restoredToken?.id,
        remediation: 'Resolve the current principal identity before restoring an API token.'
      }));
    }
    if (currentToken?.revokedAt) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_TOKEN_REVOKED',
        resourceType: 'ApiToken',
        resourceId: currentToken.id,
        remediation: 'A revoked API token cannot be restored or made effective.'
      }));
    }
    if (currentToken && restoredToken?.id !== currentToken.id) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_STATE_CHANGED',
        resourceType: 'ApiToken',
        resourceId: restoredToken?.id,
        remediation: 'Re-check the current API-token identity.'
      }));
    }
    if (restoredToken?.principalGeneration && currentPrincipal?.principalGeneration
      && restoredToken.principalGeneration !== currentPrincipal.principalGeneration) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_GENERATION_CONFLICT',
        resourceType: 'Principal',
        resourceId: restoredToken.userId,
        remediation: 'The historical API token is bound to a different principal generation.'
      }));
    }
    return this.#result({
      sourceType: 'api-token-future-hook',
      candidate: restoredToken,
      current: { token: currentToken, principal: currentPrincipal },
      conflicts,
      changes: { create: currentToken ? 0 : 1, update: currentToken ? 1 : 0, unchanged: 0, skipped: 0 }
    });
  }

  revalidateApiTokenRestore({ preflight, restoredToken, currentToken = null, currentPrincipal = null } = {}) {
    const result = this.preflightApiTokenRestore({ restoredToken, currentToken, currentPrincipal });
    if (result.decision === RestoreDecision.BLOCKED) return result;
    if (preflight?.candidateDigest && result.candidateDigest !== preflight.candidateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'The API-token candidate changed after review');
    }
    if (preflight?.stateDigest && result.stateDigest !== preflight.stateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'Current API-token state changed after review');
    }
    return result;
  }

  /**
   * Future Grant restore hook.  Grant backup/restore is deliberately absent;
   * the hook prevents a later implementation from reviving authority across
   * a Credential replacement or terminal lifecycle state.
   */
  preflightGrantRestore({ restoredGrant, currentGrant = null, currentCredential = null } = {}) {
    const conflicts = [];
    if (!currentGrant || !currentCredential) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_GRANT_BINDING_CONFLICT',
        resourceType: 'Grant',
        resourceId: restoredGrant?.grantId,
        remediation: 'A historical Grant requires the current Grant and Credential binding.'
      }));
    } else {
      const credentialGeneration = currentCredential.credentialGeneration ?? `legacy:${currentCredential.credentialId}`;
      const grantGeneration = restoredGrant?.credentialGeneration ?? `legacy:${restoredGrant?.credentialId}`;
      if (TERMINAL_CREDENTIAL_STATES.has(currentCredential.lifecycleState)
        || grantGeneration !== credentialGeneration
        || restoredGrant.credentialId !== currentCredential.credentialId
        || restoredGrant.providerKey !== currentCredential.providerKey) {
        conflicts.push(conflict({
          classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
          code: 'RESTORE_GRANT_BINDING_CONFLICT',
          resourceType: 'Grant',
          resourceId: restoredGrant?.grantId,
          remediation: 'Historical Grant authority cannot cross a Credential identity or generation change.'
        }));
      }
    }
    return this.#result({
      sourceType: 'grant-future-hook',
      candidate: restoredGrant,
      current: { grant: currentGrant, credential: credentialProjection(currentCredential ?? {}) },
      conflicts,
      changes: { create: currentGrant ? 0 : 1, update: currentGrant ? 1 : 0, unchanged: 0, skipped: 0 }
    });
  }

  revalidateGrantRestore({ preflight, restoredGrant, currentGrant = null, currentCredential = null } = {}) {
    const result = this.preflightGrantRestore({ restoredGrant, currentGrant, currentCredential });
    if (result.decision === RestoreDecision.BLOCKED) return result;
    if (preflight?.candidateDigest && result.candidateDigest !== preflight.candidateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'The Grant candidate changed after review');
    }
    if (preflight?.stateDigest && result.stateDigest !== preflight.stateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'Current Grant binding changed after review');
    }
    return result;
  }

  preflightSecretVersionRollback({ currentCredential, targetVersion } = {}) {
    const conflicts = [];
    const current = credentialProjection(currentCredential ?? {});
    const target = targetVersion?.toJSON ? targetVersion.toJSON() : targetVersion;
    if (!currentCredential || !target || current.credentialId !== target.credentialId) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_PRINCIPAL_CONFLICT',
        resourceType: 'Credential',
        resourceId: target?.credentialId ?? current.credentialId,
        remediation: 'Use the currently identified Credential only.'
      }));
    } else if (TERMINAL_CREDENTIAL_STATES.has(currentCredential.lifecycleState)) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_TERMINAL_CONFLICT',
        resourceType: 'Credential',
        resourceId: current.credentialId,
        remediation: 'Historical Secret values cannot be applied to a terminal Credential.'
      }));
    } else {
      const historicalGeneration = target.metadata?.credentialGeneration;
      if (!historicalGeneration) {
        conflicts.push(conflict({
          classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
          code: 'RESTORE_GENERATION_CONFLICT',
          resourceType: 'CredentialSecretVersion',
          resourceId: current.credentialId,
          remediation: 'Historical Secret-version identity evidence is unavailable; create a fresh version on the current Credential.'
        }));
      } else if (historicalGeneration !== current.credentialGeneration) {
        conflicts.push(conflict({
          classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
          code: 'RESTORE_GENERATION_CONFLICT',
          resourceType: 'Credential',
          resourceId: current.credentialId,
          remediation: 'Re-check the current Credential identity line.'
        }));
      }
    }
    return this.#result({
      sourceType: 'secret-version',
      candidate: target,
      current: { credential: current },
      conflicts,
      changes: { create: 0, update: conflicts.length === 0 ? 1 : 0, unchanged: 0, skipped: 0 }
    });
  }

  revalidateSecretVersionRollback({ preflight, currentCredential, targetVersion } = {}) {
    const result = this.preflightSecretVersionRollback({ currentCredential, targetVersion });
    if (result.decision === RestoreDecision.BLOCKED) return result;
    if (preflight?.candidateDigest && result.candidateDigest !== preflight.candidateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'The Secret version changed after review');
    }
    if (preflight?.stateDigest && result.stateDigest !== preflight.stateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'Current Credential state changed after review');
    }
    return result;
  }

  preflightLegacyProviderTokenRestore({ restoredToken, currentToken = null, currentCredential = null } = {}) {
    const conflicts = [];
    const resourceId = restoredToken?.providerId ?? null;
    if (!currentCredential) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_PRINCIPAL_CONFLICT',
        resourceType: 'Credential',
        resourceId,
        remediation: 'A provider/account match is insufficient; resolve the current Credential identity first.'
      }));
    } else if (TERMINAL_CREDENTIAL_STATES.has(currentCredential.lifecycleState)) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_TERMINAL_CONFLICT',
        resourceType: 'Credential',
        resourceId: currentCredential.credentialId,
        remediation: 'The mapped Credential is terminal and cannot be revived by a provider-token restore.'
      }));
    } else if (restoredToken?.credentialKey && restoredToken.credentialKey !== currentCredential.credentialKey) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_GENERATION_CONFLICT',
        resourceType: 'Credential',
        resourceId: currentCredential.credentialId,
        remediation: 'The historical provider token is bound to a different Credential identity.'
      }));
    } else if (restoredToken?.credentialGeneration
      && restoredToken.credentialGeneration !== currentCredential.credentialGeneration) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_GENERATION_CONFLICT',
        resourceType: 'Credential',
        resourceId: currentCredential.credentialId,
        remediation: 'The historical provider token is bound to a different Credential generation.'
      }));
    } else if (restoredToken?.provider !== currentCredential.providerKey
      || restoredToken?.accountId !== currentCredential.externalReference) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_STATE_CHANGED',
        resourceType: 'Credential',
        resourceId: currentCredential.credentialId,
        remediation: 'Provider and account identity must match the current mapped Credential.'
      }));
    }
    if (currentToken && restoredToken?.providerId !== currentToken.providerId) {
      conflicts.push(conflict({
        classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
        code: 'RESTORE_STATE_CHANGED',
        resourceType: 'TokenRecord',
        resourceId,
        remediation: 'Re-check the current provider/account identity.'
      }));
    }
    return this.#result({
      sourceType: 'legacy-provider-token',
      candidate: restoredToken?.toJSON ? restoredToken.toJSON() : restoredToken,
      current: {
        token: currentToken?.toJSON ? currentToken.toJSON() : currentToken,
        credential: credentialProjection(currentCredential ?? {})
      },
      conflicts,
      changes: { create: currentToken ? 0 : 1, update: currentToken ? 1 : 0, unchanged: 0, skipped: 0 }
    });
  }

  revalidateLegacyProviderTokenRestore({ preflight, restoredToken, currentToken = null, currentCredential = null } = {}) {
    const result = this.preflightLegacyProviderTokenRestore({ restoredToken, currentToken, currentCredential });
    if (result.decision === RestoreDecision.BLOCKED) return result;
    if (preflight?.candidateDigest && result.candidateDigest !== preflight.candidateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'The provider-token candidate changed after review');
    }
    if (preflight?.stateDigest && result.stateDigest !== preflight.stateDigest) {
      return this.#recheckResult(result, 'RESTORE_STATE_CHANGED', 'Current provider-token state changed after review');
    }
    return result;
  }

  assertCommitAllowed(result, { allowExplicitAdminResolution = false } = {}) {
    if (!result || result.decision === RestoreDecision.BLOCKED || result.decision === RestoreDecision.NEEDS_RE_CHECK) {
      throw this.errorFromResult(result, 'RESTORE_ADMISSION_UNAVAILABLE');
    }
    if (result.decision === RestoreDecision.CONFLICTS && !allowExplicitAdminResolution) {
      const resolution = result.conflicts.find((item) => item.class === RestoreConflictClass.EXPLICIT_ADMIN_RESOLUTION);
      throw this.errorFromConflict(resolution ?? conflict({
        classification: RestoreConflictClass.EXPLICIT_ADMIN_RESOLUTION,
        code: 'RESTORE_PRINCIPAL_CONFLICT',
        resourceType: 'Restore',
        resourceId: null,
        remediation: 'An explicit administrative resolution is required.'
      }));
    }
    return result;
  }

  errorFromResult(result, fallbackCode = 'RESTORE_CONFLICT') {
    const selected = result?.conflicts?.[0];
    if (selected) return this.errorFromConflict(selected);
    const error = new Error('Restore admission could not be proven safe');
    error.code = fallbackCode;
    error.statusCode = fallbackCode === 'RESTORE_ATOMICITY_UNSUPPORTED' ? 501 : 422;
    error.classification = RestoreConflictClass.HARD_SECURITY_BLOCK;
    error.details = { decision: result?.decision ?? RestoreDecision.BLOCKED };
    return error;
  }

  errorFromConflict(item) {
    const error = new Error(this.#messageForConflict(item));
    error.code = item?.code ?? 'RESTORE_CONFLICT';
    error.statusCode = ['RESTORE_ADMISSION_UNAVAILABLE'].includes(error.code) ? 422 : 409;
    error.classification = item?.class ?? RestoreConflictClass.HARD_SECURITY_BLOCK;
    error.details = {
      resourceType: item?.resourceType ?? null,
      resourceId: item?.resourceId ?? null,
      remediation: item?.remediation ?? null
    };
    return error;
  }

  #evaluateManagementBackup(backup, current, { actorUserId = null } = {}) {
    const candidateUsers = backup?.data?.users ?? [];
    const currentUsers = current.users ?? [];
    const currentById = new Map(currentUsers.map((user) => [user.userId, user]));
    const tombstones = current.principalTombstones ?? [];
    const tombstoneById = new Map(tombstones.map((item) => [item.userId, item]));
    const conflicts = [];
    const changes = { create: 0, update: 0, unchanged: 0, skipped: 0 };

    for (const candidate of candidateUsers) {
      const existing = currentById.get(candidate.userId);
      const tombstone = tombstoneById.get(candidate.userId);
      if (tombstone && (!existing || existing.principalGeneration !== candidate.principalGeneration)) {
        conflicts.push(conflict({
          classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
          code: 'RESTORE_DELETED_IDENTITY_BARRIER',
          resourceType: 'Principal',
          resourceId: candidate.userId,
          remediation: 'Use a new principal identity; do not reuse a deleted identity line.'
        }));
        continue;
      }
      if (!existing) {
        changes.create += 1;
        continue;
      }
      if (existing.principalGeneration !== (candidate.principalGeneration ?? `legacy:${candidate.userId}`)) {
        conflicts.push(conflict({
          classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
          code: 'RESTORE_GENERATION_CONFLICT',
          resourceType: 'Principal',
          resourceId: candidate.userId,
          remediation: 'The historical principal generation is not the current identity line.'
        }));
        continue;
      }
      const changed = ['displayName', 'email', 'roleKey', 'status'].some((field) => (existing[field] ?? null) !== (candidate[field] ?? null));
      if (changed) {
        conflicts.push(conflict({
          classification: RestoreConflictClass.EXPLICIT_ADMIN_RESOLUTION,
          code: 'RESTORE_PRINCIPAL_CONFLICT',
          resourceType: 'Principal',
          resourceId: candidate.userId,
          remediation: 'Confirm a fresh non-terminal administrative resolution.'
        }));
        changes.update += 1;
      } else {
        changes.unchanged += 1;
      }
    }

    for (const currentUser of currentUsers) {
      if (candidateUsers.some((candidate) => candidate.userId === currentUser.userId)) continue;
      conflicts.push(conflict({
        classification: RestoreConflictClass.EXPLICIT_ADMIN_RESOLUTION,
        code: 'RESTORE_PRINCIPAL_CONFLICT',
        resourceType: 'Principal',
        resourceId: currentUser.userId,
        remediation: 'Confirm removal of this non-terminal current principal as a new administrative mutation.'
      }));
      changes.update += 1;
    }

    return this.#result({
      sourceType: 'management-backup',
      candidate: { backupId: backup?.backupId, schemaVersion: backup?.schemaVersion, generatedAt: backup?.generatedAt, data: backup?.data },
      current: { users: currentUsers, roles: current.roles ?? [], principalTombstones: tombstones },
      conflicts,
      changes,
      actor: { actorId: actorUserId, requiredPermission: 'backup:manage' }
    });
  }

  #evaluateCredentialImport({ credentials, existingCredentials, tombstones, strategy, sourceType }) {
    const current = existingCredentials.map((entry) => (entry?.toJSON ? entry.toJSON() : entry));
    const candidates = credentials.map((entry) => (entry?.toJSON ? entry.toJSON() : entry));
    const currentById = new Map(current.map((entry) => [entry.credentialId, entry]));
    const conflicts = [];
    const items = [];
    const changes = { create: 0, update: 0, unchanged: 0, skipped: 0 };

    for (const candidate of candidates) {
      const byId = currentById.get(candidate.credentialId);
      const byIdentity = byId ?? current.find((entry) => entry.providerKey === candidate.providerKey
        && entry.credentialMethodKey === candidate.credentialMethodKey
        && entry.externalReference === candidate.externalReference);
      const tombstone = tombstones.find((entry) => entry.credentialId === candidate.credentialId);
      const itemConflicts = [];

      if (tombstone && !byId) {
        itemConflicts.push(conflict({
          classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
          code: 'RESTORE_DELETED_IDENTITY_BARRIER',
          resourceType: 'Credential',
          resourceId: candidate.credentialId,
          remediation: 'Rename to a new identity admitted by the current Credential store.'
        }));
      }

      if (byIdentity) {
        if (TERMINAL_CREDENTIAL_STATES.has(byIdentity.lifecycleState) && strategy !== 'skip') {
          itemConflicts.push(conflict({
            classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
            code: 'RESTORE_TERMINAL_CONFLICT',
            resourceType: 'Credential',
            resourceId: byIdentity.credentialId,
            remediation: 'A terminal Credential cannot be made consumable by historical import.'
          }));
        }
        const sameId = byIdentity.credentialId === candidate.credentialId;
        if (sameId && !credentialBindingMatches(byIdentity, candidate, { includeIdentityAnchors: false })) {
          itemConflicts.push(conflict({
            classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
            code: 'RESTORE_IMMUTABLE_BINDING_CONFLICT',
            resourceType: 'Credential',
            resourceId: byIdentity.credentialId,
            remediation: 'Overwrite cannot change the Credential provider, account, method, profile, configuration, or OAuth binding.'
          }));
        }
        const candidateGeneration = candidate.credentialGeneration ?? `legacy:${candidate.credentialId}`;
        const existingGeneration = byIdentity.credentialGeneration ?? `legacy:${byIdentity.credentialId}`;
        if (sameId && candidateGeneration !== existingGeneration) {
          itemConflicts.push(conflict({
            classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
            code: 'RESTORE_GENERATION_CONFLICT',
            resourceType: 'Credential',
            resourceId: byIdentity.credentialId,
            remediation: 'The imported Credential is not on the current identity line.'
          }));
        } else if (!sameId && !candidateGeneration.startsWith('legacy:') && !existingGeneration.startsWith('legacy:') && candidateGeneration !== existingGeneration) {
          itemConflicts.push(conflict({
            classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
            code: 'RESTORE_GENERATION_CONFLICT',
            resourceType: 'Credential',
            resourceId: byIdentity.credentialId,
            remediation: 'Overwrite or rename cannot cross a replacement Credential generation.'
          }));
        }
        if (itemConflicts.length === 0) changes.update += 1;
      } else {
        changes.create += 1;
      }

      conflicts.push(...itemConflicts);
      items.push({
        credentialId: candidate.credentialId,
        targetCredentialId: byIdentity?.credentialId ?? null,
        conflict: itemConflicts[0] ?? null,
        strategy
      });
    }

    return this.#result({
      sourceType,
      candidate: candidates,
      current: { credentials: current, tombstones: tombstones.map(tombstoneProjection) },
      conflicts,
      changes,
      items
    });
  }

  #managementState() {
    if (this.accessManagementService?.getRestoreState) return this.accessManagementService.getRestoreState();
    return Promise.all([
      this.accessManagementService?.listUsers?.() ?? [],
      this.accessManagementService?.listRoles?.() ?? []
    ]).then(([users, roles]) => ({ users, roles, principalTombstones: [] }));
  }

  #result({ sourceType, candidate, current, conflicts, changes, actor = null, items = [] }) {
    const hard = conflicts.filter((item) => item.class === RestoreConflictClass.HARD_SECURITY_BLOCK);
    const explicit = conflicts.filter((item) => item.class === RestoreConflictClass.EXPLICIT_ADMIN_RESOLUTION);
    const decision = hard.length > 0
      ? RestoreDecision.BLOCKED
      : explicit.length > 0
        ? RestoreDecision.CONFLICTS
        : RestoreDecision.CAN_RESTORE;
    return Object.freeze({
      decision,
      sourceType,
      candidateDigest: digestRestoreValue(candidate),
      stateDigest: digestRestoreValue(current),
      checkedAt: this.#timestamp(),
      changes: { ...changes },
      conflicts: conflicts.map((entry) => ({ ...entry })),
      items: items.map((entry) => ({ ...entry })),
      actor: actor ? { ...actor } : null
    });
  }

  #recheckResult(result, code, remediation) {
    const recheck = conflict({
      classification: RestoreConflictClass.HARD_SECURITY_BLOCK,
      code,
      resourceType: 'Restore',
      resourceId: null,
      remediation
    });
    return Object.freeze({
      ...result,
      decision: RestoreDecision.NEEDS_RE_CHECK,
      conflicts: [recheck, ...result.conflicts]
    });
  }

  #filterSkipped(result, skippedCredentialIds) {
    const skipped = new Set(skippedCredentialIds);
    if (skipped.size === 0) return result;
    const actionable = result.items.filter((item) => !skipped.has(item.credentialId));
    const skippedTargets = new Set(result.items
      .filter((item) => skipped.has(item.credentialId))
      .map((item) => item.targetCredentialId)
      .filter(Boolean));
    const conflicts = result.conflicts.filter((item) => (
      !skipped.has(item.resourceId) && !skippedTargets.has(item.resourceId)
    ));
    const hard = conflicts.some((item) => item.class === RestoreConflictClass.HARD_SECURITY_BLOCK);
    const explicit = conflicts.some((item) => item.class === RestoreConflictClass.EXPLICIT_ADMIN_RESOLUTION);
    return Object.freeze({
      ...result,
      decision: hard ? RestoreDecision.BLOCKED : explicit ? RestoreDecision.CONFLICTS : RestoreDecision.CAN_RESTORE,
      items: actionable,
      conflicts,
      changes: { ...result.changes, skipped: skipped.size }
    });
  }

  #messageForConflict(item = {}) {
    switch (item.code) {
      case 'RESTORE_DELETED_IDENTITY_BARRIER': return 'Historical identity is blocked by a deletion barrier';
      case 'RESTORE_GENERATION_CONFLICT': return 'Historical identity generation conflicts with current state';
      case 'RESTORE_TERMINAL_CONFLICT': return 'Current terminal security state blocks historical input';
      case 'RESTORE_TOKEN_REVOKED': return 'A revoked API token cannot be restored';
      case 'RESTORE_GRANT_BINDING_CONFLICT': return 'Historical Grant binding is not current';
      case 'RESTORE_STATE_CHANGED': return 'Current state changed after restore review';
      case 'RESTORE_PRINCIPAL_CONFLICT': return 'Current principal state requires explicit resolution';
      default: return 'Restore admission is blocked or requires re-check';
    }
  }

  #timestamp() {
    const value = this.clock();
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) throw new Error('RestoreAdmissionService clock must return a valid date');
    return date.toISOString();
  }
}
