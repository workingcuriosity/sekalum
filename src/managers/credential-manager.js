import { ProviderResult } from '../models/provider-result.js';
import { Credential } from '../models/credential.js';
import { CredentialMetadata } from '../models/credential-metadata.js';
import { LifecycleState } from '../models/lifecycle-state.js';
import { OAuthResult } from '../models/oauth-result.js';
import { EGRESS_PURPOSES, EgressPolicy, privateExceptionFromConfig } from '../services/egress-policy.js';
import { safeError } from '../utils/safe-diagnostics.js';
import { assertResolvedValue } from '../oauth/oauth-provider-configuration.js';
import { validateNamedIdentifier } from '../security/authorization-identifier.js';
import { withBindingCommitLock } from '../storage/binding-commit-coordinator.js';
import { OAuthCredentialBinding } from '../models/oauth-context-binding.js';
import { assertCredentialBindingUnchanged } from '../security/credential-binding-guard.js';

export class CredentialManager {
  constructor({
    credentialStore = null,
    providerManager = null,
    tokenLifecycleService = null,
    config = null,
    logger = null,
    secretVersioningService = null,
    credentialHistoryService = null,
    auditLogService = null,
    consumerGrantService = null,
    providerConfigurationService = null,
    connectionTargetPolicy = null,
    egressPolicy = null
  } = {}) {
    this.credentialStore = credentialStore;
    this.providerManager = providerManager;
    this.tokenLifecycleService = tokenLifecycleService;
    this.config = config;
    this.logger = logger;
    this.secretVersioningService = secretVersioningService;
    this.credentialHistoryService = credentialHistoryService;
    this.auditLogService = auditLogService;
    this.consumerGrantService = consumerGrantService;
    this.providerConfigurationService = providerConfigurationService;
    this.connectionTargetPolicy = connectionTargetPolicy;
    const allowPrivateNetworks = String(config?.get?.('CONNECTION_TEST_ALLOW_PRIVATE_NETWORKS', 'false')).toLowerCase() === 'true';
    this.egressPolicy = egressPolicy ?? new EgressPolicy({
      allowPrivateNetworks,
      privateException: allowPrivateNetworks ? privateExceptionFromConfig(config) : null
    });
  }

  async register(credentialInput) {
    CredentialMetadata.assertWriteSafe(credentialInput?.metadata ?? {});
    const credential = this.#bindProviderProfile(Credential.from(credentialInput));
    this.#validateCreationContract(credential);
    try {
      await withBindingCommitLock(async () => {
        await this.#assertProviderConfigurationReference(credential);
        await this.#createIfAvailable(credential);
      });
      try {
        await this.#recordSecretVersion(credential, { reason: 'initial-import' });
      } catch (versionError) {
        const rolledBack = await this.#rollbackFailedRegistration(credential, versionError);
        if (rolledBack) {
          throw this.#creationError(
            'CREDENTIAL_SECRET_VERSIONING_FAILED',
            'Credential secret version could not be recorded. No credential was saved',
            500,
            'credential.create.secretVersioningFailed'
          );
        }

        // The credential still exists, so returning success avoids telling the
        // operator that creation failed when the credential is already usable.
        return credential;
      }
    } catch (error) {
      if (error.code?.startsWith('CREDENTIAL_') || error.code?.startsWith('PROVIDER_CONFIGURATION_')) throw error;
      if (error.code?.startsWith('ENCRYPTED_JSON_')) {
        throw this.#creationError('CREDENTIAL_ENCRYPTION_FAILED', 'Credential encryption failed', 500, 'credential.create.encryptionFailed');
      }
      throw this.#creationError('CREDENTIAL_PERSISTENCE_FAILED', 'Credential could not be persisted', 500, 'credential.create.persistenceFailed');
    }
    return credential;
  }

  async #rollbackFailedRegistration(credential, versionError) {
    if (!this.credentialStore?.delete) {
      this.logger?.error?.('Credential secret versioning failed and registration rollback is unavailable', {
        credentialId: credential.credentialId,
        code: versionError?.code ?? 'SECRET_VERSIONING_FAILED'
      });
      return false;
    }

    try {
      const deleted = await this.credentialStore.delete(credential.credentialId);
      if (deleted) return true;

      this.logger?.error?.('Credential secret versioning failed and registration rollback was not confirmed', {
        credentialId: credential.credentialId,
        versioningCode: versionError?.code ?? 'SECRET_VERSIONING_FAILED',
        rollbackCode: 'CREDENTIAL_ROLLBACK_NOT_CONFIRMED'
      });
      return false;
    } catch (rollbackError) {
      this.logger?.error?.('Credential secret versioning failed and registration rollback did not complete', {
        credentialId: credential.credentialId,
        versioningCode: versionError?.code ?? 'SECRET_VERSIONING_FAILED',
        rollbackCode: rollbackError?.code ?? 'CREDENTIAL_ROLLBACK_FAILED'
      });
      return false;
    }
  }

  #validateCreationContract(credential) {
    if (!this.providerManager?.getProvider) return;
    let provider;
    try {
      provider = this.providerManager?.getProvider?.(credential.providerKey);
    } catch {
      throw this.#creationError('CREDENTIAL_PROVIDER_UNKNOWN', 'Credential provider is not registered', 400, 'credential.create.providerUnknown');
    }

    if (!provider) {
      throw this.#creationError('CREDENTIAL_PROVIDER_UNKNOWN', 'Credential provider is not registered', 400, 'credential.create.providerUnknown');
    }

    const boundProfile = credential.providerProfile ?? credential.metadata.toJSON().custom?.providerProfile ?? null;
    if (boundProfile && provider.providerProfile && boundProfile.digest !== provider.providerProfile.digest) {
      throw this.#creationError(
        'CREDENTIAL_PROFILE_MISMATCH',
        'Credential provider profile is stale or incompatible',
        409,
        'credential.create.profileMismatch'
      );
    }

    const fields = this.#credentialFieldsFor(credential, provider, 'credential.create');
    const fieldKeys = new Set(fields.map((field) => field.key));
    for (const secret of credential.secrets) {
      if (!fieldKeys.has(secret.name)) {
        throw this.#creationError('CREDENTIAL_FIELD_INVALID', `Credential secret '${secret.name}' is not defined by the credential method`, 400, 'credential.create.fieldInvalid', { field: secret.name });
      }
    }

    for (const field of fields) {
      if (field.systemManaged || field.section === 'providerConfiguration') continue;
      const value = this.#credentialFieldValue(credential, field);
      const missing = value === undefined || value === null || (typeof value === 'string' && value.trim() === '');
      if (field.required && missing) {
        const code = field.secret ? 'CREDENTIAL_SECRET_MISSING' : 'CREDENTIAL_FIELD_MISSING';
        const messageKey = field.secret ? 'credential.create.secretMissing' : 'credential.create.fieldMissing';
        throw this.#creationError(code, `Required credential field '${field.key}' is missing`, 400, messageKey, { field: field.key });
      }
      if (!missing) this.#validateCredentialField(field, value);
    }
  }

  #credentialFieldsFor(credential, provider, operation) {
    const methods = provider?.credentialMethods ?? [];
    const bindings = provider?.providerMethodBindings ?? [];
    // ProviderManager rejects legacy records at execution time. Retaining this
    // contract branch keeps the manager usable with declarative test doubles
    // and third-party providers while built-in providers are method-based.
    if (methods.length === 0 && bindings.length === 0) return provider?.credentialFields ?? [];
    if (!credential.credentialMethodKey) {
      throw this.#creationError(
        'CREDENTIAL_METHOD_REQUIRED',
        'credentialMethodKey is required for this provider',
        400,
        `${operation}.methodRequired`
      );
    }

    const method = methods.find((candidate) => candidate.key === credential.credentialMethodKey);
    const binding = bindings.find((candidate) => candidate.methodKey === credential.credentialMethodKey);
    if (!method || !binding) {
      throw this.#creationError(
        'CREDENTIAL_METHOD_UNAVAILABLE',
        `Credential method '${credential.credentialMethodKey}' is not available for provider '${credential.providerKey}'`,
        400,
        `${operation}.methodUnavailable`,
        { credentialMethodKey: credential.credentialMethodKey }
      );
    }
    return method.credentialFields ?? [];
  }

  #credentialFieldValue(credential, field) {
    if (field.secret) return credential.secrets.find((secret) => secret.name === field.key)?.value;
    const metadata = credential.metadata.toJSON();
    if (field.key === 'displayName') return metadata.displayName ?? credential.externalReference;
    if (field.key === 'description') return metadata.description;
    if (field.key === 'scopes') return metadata.scopes;
    return metadata.custom?.[field.key] ?? metadata[field.key];
  }

  #validateCredentialField(field, value) {
    try {
      assertResolvedValue(value, field.key);
    } catch {
      throw this.#creationError(
        'CREDENTIAL_PLACEHOLDER_UNRESOLVED',
        `Credential field '${field.key}' contains an unresolved placeholder`,
        400,
        'credential.create.placeholderUnresolved',
        { field: field.key }
      );
    }
    const validation = field.validation ?? {};
    const text = typeof value === 'string' ? value.trim() : null;
    const invalidType = ['api-key', 'password', 'text', 'textarea', 'url', 'email'].includes(field.type) && text === null;
    const tooShort = text !== null && validation.minLength !== undefined && text.length < validation.minLength;
    const tooLong = text !== null && validation.maxLength !== undefined && text.length > validation.maxLength;
    const invalidPattern = text !== null && validation.pattern && !(new RegExp(validation.pattern).test(text));
    const invalidInteger = field.type === 'integer' && (!Number.isInteger(Number(value))
      || (validation.minimum !== undefined && Number(value) < validation.minimum)
      || (validation.maximum !== undefined && Number(value) > validation.maximum));

    if (invalidType || tooShort || tooLong || invalidPattern || invalidInteger) {
      throw this.#creationError('CREDENTIAL_FIELD_INVALID', `Credential field '${field.key}' is invalid`, 400, 'credential.create.fieldInvalid', { field: field.key });
    }
  }

  #creationError(code, message, statusCode, messageKey, details = {}) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    error.messageKey = messageKey;
    error.details = details;
    return error;
  }



  async importCredential(oauthResult) {
    if (!(oauthResult instanceof OAuthResult)) {
      throw new Error('CredentialManager.importCredential() requires an OAuthResult');
    }

    this.#assertStore('importCredential');

    const contextBinding = OAuthCredentialBinding.from(oauthResult.contextBinding);
    if (contextBinding && (contextBinding.providerKey !== oauthResult.provider
      || contextBinding.accountId !== oauthResult.accountId)) {
      throw this.#oauthBindingError('OAUTH_CREDENTIAL_BINDING_MISMATCH', 'OAuth result identity does not match its admitted context');
    }
    if (contextBinding && this.providerManager?.validateOAuthResultBinding) {
      await this.providerManager.validateOAuthResultBinding(contextBinding);
    }

    return withBindingCommitLock(async () => {
    const existing = await this.#findOAuthCredential(oauthResult);
    if (contextBinding && existing) this.#assertCompatibleOAuthCredential(existing, contextBinding);

    const providerProfile = oauthResult.metadata?.providerProfile ?? this.#providerProfileFor(oauthResult.provider);
    const credentialMethodKey = oauthResult.metadata?.credentialMethodKey
      ?? this.#oauthCredentialMethodKeyFor(oauthResult.provider);
    const credential = this.#bindProviderProfile(Credential.from({
      ...(existing?.toJSON?.() ?? {}),
      ...(existing ? { credentialKey: existing.credentialKey } : {}),
      providerKey: oauthResult.provider,
      ...(providerProfile ? { providerProfile } : {}),
      credentialMethodKey: existing?.credentialMethodKey ?? credentialMethodKey,
      ...(contextBinding ? { oauthCredentialBinding: contextBinding.toJSON() } : {}),
      externalReference: oauthResult.accountId,
      lifecycleState: LifecycleState.ACTIVE,
      secrets: [
        { name: 'accessToken', value: oauthResult.accessToken },
        ...(oauthResult.refreshToken ? [{ name: 'refreshToken', value: oauthResult.refreshToken }] : [])
      ],
      metadata: {
        ...(existing?.metadata?.toJSON?.() ?? {}),
        expiresAt: oauthResult.expiresAt,
        scopes: oauthResult.scopes,
        custom: {
          ...(existing?.metadata?.toJSON?.().custom ?? {}),
          ...(oauthResult.accountName ? { accountName: oauthResult.accountName } : {}),
          ...(providerProfile ? { providerProfile } : {}),
          ...oauthResult.metadata
        }
      },
      createdAt: existing?.createdAt ?? new Date(),
      updatedAt: new Date(),
      version: (existing?.version ?? 0) + 1
    }));

    CredentialMetadata.assertWriteSafe(credential.metadata);
    this.#validateCreationContract(credential);
    if (existing?.lifecycleState === LifecycleState.REVOKED || existing?.lifecycleState === LifecycleState.DELETED) {
      throw this.#lifecycleConflict(existing, 'Credential lifecycle is terminal');
    }
    if (existing) await this.#saveLifecycleIfCurrent(credential, { expectedVersion: existing.version });
    else await this.#createIfAvailable(credential);
    return credential;
    });
  }

  #assertCompatibleOAuthCredential(existing, binding) {
    const current = OAuthCredentialBinding.from(existing.oauthCredentialBinding);
    if (!current) throw this.#oauthBindingError('OAUTH_CREDENTIAL_BINDING_MISMATCH', 'Existing Credential has no compatible OAuth binding');
    const sameProfile = current.providerProfile?.digest === binding.providerProfile?.digest;
    const sameScopes = JSON.stringify(current.grantedScopes) === JSON.stringify(binding.grantedScopes);
    if (current.providerKey !== binding.providerKey
      || !sameProfile
      || current.credentialMethodKey !== binding.credentialMethodKey
      || current.providerConfigurationId !== binding.providerConfigurationId
      || current.clientBindingFingerprint !== binding.clientBindingFingerprint
      || current.accountId !== binding.accountId
      || !sameScopes) {
      throw this.#oauthBindingError('OAUTH_CREDENTIAL_BINDING_MISMATCH', 'Existing Credential cannot be silently rebound');
    }
  }

  #oauthBindingError(code, message) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = 409;
    error.messageKey = 'credential.oauth.bindingMismatch';
    return error;
  }

  async importCredentialBatch(operations = [], { createdBy = 'system', beforeCommit = null, onCommitted = null } = {}) {
    this.#assertStore('importCredentialBatch');
    if (!Array.isArray(operations)) {
      throw new Error('CredentialManager.importCredentialBatch() requires an array');
    }
    if (typeof this.credentialStore.applyBatch !== 'function') {
      const error = new Error('Credential import requires an atomic credential store');
      error.code = 'CREDENTIAL_IMPORT_ATOMICITY_UNSUPPORTED';
      error.statusCode = 500;
      throw error;
    }

    const currentCredentials = (await this.credentialStore.list()).map((credential) => Credential.from(credential));
    const currentById = new Map(currentCredentials.map((credential) => [credential.credentialId, credential]));
    const planned = [];
    const plannedTargets = new Set();

    for (const operation of operations) {
      if (!operation || !['create', 'overwrite'].includes(operation.action)) {
        const error = new Error('Credential import operation is invalid');
        error.code = 'CREDENTIAL_IMPORT_OPERATION_INVALID';
        error.statusCode = 400;
        throw error;
      }

      if (operation.action === 'create') {
        const credential = this.#bindProviderProfile(Credential.from(operation.credential));
        CredentialMetadata.assertWriteSafe(credential.metadata);
        this.#validateCreationContract(credential);
        planned.push({
          mode: 'create',
          credential,
          versionReason: 'initial-import',
          sourceCredentialId: operation.sourceCredentialId ?? credential.credentialId,
          resultAction: operation.resultAction ?? 'created'
        });
        continue;
      }

      const targetCredentialId = operation.targetCredentialId;
      if (plannedTargets.has(targetCredentialId)) {
        const error = new Error('Credential import targets the same identity more than once');
        error.code = 'CREDENTIAL_IMPORT_DUPLICATE_TARGET';
        error.statusCode = 409;
        throw error;
      }
      plannedTargets.add(targetCredentialId);

      const existing = currentById.get(targetCredentialId);
      if (!existing) {
        throw this.#lifecycleConflict(null, 'Credential no longer exists', {
          credentialId: targetCredentialId,
          expectedVersion: operation.expectedVersion,
          actualVersion: null,
          reason: 'MISSING'
        });
      }
      if (operation.expectedVersion !== undefined && existing.version !== operation.expectedVersion) {
        throw this.#lifecycleConflict(existing, 'Credential changed before import overwrite', {
          credentialId: targetCredentialId,
          expectedVersion: operation.expectedVersion,
          actualVersion: existing.version,
          reason: 'VERSION_MISMATCH'
        });
      }

      const imported = Credential.from(operation.credential).toJSON();
      try {
        assertCredentialBindingUnchanged(existing, imported, { operation: 'credential import overwrite' });
      } catch (error) {
        const conflict = this.#lifecycleConflict(existing, 'Credential identity binding cannot change during import overwrite', {
          credentialId: targetCredentialId,
          expectedVersion: operation.expectedVersion,
          actualVersion: existing.version,
          reason: 'IMMUTABLE_BINDING'
        });
        conflict.statusCode = error?.statusCode ?? 409;
        throw conflict;
      }
      const credential = Credential.from({
        ...existing.toJSON(),
        ...imported,
        credentialId: existing.credentialId,
        credentialGeneration: existing.credentialGeneration,
        credentialKey: existing.credentialKey,
        createdAt: existing.createdAt,
        updatedAt: new Date(),
        version: existing.version + 1
      });
      CredentialMetadata.assertWriteSafe(credential.metadata);
      this.#validateCreationContract(credential);
      planned.push({
        mode: 'update',
        credential,
        expectedVersion: operation.expectedVersion,
        versionReason: 'credential-import-overwrite',
        sourceCredentialId: operation.sourceCredentialId ?? imported.credentialId,
        resultAction: 'overwritten'
      });
    }

    const finalize = async ({ credentials }) => onCommitted?.({ credentials, operations: planned });
    const afterCommit = async ({ credentials }) => {
      const versionEntries = planned
        .filter((operation) => operation.credential.secrets.length > 0)
        .map((operation) => ({
          credential: operation.credential,
          reason: operation.versionReason,
          createdBy
        }));

      if (versionEntries.length > 0 && this.secretVersioningService?.recordCredentialVersion
        && typeof this.secretVersioningService.recordCredentialVersionsAtomically !== 'function') {
        const error = new Error('Credential import requires atomic Secret-Version persistence');
        error.code = 'CREDENTIAL_IMPORT_ATOMICITY_UNSUPPORTED';
        error.statusCode = 500;
        throw error;
      }

      if (versionEntries.length > 0 && typeof this.secretVersioningService?.recordCredentialVersionsAtomically === 'function') {
        const versionResult = await this.secretVersioningService.recordCredentialVersionsAtomically(versionEntries, {
          onCommitted: () => finalize({ credentials })
        });
        return versionResult.callbackResult;
      }

      return finalize({ credentials });
    };

    const committed = await this.credentialStore.applyBatch(
      planned.map((operation) => ({
        mode: operation.mode,
        credential: operation.credential,
        expectedVersion: operation.expectedVersion
      })),
      {
        beforeCommit: ({ currentCredentials, credentials, tombstones, currentTombstones }) => beforeCommit?.({
          currentCredentials,
          credentials,
          tombstones,
          currentTombstones,
          operations: planned
        }),
        afterCommit
      }
    );

    return {
      credentials: committed.credentials,
      operations: planned,
      callbackResult: committed.callbackResult
    };
  }

  #oauthCredentialMethodKeyFor(providerKey) {
    const provider = this.#providerForUpdate(providerKey);
    const methods = (provider?.credentialMethods ?? []).filter((method) => method.authenticationMethod === 'oauth2');
    if (methods.length !== 1) {
      throw this.#creationError('OAUTH_METHOD_REQUIRED', 'OAuth credential method is not uniquely bound to the provider', 400, 'credential.oauth.methodRequired');
    }
    return methods[0].key;
  }

  #providerProfileFor(providerKey) {
    try {
      return this.providerManager?.getProvider?.(providerKey)?.providerProfile ?? null;
    } catch {
      return null;
    }
  }

  #bindProviderProfile(credential) {
    const providerProfile = this.#providerProfileFor(credential.providerKey);
    if (!providerProfile) return credential;
    const metadata = credential.metadata.toJSON();
    const custom = metadata.custom ?? {};
    if (credential.providerProfile || custom.providerProfile) return credential;
    return Credential.from({
      ...credential.toJSON(),
      providerProfile,
      metadata: {
        ...metadata,
        custom
      }
    });
  }

  async refreshExpiredCredentials(options = {}) {
    this.#assertStore('refreshExpiredCredentials');

    const refreshBeforeDays = Number(
      options.refreshBeforeDays ?? this.config?.get?.('REFRESH_BEFORE_DAYS', 14) ?? 14
    );

    const credentials = await this.credentialStore.list();

    this.logger?.info?.(`Checking ${credentials.length} credential(s) for refresh`);

    const candidates = credentials.filter((credential) =>
      this.#shouldRefreshCredential(credential, refreshBeforeDays)
    );

    for (const credential of candidates) {
      const providerResult = await this.providerManager.refreshCredential(
        this.#providerOperationCredential(credential)
      );

      if (!providerResult.success) {
        throw new Error(
          providerResult.error?.message ??
            `Provider refresh failed for ${credential.credentialId}`
        );
      }

      const oauthResult = providerResult.data;

      if (!(oauthResult instanceof OAuthResult)) {
        throw new Error(
          `Provider refresh did not return OAuthResult for ${credential.credentialId}`
        );
      }

      await this.#persistOAuthRefresh(credential, oauthResult);
    }

    this.logger?.info?.(`Refresh candidates processed: ${candidates.length}`);

    return candidates;
  }

  async load(credentialId) {
    return this.getCredential(credentialId);
  }

  async getCredential(credentialId) {
    this.#assertStore('getCredential');
    return this.credentialStore.load(credentialId);
  }

  async getCredentialByKey(credentialKey) {
    this.#assertStore('getCredentialByKey');
    if (typeof this.credentialStore.loadByCredentialKey === 'function') {
      try {
        return await this.credentialStore.loadByCredentialKey(credentialKey);
      } catch (error) {
        if (error?.code === 'NOT_FOUND' || error?.code === 'CREDENTIAL_IDENTITY_ORPHANED') return null;
        throw error;
      }
    }
    const credentials = await this.credentialStore.list();
    return credentials.find((credential) => credential.credentialKey === credentialKey) ?? null;
  }

  async isDeletedIdentity(credentialId) {
    this.#assertStore('isDeletedIdentity');
    return this.credentialStore.isDeletedIdentity?.(credentialId) ?? false;
  }

  async getRestoreState() {
    this.#assertStore('getRestoreState');
    if (typeof this.credentialStore.getRestoreState === 'function') {
      return this.credentialStore.getRestoreState();
    }
    return { credentials: await this.credentialStore.list(), tombstones: [] };
  }

  async getCredentialMetadata(credentialId) {
    this.#assertStore('getCredentialMetadata');
    if (typeof this.credentialStore.loadMetadata === 'function') {
      return this.credentialStore.loadMetadata(credentialId);
    }
    const credential = await this.credentialStore.load(credentialId);
    return this.#toMetadata(credential);
  }

  async listCredentials(options = {}) {
    this.#assertStore('listCredentials');

    const credentials = await this.credentialStore.list();

    if (!options || Object.keys(options).length === 0) {
      return credentials;
    }

    return this.#queryCredentials(credentials, options);
  }

  async listCredentialMetadata(options = {}) {
    this.#assertStore('listCredentialMetadata');

    const credentials = typeof this.credentialStore.listMetadata === 'function'
      ? await this.credentialStore.listMetadata()
      : (await this.credentialStore.list()).map((credential) => this.#toMetadata(credential));

    if (!options || Object.keys(options).length === 0) {
      return credentials;
    }

    return this.#queryCredentials(credentials, options);
  }

  #queryCredentials(credentials, options = {}) {
    const search = this.#normalizeText(options.search);
    const provider = this.#normalizeText(options.provider);
    const type = this.#normalizeText(options.type);
    const state = this.#normalizeText(options.state);
    const sort = options.sort ?? 'createdAt';
    const order = this.#normalizeText(options.order ?? 'asc');

    if (!['name', 'provider', 'type', 'state', 'expiresAt', 'createdAt', 'updatedAt'].includes(sort)) {
      const error = new Error(`Unsupported credential sort field '${sort}'`);
      error.code = 'UNSUPPORTED_SORT_FIELD';
      throw error;
    }

    if (!['asc', 'desc'].includes(order)) {
      const error = new Error(`Unsupported credential sort order '${options.order}'`);
      error.code = 'UNSUPPORTED_SORT_ORDER';
      throw error;
    }

    const filtered = credentials.filter((credential) => {
      const view = this.#credentialView(credential);

      if (provider && this.#normalizeText(view.providerKey) !== provider) return false;
      if (type && this.#normalizeText(view.type) !== type) return false;
      if (state && this.#normalizeText(view.lifecycleState) !== state) return false;

      if (search) {
        const haystack = [
          view.credentialId,
          view.providerKey,
          view.externalReference,
          view.metadata.displayName,
          view.metadata.description,
          ...(view.metadata.tags ?? [])
        ].filter(Boolean).join(' ').toLowerCase();

        if (!haystack.includes(search)) return false;
      }

      return true;
    });

    return filtered.sort((left, right) => {
      const leftValue = this.#sortValue(this.#credentialView(left), sort);
      const rightValue = this.#sortValue(this.#credentialView(right), sort);

      if (leftValue < rightValue) return order === 'asc' ? -1 : 1;
      if (leftValue > rightValue) return order === 'asc' ? 1 : -1;
      return 0;
    });
  }

  #credentialView(credential) {
    const value = typeof credential?.toJSON === 'function' ? credential.toJSON() : credential;
    const metadata = value?.metadata ?? {};

    return {
      ...value,
      metadata,
      type: metadata.type ?? metadata.credentialType ?? metadata.custom?.type ?? this.#inferCredentialType(value)
    };
  }

  #inferCredentialType(value) {
    const secretNames = value?.secretNames ?? (value?.secrets ?? []).map((secret) => secret.name);

    if (secretNames.includes('apiKey')) return 'api-key';
    if (secretNames.includes('host') || secretNames.includes('password') || secretNames.includes('privateKey')) return 'connection';
    if (secretNames.includes('accessToken') || secretNames.includes('refreshToken')) return 'oauth';

    return value?.metadata?.custom?.credentialType ?? 'unknown';
  }

  #toMetadata(credential) {
    if (typeof credential?.toMetadataJSON === 'function') return credential.toMetadataJSON();
    if (!credential || typeof credential !== 'object') return credential;
    const { secrets: _secrets, ...metadata } = credential;
    return metadata;
  }

  #sortValue(value, field) {
    if (field === 'name') return this.#normalizeText(value.metadata.displayName ?? value.externalReference ?? value.credentialId);
    if (field === 'provider') return this.#normalizeText(value.providerKey);
    if (field === 'type') return this.#normalizeText(value.type);
    if (field === 'state') return this.#normalizeText(value.lifecycleState);
    if (field === 'expiresAt') return value.metadata.expiresAt ? new Date(value.metadata.expiresAt).getTime() : Number.MAX_SAFE_INTEGER;
    if (field === 'updatedAt') return value.updatedAt ? new Date(value.updatedAt).getTime() : 0;
    return value.createdAt ? new Date(value.createdAt).getTime() : 0;
  }

  #normalizeText(value) {
    return String(value ?? '').trim().toLowerCase();
  }


  async updateCredential(credentialId, updates = {}, options = {}) {
    this.#assertStore('updateCredential');

    if (typeof credentialId !== 'string' || credentialId.trim() === '' || credentialId !== credentialId.trim()) {
      throw new Error('CredentialManager.updateCredential() requires a credentialId');
    }

    const existingCredential = await this.getCredential(credentialId);

    if (!existingCredential) {
      throw new Error(`CredentialManager.updateCredential() could not find credential '${credentialId}'`);
    }

    if (options.expectedVersion !== undefined && existingCredential.version !== options.expectedVersion) {
      throw this.#lifecycleConflict(existingCredential, 'Credential changed before update');
    }

    const normalizedUpdates = options.userUpdate
      ? this.#normalizeUserUpdate(existingCredential, updates)
      : updates;

    const nextCredential = Credential.from({
      ...existingCredential.toJSON(),
      ...normalizedUpdates,
      credentialId: existingCredential.credentialId,
      metadata: {
        ...existingCredential.metadata.toJSON(),
        ...(normalizedUpdates.metadata ?? {})
      },
      secrets: this.#updatedSecrets(existingCredential, normalizedUpdates.secrets, {
        ...options,
        replaceSecrets: options.replaceSecrets || (
          normalizedUpdates.credentialMethodKey
          && normalizedUpdates.credentialMethodKey !== existingCredential.credentialMethodKey
        )
      }),
      createdAt: existingCredential.createdAt,
      updatedAt: new Date(),
      version: existingCredential.version + 1
    });

    assertCredentialBindingUnchanged(existingCredential, nextCredential, { operation: 'credential update' });

    this.#validateCreationContract(nextCredential);
    await withBindingCommitLock(async () => {
      await this.#assertProviderConfigurationReference(nextCredential);
      await options.beforeCommit?.({
        currentCredential: existingCredential,
        nextCredential
      });
      await this.#saveLifecycleIfCurrent(nextCredential, { expectedVersion: existingCredential.version });
    });
    if (!options.skipSecretVersionRecord && normalizedUpdates.secrets) {
      try {
        await this.#recordSecretVersion(nextCredential, {
          reason: options.versionReason ?? 'manual-update',
          createdBy: options.createdBy ?? 'system'
        });
      } catch (versionError) {
        const rolledBack = await this.#rollbackFailedUpdate(existingCredential, nextCredential, versionError);
        if (rolledBack) {
          throw this.#creationError(
            'CREDENTIAL_SECRET_VERSIONING_FAILED',
            'Credential update was rolled back because its secret version could not be recorded',
            500,
            'credential.update.secretVersioningFailed'
          );
        }

        // The update still exists, so do not report a failed operation that the
        // caller cannot safely retry without first reading the current state.
        return nextCredential;
      }
    }
    return nextCredential;
  }

  async #rollbackFailedUpdate(existingCredential, nextCredential, versionError) {
    if (!this.credentialStore?.save && !this.credentialStore?.saveConditional) {
      this.logger?.error?.('Credential secret versioning failed and update rollback is unavailable', {
        credentialId: nextCredential.credentialId,
        versioningCode: versionError?.code ?? 'SECRET_VERSIONING_FAILED',
        rollbackCode: 'CREDENTIAL_ROLLBACK_UNAVAILABLE'
      });
      return false;
    }

    try {
      await this.#saveLifecycleIfCurrent(existingCredential, { expectedVersion: nextCredential.version });
      return true;
    } catch (rollbackError) {
      this.logger?.error?.('Credential secret versioning failed and update rollback did not complete', {
        credentialId: nextCredential.credentialId,
        versioningCode: versionError?.code ?? 'SECRET_VERSIONING_FAILED',
        rollbackCode: rollbackError?.code ?? 'CREDENTIAL_ROLLBACK_FAILED'
      });
      return false;
    }
  }

  #updatedSecrets(existingCredential, requestedSecrets, options) {
    const existingSecrets = existingCredential.secrets.map((secret) => secret.toJSON());
    if (!requestedSecrets) return existingSecrets;
    if (options.replaceSecrets) return requestedSecrets;

    const merged = new Map(existingSecrets.map((secret) => [secret.name, secret]));
    for (const secret of requestedSecrets) {
      if (secret?.value === undefined || secret.value === null || String(secret.value).trim() === '') continue;
      merged.set(secret.name, secret);
    }
    return [...merged.values()];
  }

  #normalizeUserUpdate(existingCredential, updates) {
    const allowedTopLevel = new Set(['credentialMethodKey', 'metadata', 'secrets']);
    const unexpected = Object.keys(updates ?? {}).find((key) => !allowedTopLevel.has(key));
    if (unexpected) {
      throw this.#creationError('CREDENTIAL_FIELD_INVALID', `Credential field '${unexpected}' is not editable`, 400, 'credential.update.fieldInvalid');
    }

    const provider = this.#providerForUpdate(existingCredential.providerKey);
    const requestedMethodKey = updates.credentialMethodKey ?? existingCredential.credentialMethodKey;
    const contractCredential = Credential.from({
      ...existingCredential.toJSON(),
      credentialMethodKey: requestedMethodKey
    });
    const fields = this.#credentialFieldsFor(contractCredential, provider, 'credential.update');
    const editableFields = fields.filter((field) => field.visible !== false
      && field.userConfigurable !== false
      && !field.systemManaged
      && !field.readonly
      && field.section !== 'providerConfiguration');
    const editableMetadataFields = new Map(editableFields.filter((field) => !field.secret).map((field) => [field.key, field]));
    const editableSecretFields = new Map(editableFields.filter((field) => field.secret).map((field) => [field.key, field]));
    const requestedMetadata = updates.metadata ?? {};
    const allowedMetadata = new Set(['displayName', 'description', 'tags', 'scopes', 'custom', 'sensitiveMetadata']);
    const unexpectedMetadata = Object.keys(requestedMetadata).find((key) => !allowedMetadata.has(key));
    if (unexpectedMetadata) {
      throw this.#creationError('CREDENTIAL_FIELD_INVALID', `Credential metadata '${unexpectedMetadata}' is not editable`, 400, 'credential.update.fieldInvalid');
    }

    const metadata = {};
    for (const key of ['displayName', 'description', 'tags', 'scopes']) {
      if (Object.hasOwn(requestedMetadata, key)) metadata[key] = requestedMetadata[key];
    }
    const requestedCustom = requestedMetadata.custom ?? {};
    const unexpectedCustom = Object.keys(requestedCustom).find((key) => !editableMetadataFields.has(key));
    if (unexpectedCustom) {
      throw this.#creationError('CREDENTIAL_FIELD_INVALID', `Credential metadata '${unexpectedCustom}' is not editable`, 400, 'credential.update.fieldInvalid');
    }
    if (Object.hasOwn(requestedMetadata, 'sensitiveMetadata')
      && (!requestedMetadata.sensitiveMetadata || typeof requestedMetadata.sensitiveMetadata !== 'object' || Array.isArray(requestedMetadata.sensitiveMetadata))) {
      throw this.#creationError('CREDENTIAL_METADATA_INVALID', 'Credential metadata contains unsupported custom values', 400, 'credential.metadata.invalid');
    }
    const methodChanged = requestedMethodKey !== existingCredential.credentialMethodKey;
    if (Object.keys(requestedCustom).length > 0 || methodChanged) {
      metadata.custom = {
        ...(methodChanged
          ? Object.fromEntries(Object.entries(existingCredential.metadata.toJSON().custom ?? {})
            .filter(([key]) => editableMetadataFields.has(key)))
          : existingCredential.metadata.toJSON().custom ?? {}),
        ...requestedCustom
      };
    }
    if (Object.hasOwn(requestedMetadata, 'sensitiveMetadata')) {
      metadata.sensitiveMetadata = requestedMetadata.sensitiveMetadata;
    }

    try {
      CredentialMetadata.assertWriteSafe(metadata);
    } catch {
      throw this.#creationError('CREDENTIAL_METADATA_INVALID', 'Credential metadata contains unsupported custom values', 400, 'credential.metadata.invalid');
    }

    for (const [key, field] of editableMetadataFields) {
      const value = key === 'displayName'
        ? metadata.displayName
        : key === 'description'
          ? metadata.description
          : key === 'tags'
            ? metadata.tags
            : key === 'scopes'
              ? metadata.scopes
              : requestedCustom[key];
      if (value !== undefined) this.#validateCredentialField(field, value);
    }

    const secrets = (updates.secrets ?? []).flatMap((secret) => {
      const field = editableSecretFields.get(secret?.name);
      if (!field) {
        throw this.#creationError('CREDENTIAL_FIELD_INVALID', `Credential secret '${secret?.name ?? 'unknown'}' is not editable`, 400, 'credential.update.fieldInvalid');
      }
      if (secret.value === undefined || secret.value === null || String(secret.value).trim() === '') return [];
      this.#validateCredentialField(field, secret.value);
      return [{ name: field.key, value: secret.value, type: secret.type ?? field.type }];
    });

    return {
      ...(Object.hasOwn(updates, 'credentialMethodKey') ? { credentialMethodKey: requestedMethodKey } : {}),
      ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
      ...(Object.hasOwn(updates, 'secrets') || methodChanged ? { secrets } : {})
    };
  }

  async migrateLegacyCredentialMethods() {
    this.#assertStore('migrateLegacyCredentialMethods');
    const credentials = await this.credentialStore.list();
    const migrated = [];
    for (const credential of credentials) {
      if (credential.credentialMethodKey) continue;
      const provider = this.#providerForUpdate(credential.providerKey);
      const methods = provider?.credentialMethods ?? [];
      const bindings = provider?.providerMethodBindings ?? [];
      const methodKey = this.#legacyCredentialMethodKey(credential, methods, bindings);
      if (!methodKey) {
        throw this.#creationError(
          'CREDENTIAL_METHOD_MIGRATION_AMBIGUOUS',
          `Credential '${credential.credentialId}' cannot be migrated because provider '${credential.providerKey}' has no unique credential method`,
          409,
          'credential.migration.ambiguous'
        );
      }
      const next = Credential.from({
        ...credential.toJSON(),
        credentialMethodKey: methodKey,
        updatedAt: new Date(),
        version: credential.version + 1
      });
      this.#validateCreationContract(next);
      await this.#saveLifecycleIfCurrent(next, { expectedVersion: credential.version, allowBindingChange: true });
      migrated.push(next.credentialId);
    }
    return migrated;
  }

  async migrateLegacyProviderProfiles() {
    this.#assertStore('migrateLegacyProviderProfiles');
    const credentials = await this.credentialStore.list();
    const migrated = [];
    for (const credential of credentials) {
      if (credential.providerProfileMigration?.migrationComplete === true
        && credential.providerProfileMigration?.migrationVerified === true) continue;
      const providerProfile = this.#providerProfileFor(credential.providerKey);
      if (!providerProfile) {
        throw this.#creationError(
          'CREDENTIAL_PROFILE_MIGRATION_UNAVAILABLE',
          `Credential '${credential.credentialId}' cannot be migrated because provider '${credential.providerKey}' has no profile`,
          409,
          'credential.migration.profileUnavailable'
        );
      }
      const next = Credential.from({
        ...credential.toJSON(),
        providerProfile,
        providerProfileMigration: {
          migrationComplete: true,
          migrationVerified: true,
          profileDigest: providerProfile.digest,
          source: 'legacy-migration'
        },
        updatedAt: new Date(),
        version: credential.version + 1
      });
      this.#validateCreationContract(next);
      await this.#saveLifecycleIfCurrent(next, { expectedVersion: credential.version, allowBindingChange: true });
      migrated.push(next.credentialId);
    }
    return migrated;
  }

  #legacyCredentialMethodKey(credential, methods, bindings) {
    const boundMethodKeys = new Set(bindings.map((binding) => binding.methodKey));
    const methodKeys = new Set(methods.map((method) => method.key).filter((key) => boundMethodKeys.has(key)));
    const metadata = credential.metadata.toJSON();
    const explicitType = metadata.credentialType ?? metadata.custom?.credentialType ?? metadata.custom?.type;
    if (typeof explicitType === 'string' && methodKeys.has(explicitType)) return explicitType;

    // LegacyTokenCredentialStoreAdapter represents OAuth grants as access and
    // optional refresh tokens. That durable source shape deterministically
    // selects oauth2 even for providers (such as Discord) with more methods.
    const secretNames = new Set(credential.secrets.map((secret) => secret.name));
    if ((secretNames.has('accessToken') || secretNames.has('refreshToken')) && methodKeys.has('oauth2')) {
      return 'oauth2';
    }

    return methodKeys.size === 1 ? [...methodKeys][0] : null;
  }

  async migrateCredentialMethod(credentialId, credentialMethodKey) {
    this.#assertStore('migrateCredentialMethod');
    try {
      validateNamedIdentifier('credentialMethodKey', credentialMethodKey);
    } catch (error) {
      if (typeof credentialMethodKey !== 'string' || credentialMethodKey.trim() === '') {
        throw this.#creationError('CREDENTIAL_METHOD_REQUIRED', 'credentialMethodKey is required for migration', 400, 'credential.migration.methodRequired');
      }
      throw error;
    }
    const existingCredential = await this.getCredential(credentialId);
    if (!existingCredential) {
      throw this.#creationError('CREDENTIAL_NOT_FOUND', 'Credential not found', 404, 'credential.migration.notFound');
    }
    const migrated = Credential.from({
      ...existingCredential.toJSON(),
      credentialMethodKey,
      updatedAt: new Date(),
      version: existingCredential.version + 1
    });
    this.#validateCreationContract(migrated);
    await this.#saveLifecycleIfCurrent(migrated, { expectedVersion: existingCredential.version, allowBindingChange: true });
    return migrated;
  }

  #providerForUpdate(providerKey) {
    if (!this.providerManager?.getProvider) return null;
    try {
      return this.providerManager.getProvider(providerKey);
    } catch {
      throw this.#creationError('CREDENTIAL_PROVIDER_UNKNOWN', 'Credential provider is not registered', 400, 'credential.update.providerUnknown');
    }
  }


  async listCredentialHistory(credentialId, options = {}) {
    this.#assertCredentialHistory('listCredentialHistory');
    return this.credentialHistoryService.listCredentialHistory(credentialId, options);
  }

  async summarizeCredentialHistory(credentialId, options = {}) {
    this.#assertCredentialHistory('summarizeCredentialHistory');
    return this.credentialHistoryService.summarizeCredentialHistory(credentialId, options);
  }

  async listSecretVersions(credentialId) {
    this.#assertSecretVersioning('listSecretVersions');
    return this.secretVersioningService.listCredentialVersions(credentialId);
  }

  async rollbackSecretVersion(credentialId, version, context = {}) {
    this.#assertSecretVersioning('rollbackSecretVersion');
    return this.secretVersioningService.rollbackCredentialSecrets(credentialId, version, context);
  }

  async deleteCredential(credentialId, context = {}) {
    this.#assertStore('deleteCredential');

    if (!credentialId) {
      throw new Error('CredentialManager.deleteCredential() requires a credentialId');
    }

    const credential = await this.getCredential(credentialId);

    if (!credential) {
      throw new Error(`CredentialManager.deleteCredential() could not find credential '${credentialId}'`);
    }

    return this.delete(credential, context);
  }

  async delete(credentialOrId, context = {}) {
    let credential = await this.#resolveCredential(credentialOrId);

    if (this.providerManager?.revokeCredential && credential.lifecycleState !== LifecycleState.REVOKED) {
      const revoked = await this.revoke(credential, context);
      if (!revoked.success) {
        if (revoked.error?.classification === 'provider_contract_incompatible') {
          // Providers without a revoke capability retain the established local
          // delete semantics; a real remote revoke failure remains terminally
          // blocked above this boundary.
        } else {
          const error = new Error('Provider revoke failed; credential remains available for retry');
          error.code = revoked.error?.code ?? 'PROVIDER_REVOKE_FAILED';
          if (revoked.error?.statusCode) error.statusCode = revoked.error.statusCode;
          throw error;
        }
      } else {
        credential = revoked.data.credential;
      }
    }

    credential = await this.#persistDecommissioning(credential, 'delete', context);
    if (credential.decommissioning?.providerCleanup?.status !== 'complete'
      && credential.decommissioning?.providerCleanup?.status !== 'not_required'
      && this.providerManager?.revokeCredential) {
      const providerResult = await this.#executeProviderAction('revokeCredential', credential);
      credential = providerResult.success || providerResult.error?.classification === 'provider_contract_incompatible'
        ? await this.#recordDecommissioningStep(credential, 'providerCleanup', providerResult.success ? 'complete' : 'not_required', null, context)
        : await this.#recordDecommissioningFailure(credential, 'providerCleanup', providerResult.error, context);
      if (credential.decommissioning?.providerCleanup?.status !== 'complete') return credential;
    }
    try {
      if (this.consumerGrantService?.cleanupForCredential) {
        await this.consumerGrantService.cleanupForCredential({
          credentialId: credential.credentialId,
          credentialGeneration: credential.credentialGeneration
        });
      }
      credential = await this.#recordDecommissioningStep(credential, 'grantCleanup', 'complete', null, context);
    } catch (error) {
      return this.#recordDecommissioningFailure(credential, 'grantCleanup', error, context);
    }

    const deletedCredential = credential.withLifecycleState(LifecycleState.DELETED);

    await this.#invalidateSecretHistory(credential, 'credential-deleted');

    if (this.credentialStore?.delete) {
      if (typeof this.credentialStore.deleteConditional === 'function') {
        await this.credentialStore.deleteConditional(deletedCredential.credentialId, { expectedVersion: credential.version });
      } else {
        await this.credentialStore.delete(deletedCredential.credentialId);
      }
    }

    await this.#recordLifecycleAudit('credential.deleted', deletedCredential, context, {
      previousState: credential.lifecycleState
    });

    return deletedCredential;
  }

  async validate(credentialOrId) {
    const credential = await this.#resolveCredential(credentialOrId);
    if (this.#isTerminalLifecycle(credential)) {
      return ProviderResult.failure(this.#lifecycleConflict(credential, 'Credential lifecycle is terminal'));
    }
    let connectionCredential;

    try {
      connectionCredential = await this.#prepareConnectionCredential(credential, EGRESS_PURPOSES.PROVIDER_VALIDATION);
    } catch (error) {
      return ProviderResult.failure(error);
    }
    const result = await this.#executeProviderAction('validateCredential', connectionCredential);

    if (!result.success) return result;

    const checkedAt = new Date().toISOString();
    const metadata = credential.metadata.toJSON();
    const validatedCredential = Credential.from({
      ...credential.toJSON(),
      lifecycleState: LifecycleState.ACTIVE,
      metadata: {
        ...metadata,
        custom: {
          ...(metadata.custom ?? {}),
          lastValidatedAt: checkedAt
        }
      },
      updatedAt: new Date(),
      version: credential.version + 1
    });
    const persistedCredential = await this.#saveLifecycleIfCurrent(validatedCredential, { expectedVersion: credential.version });

    return ProviderResult.success({
      credential: persistedCredential,
      provider: result.data
    });
  }

  async testConnection(draftInput) {
    let credential;

    try {
      credential = this.#draftCredentialFrom(draftInput);
      const provider = this.#connectionTestProvider(credential.providerKey);
      this.#validateCreationContract(credential);
      credential = await this.#prepareConnectionCredential(credential, EGRESS_PURPOSES.CREDENTIAL_CONNECTION_TEST);

      const operationContext = ['ftp', 'sftp'].includes(credential.providerKey)
        ? { purpose: EGRESS_PURPOSES.CREDENTIAL_CONNECTION_TEST }
        : {};
      const result = await this.providerManager.validateCredential(credential, operationContext);
      if (!result?.success) throw this.#connectionTestProviderError(result?.error, credential, provider);

      return Object.freeze({
        providerKey: provider.key ?? credential.providerKey,
        status: 'connected',
        messageKey: 'credential.connection.success',
        checkedAt: new Date().toISOString()
      });
    } catch (error) {
      if (error?.code?.startsWith('CREDENTIAL_CONNECTION_')) throw error;
      throw this.#connectionTestError(
        'CREDENTIAL_CONNECTION_INVALID',
        'Credential connection test input is invalid',
        400,
        'credential.connectionTest.invalid',
        error?.details?.field ? { field: error.details.field } : {},
        this.#connectionFailureClassification(error)
      );
    }
  }

  async refresh(credentialOrId, context = {}) {
    const credential = await this.#resolveCredential(credentialOrId);
    if (this.#isTerminalLifecycle(credential)) {
      return ProviderResult.failure(this.#lifecycleConflict(credential, 'Credential lifecycle is terminal'));
    }
    let currentOAuthBinding = null;
    if (credential.oauthCredentialBinding && this.providerManager?.getOAuthClientBinding) {
      try {
        currentOAuthBinding = await this.providerManager.getOAuthClientBinding(credential);
        if (currentOAuthBinding.clientBindingFingerprint !== credential.oauthCredentialBinding.clientBindingFingerprint) {
          return ProviderResult.failure(this.#oauthBindingError('OAUTH_CLIENT_MISMATCH', 'OAuth client binding changed before refresh'));
        }
      } catch (error) {
        return ProviderResult.failure(error);
      }
    }
    const result = await this.#executeProviderAction('refreshCredential', credential);

    if (!result.success) return result;

    const refreshedCredential = result.data instanceof OAuthResult
      ? this.#credentialFromOAuthResult(credential, result.data)
      : Credential.from({
        ...credential.toJSON(),
        ...(result.data?.credential ?? {}),
        lifecycleState: LifecycleState.ACTIVE,
        updatedAt: new Date(),
        version: credential.version + 1
      });

    if (credential.oauthCredentialBinding && result.data instanceof OAuthResult) {
      const binding = credential.oauthCredentialBinding;
      if (result.data.provider !== binding.providerKey || result.data.accountId !== binding.accountId) {
        return ProviderResult.failure(this.#oauthBindingError('OAUTH_ACCOUNT_MISMATCH', 'Refresh evidence attempted an account rebind'));
      }
      if (currentOAuthBinding && currentOAuthBinding.providerProfile?.digest !== binding.providerProfile?.digest) {
        return ProviderResult.failure(this.#oauthBindingError('OAUTH_PROFILE_MISMATCH', 'OAuth provider profile changed before refresh'));
      }
      const granted = new Set(result.data.scopes ?? []);
      if (result.data.scopes?.length > 0 && binding.grantedScopes.some((scope) => !granted.has(scope))) {
        return ProviderResult.failure(this.#oauthBindingError('OAUTH_SCOPE_MISMATCH', 'Refresh evidence weakened the stored scope binding'));
      }
    }

    const persistedCredential = await this.#saveLifecycleIfCurrent(refreshedCredential, { expectedVersion: credential.version });
    await this.#recordSecretVersion(persistedCredential, { reason: 'refresh' });
    await this.#recordLifecycleAudit('credential.rotated', persistedCredential, context, {
      previousVersion: credential.version,
      version: persistedCredential.version
    });

    return ProviderResult.success({
      credential: persistedCredential,
      provider: result.data
    });
  }

  async refreshIfDue(credentialOrId, options = {}) {
    const credential = await this.#resolveCredential(credentialOrId);
    const refreshBeforeDays = Number(
      options.refreshBeforeDays ?? this.config?.get?.('REFRESH_BEFORE_DAYS', 14) ?? 14
    );

    if (!this.#shouldRefreshCredential(credential, refreshBeforeDays)) {
      return credential;
    }

    const result = await this.refresh(credential);
    if (!result.success) {
      const error = new Error(
        result.error?.message ?? `Provider refresh failed for ${credential.credentialId}`
      );
      error.code = result.error?.code ?? 'PROVIDER_REFRESH_FAILED';
      throw error;
    }

    return result.data?.credential ?? result.data;
  }

  async revoke(credentialOrId, context = {}) {
    const credential = await this.#resolveCredential(credentialOrId);

    if (credential.lifecycleState === LifecycleState.REVOKED) {
      const contained = credential.decommissioning
        ? credential
        : await this.#persistDecommissioning(credential, 'revoke', context);
      let retried = contained;
      if (retried.decommissioning?.providerCleanup?.status !== 'complete'
        && retried.decommissioning?.providerCleanup?.status !== 'not_required'
        && this.providerManager?.revokeCredential) {
        const providerResult = await this.#executeProviderAction('revokeCredential', retried);
        retried = providerResult.success || providerResult.error?.classification === 'provider_contract_incompatible'
          ? await this.#recordDecommissioningStep(retried, 'providerCleanup', providerResult.success ? 'complete' : 'not_required', null, context)
          : await this.#recordDecommissioningFailure(retried, 'providerCleanup', providerResult.error, context);
      }
      try {
        await this.#invalidateSecretHistory(retried, 'credential-revoked');
      } catch (error) {
        const failed = await this.#recordDecommissioningFailure(retried, 'secretHistoryCleanup', error, context);
        return ProviderResult.success({ credential: failed, provider: null, idempotent: true });
      }
      await this.#recordLifecycleAudit('credential.revoke.noop', credential, context, {
        reason: 'already-revoked'
      });
      return ProviderResult.success({ credential: retried, provider: null, idempotent: true });
    }
    if (credential.lifecycleState === LifecycleState.DELETED) {
      return ProviderResult.failure(this.#lifecycleConflict(credential, 'Credential lifecycle is terminal'));
    }

    // Commit local containment before any fallible provider or cleanup work.
    let persistedCredential = await this.#persistDecommissioning(
      credential,
      'revoke',
      context,
      LifecycleState.REVOKED
    );

    const result = this.providerManager?.revokeCredential
      ? await this.#executeProviderAction('revokeCredential', persistedCredential)
      : ProviderResult.success(null);

    if (result.success || result.error?.classification === 'provider_contract_incompatible') {
      persistedCredential = await this.#recordDecommissioningStep(
        persistedCredential,
        'providerCleanup',
        result.success ? 'complete' : 'not_required',
        null,
        context
      );
    } else {
      persistedCredential = await this.#recordDecommissioningFailure(
        persistedCredential,
        'providerCleanup',
        result.error,
        context
      );
    }

    try {
      await this.#invalidateSecretHistory(persistedCredential, 'credential-revoked');
      persistedCredential = await this.#recordDecommissioningStep(
        persistedCredential,
        'secretHistoryCleanup',
        'complete',
        null,
        context
      );
    } catch (error) {
      persistedCredential = await this.#recordDecommissioningFailure(
        persistedCredential,
        'secretHistoryCleanup',
        error,
        context
      );
    }

    await this.#recordLifecycleAudit('credential.revoked', persistedCredential, context, {
      previousState: credential.lifecycleState
    });

    return ProviderResult.success({
      credential: persistedCredential,
      provider: result.data,
      cleanupRequired: persistedCredential.decommissioning?.providerCleanup?.status !== 'complete'
        || persistedCredential.decommissioning?.secretHistoryCleanup?.status !== 'complete'
    });
  }

  async healthCheck(credentialOrId) {
    const credential = await this.#resolveCredential(credentialOrId);
    let connectionCredential;

    try {
      connectionCredential = await this.#prepareConnectionCredential(credential, EGRESS_PURPOSES.PROVIDER_HEALTH_CHECK);
    } catch (error) {
      return ProviderResult.failure(error);
    }
    return this.#executeProviderAction('healthCheckCredential', connectionCredential, {
      purpose: EGRESS_PURPOSES.PROVIDER_HEALTH_CHECK
    });
  }

  #draftCredentialFrom(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw this.#connectionTestError(
        'CREDENTIAL_CONNECTION_INVALID',
        'Credential connection test input is invalid',
        400,
        'credential.connectionTest.invalid'
      );
    }

    const secrets = Array.isArray(input.secrets)
      ? input.secrets.map(({ name, value, metadata }) => ({ name, value, metadata }))
      : [];

    return this.#bindProviderProfile(Credential.from({
      providerKey: input.providerKey,
      credentialMethodKey: input.credentialMethodKey ?? null,
      externalReference: input.externalReference ?? null,
      lifecycleState: LifecycleState.REGISTERED,
      metadata: input.metadata ?? {},
      secrets
    }));
  }

  #connectionTestProvider(providerKey) {
    if (!this.providerManager?.getProvider || !this.providerManager?.validateCredential) {
      throw this.#connectionTestError(
        'CREDENTIAL_CONNECTION_UNAVAILABLE',
        'Credential connection testing is unavailable',
        503,
        'credential.connectionTest.unavailable'
      );
    }

    let provider;
    try {
      provider = this.providerManager.getProvider(providerKey);
    } catch {
      throw this.#connectionTestError(
        'CREDENTIAL_CONNECTION_UNSUPPORTED',
        'This provider does not support connection testing',
        422,
        'credential.connectionTest.unsupported'
      );
    }

    const capabilities = provider?.capabilities?.toArray?.() ?? provider?.capabilities ?? [];
    if (!capabilities.includes('validation')) {
      throw this.#connectionTestError(
        'CREDENTIAL_CONNECTION_UNSUPPORTED',
        'This provider does not support connection testing',
        422,
        'credential.connectionTest.unsupported'
      );
    }

    return provider;
  }

  async #prepareConnectionCredential(credential, purpose = EGRESS_PURPOSES.PROVIDER_VALIDATION) {
    if (!['ftp', 'sftp'].includes(credential.providerKey)) return credential;

    const metadata = credential.metadata.toJSON();
    const hostSecret = credential.secrets.find((secret) => secret.name === 'host');
    const host = hostSecret?.value ?? metadata.custom?.host;
    const target = this.connectionTargetPolicy
      ? await this.connectionTargetPolicy.resolveAllowedTarget(host)
      : await this.egressPolicy.admit(host, {
        pathId: purpose === EGRESS_PURPOSES.CREDENTIAL_CONNECTION_TEST ? `${credential.providerKey.toUpperCase()}-DRAFT` : `${credential.providerKey.toUpperCase()}-STORED`,
        purpose,
        protocol: credential.providerKey,
        port: Number(metadata.custom?.port ?? (credential.providerKey === 'ftp' ? 21 : 22)),
        providerKey: credential.providerKey
      });
    const admittedAddress = target.connectAddress ?? target.address;
    const verificationHost = target.verificationHost ?? target.host;
    const secrets = credential.secrets.map((secret) => secret.name === 'host'
      ? { name: secret.name, value: admittedAddress, metadata: secret.metadata }
      : secret.toJSON());

    return Credential.from({
      ...credential.toJSON(),
      secrets,
      metadata: {
        ...metadata,
        custom: {
          ...(metadata.custom ?? {}),
          ...(hostSecret ? {} : { host: admittedAddress }),
          connectionVerificationHost: verificationHost
        }
      }
    });
  }

  #connectionTestProviderError(error = {}, credential = null, provider = null) {
    const code = String(error?.code ?? '').toUpperCase();
    const statusCode = Number(error?.statusCode ?? error?.status ?? 0);
    const name = String(error?.name ?? '');
    const message = String(error?.message ?? '').toLowerCase();
    const field = credential?.providerKey === 'openai' ? 'apiKey' : credential?.providerKey === 'ftp' || credential?.providerKey === 'sftp' ? 'host' : null;
    const targetField = credential?.providerKey === 'ftp' || credential?.providerKey === 'sftp' ? 'host' : field;

    if (code === 'EGRESS_TARGET_BLOCKED') {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_TARGET_BLOCKED',
        'Credential connection target is not allowed',
        400,
        'credential.connectionTest.targetBlocked',
        targetField ? { field: targetField } : {},
        'policy_rejected'
      );
    }

    if (code === 'EGRESS_DNS_FAILED') {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_DNS_FAILED',
        'Credential connection target could not be resolved',
        422,
        'credential.connectionTest.dnsFailed',
        targetField ? { field: targetField } : {},
        'transport_failure'
      );
    }

    if (code.includes('TIMEOUT') || code.includes('TIMEDOUT') || code === 'ABORT_ERR' || name === 'AbortError') {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_TIMEOUT',
        'Credential connection test timed out',
        504,
        'credential.connectionTest.timeout',
        targetField ? { field: targetField } : {},
        'transport_failure'
      );
    }

    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || message.includes('dns')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_DNS_FAILED',
        'Credential connection target could not be resolved',
        422,
        'credential.connectionTest.dnsFailed',
        targetField ? { field: targetField } : {},
        'transport_failure'
      );
    }

    if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH' || message.includes('host unreachable')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_HOST_UNREACHABLE',
        'Credential connection host is unreachable',
        422,
        'credential.connectionTest.hostUnreachable',
        targetField ? { field: targetField } : {},
        'transport_failure'
      );
    }

    if (code === 'ECONNREFUSED' || message.includes('connection refused')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_REFUSED',
        'Credential connection was refused',
        422,
        'credential.connectionTest.refused',
        targetField ? { field: targetField } : {},
        'transport_failure'
      );
    }

    if (code.includes('HOST_KEY') || message.includes('host key')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_HOST_KEY_FAILED',
        'Credential connection host key could not be verified',
        422,
        'credential.connectionTest.hostKeyFailed',
        { field: 'host' },
        'transport_failure'
      );
    }

    if (code.includes('PRIVATE_KEY') || message.includes('private key')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_INVALID_PRIVATE_KEY',
        'Credential private key is invalid',
        422,
        'credential.connectionTest.invalidPrivateKey',
        { field: 'privateKey' },
        'transport_failure'
      );
    }

    if (code.includes('TLS') || code.includes('CERT') || message.includes('certificate')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_TLS_FAILED',
        'Credential connection TLS verification failed',
        422,
        'credential.connectionTest.tlsFailed',
        field ? { field } : {},
        'transport_failure'
      );
    }

    if (statusCode === 429 || code.includes('RATE')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_RATE_LIMITED',
        'Credential connection test is rate limited',
        429,
        'credential.connectionTest.rateLimited',
        field ? { field } : {},
        'validation_operation_failed'
      );
    }

    if (statusCode === 401 || code.includes('AUTH')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_AUTHENTICATION_FAILED',
        'Credential authentication was rejected',
        422,
        'credential.connectionTest.authenticationFailed',
        field ? { field } : {},
        this.#isAuthorizationRequired(provider, statusCode, code, message)
          ? 'authorization_required'
          : 'credential_invalid'
      );
    }

    if (statusCode === 403 || code.includes('PERMISSION') || code.includes('FORBIDDEN')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_PERMISSION_DENIED',
        'Credential permission was denied',
        422,
        'credential.connectionTest.permissionDenied',
        field ? { field } : {},
        code.includes('SCOPE') || message.includes('scope')
          ? 'scope_insufficient'
          : this.#isPolicyRejection(code, message)
            ? 'policy_rejected'
            : 'credential_invalid'
      );
    }

    if (statusCode >= 500 || code.includes('UNAVAILABLE')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_PROVIDER_UNAVAILABLE',
        'Credential provider is unavailable',
        503,
        'credential.connectionTest.providerUnavailable',
        field ? { field } : {},
        'validation_operation_failed'
      );
    }

    return this.#connectionTestError(
      'CREDENTIAL_CONNECTION_FAILED',
      'Credential connection test failed',
      422,
      'credential.connectionTest.failed',
      field ? { field } : {},
      this.#connectionFailureClassification(error)
    );
  }

  #connectionTestError(code, message, statusCode, messageKey, details = {}, classification = 'validation_operation_failed') {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    error.messageKey = messageKey;
    error.details = details;
    error.classification = classification;
    return error;
  }

  #isAuthorizationRequired(provider, statusCode, code, message) {
    const capabilities = provider?.capabilities?.toArray?.() ?? provider?.capabilities ?? [];
    return (statusCode === 401 && (provider?.authType === 'oauth2' || capabilities.includes('oauth')))
      || code.includes('AUTHORIZATION_REQUIRED')
      || message.includes('authorization required');
  }

  #isPolicyRejection(code, message) {
    return code.includes('POLICY')
      || code.includes('BLOCKED')
      || message.includes('policy rejected')
      || message.includes('not allowed');
  }

  #connectionFailureClassification(error = {}) {
    const code = String(error?.code ?? '').toUpperCase();
    if (code.includes('PLACEHOLDER')) return 'provider_configuration_invalid';
    if (code.includes('PROFILE') || code.includes('CONTRACT') || code.includes('ENDPOINT') || code.includes('API_VERSION')) {
      return 'provider_contract_incompatible';
    }
    if (code.includes('TARGET_BLOCKED') || code.includes('POLICY')) return 'policy_rejected';
    if (code.includes('TIMEOUT') || code.includes('DNS') || code.includes('UNREACHABLE') || code.includes('REFUSED')
      || code.includes('TLS') || code.includes('HOST_KEY') || code.includes('PRIVATE_KEY')) return 'transport_failure';
    if (code.includes('SCOPE') || code.includes('PERMISSION') || code.includes('FORBIDDEN')) return 'scope_insufficient';
    if (code.includes('AUTHORIZATION_REQUIRED')) return 'authorization_required';
    if (code.includes('AUTHENTICATION') || code.includes('INVALID')) return 'credential_invalid';
    if (code.includes('CONFIGURATION')) return 'provider_configuration_invalid';
    return 'validation_operation_failed';
  }

  async executeBulkAction({ credentialIds = [], action } = {}) {
    if (!Array.isArray(credentialIds) || credentialIds.length === 0 || credentialIds.length > 100) {
      const error = new Error('CredentialManager.executeBulkAction() requires at least one credentialId');
      error.code = 'INVALID_BULK_CREDENTIAL_IDS';
      throw error;
    }
    const normalizedIds = credentialIds.map((id) => {
      try {
        return validateNamedIdentifier('credentialId', id);
      } catch (cause) {
        const error = new Error('CredentialManager.executeBulkAction() received an invalid credentialId', { cause });
        error.code = 'INVALID_BULK_CREDENTIAL_IDS';
        throw error;
      }
    });
    if (new Set(normalizedIds).size !== normalizedIds.length) {
      const error = new Error('CredentialManager.executeBulkAction() rejects duplicate credentialIds');
      error.code = 'DUPLICATE_BULK_CREDENTIAL_IDS';
      throw error;
    }

    const normalizedAction = String(action ?? '').trim();
    const actionMap = {
      validate: (credentialId) => this.executeLifecycleAction(credentialId, 'validate'),
      refresh: (credentialId) => this.executeLifecycleAction(credentialId, 'refresh'),
      revoke: (credentialId) => this.executeLifecycleAction(credentialId, 'revoke'),
      'health-check': (credentialId) => this.executeLifecycleAction(credentialId, 'health-check'),
      delete: (credentialId) => this.deleteCredential(credentialId)
    };

    const execute = actionMap[normalizedAction];

    if (!execute) {
      const error = new Error(`Unsupported bulk credential action '${action}'`);
      error.code = 'UNSUPPORTED_BULK_ACTION';
      throw error;
    }

    const results = [];

    for (const credentialId of normalizedIds) {
      try {
        const result = await execute(credentialId);
        results.push({
          credentialId,
          success: true,
          data: result
        });
      } catch (error) {
        const safe = safeError(error, { fallbackMessage: 'Bulk credential action failed' });
        results.push({
          credentialId,
          success: false,
          error: {
            code: safe.code ?? 'BULK_ACTION_FAILED',
            message: safe.message
          }
        });
      }
    }

    const succeeded = results.filter((result) => result.success).length;
    const failed = results.length - succeeded;

    return {
      action: normalizedAction,
      requested: credentialIds.length,
      succeeded,
      failed,
      results
    };
  }

  async executeLifecycleAction(credentialId, lifecycleAction) {
    const actionMap = {
      validate: () => this.validate(credentialId),
      refresh: () => this.refresh(credentialId),
      revoke: () => this.revoke(credentialId),
      'health-check': () => this.healthCheck(credentialId),
    };

    const execute = actionMap[lifecycleAction];

    if (!execute) {
      const error = new Error(`Unsupported lifecycle action '${lifecycleAction}'`);
      error.code = 'UNSUPPORTED_LIFECYCLE_ACTION';
      throw error;
    }

    const result = await execute();

    if (result instanceof ProviderResult) {
      if (!result.success) {
        const error = new Error(result.error?.message ?? 'Lifecycle action failed');
        error.code = result.error?.code ?? 'LIFECYCLE_ACTION_FAILED';
        throw error;
      }

      return result.data?.credential ?? result.data;
    }

    return result;
  }

  async #executeProviderAction(actionName, credential, operationContext = {}) {
    if (!this.providerManager?.[actionName]) {
      return ProviderResult.failure(
        new Error(`ProviderManager does not support credential action '${actionName}'`)
      );
    }

    return this.providerManager[actionName](this.#providerOperationCredential(credential), operationContext);
  }

  #providerOperationCredential(credential) {
    const secrets = new Map(credential.secrets.map((secret) => [secret.name, secret.value]));
    if (!secrets.has('accessToken') && !secrets.has('refreshToken')) return credential;
    const metadata = credential.metadata.toJSON();

    return {
      ...credential,
      provider: credential.providerKey,
      providerId: metadata.custom?.legacyProviderId
        ?? (credential.externalReference ? `${credential.providerKey}:${credential.externalReference}` : credential.credentialId),
      accountId: credential.externalReference,
      accountName: metadata.custom?.accountName ?? null,
      accessToken: secrets.get('accessToken') ?? null,
      refreshToken: secrets.get('refreshToken') ?? null,
      expiresAt: metadata.expiresAt ?? null,
      scopes: metadata.scopes ?? [],
      metadata,
      providerConfiguration: metadata.providerConfiguration ?? null
    };
  }

  async #findOAuthCredential(oauthResult) {
    if (typeof this.credentialStore.loadByExternalReference === 'function') {
      try {
        return await this.credentialStore.loadByExternalReference(oauthResult.provider, oauthResult.accountId);
      } catch (error) {
        if (error?.code !== 'NOT_FOUND') throw error;
        return null;
      }
    }

    if (typeof this.credentialStore.list !== 'function') return null;
    const matches = (await this.credentialStore.list()).filter((credential) => (
      credential.providerKey === oauthResult.provider && credential.externalReference === oauthResult.accountId
    ));
    if (matches.length > 1) {
      const error = new Error(`External Credential reference '${oauthResult.provider}:${oauthResult.accountId}' is ambiguous`);
      error.code = 'CREDENTIAL_IDENTITY_AMBIGUOUS';
      throw error;
    }
    return matches[0] ?? null;
  }

  async #resolveCredential(credentialOrId) {
    if (credentialOrId instanceof Credential) return credentialOrId;

    if (typeof credentialOrId === 'object' && credentialOrId !== null) {
      return Credential.from(credentialOrId);
    }

    this.#assertStore('resolve credential');
    return this.credentialStore.load(credentialOrId);
  }


  async #recordSecretVersion(credential, options = {}) {
    if (!this.secretVersioningService?.recordCredentialVersion) return;
    await this.secretVersioningService.recordCredentialVersion(credential, options);
  }

  async #invalidateSecretHistory(credential, reason) {
    if (!this.secretVersioningService?.invalidateHistoryForCredential) return;
    await this.secretVersioningService.invalidateHistoryForCredential(credential.credentialId, { reason });
  }

  #initialDecommissioning(intent, credential) {
    const now = new Date().toISOString();
    return {
      intent,
      requestedAt: credential.decommissioning?.requestedAt ?? now,
      providerCleanup: credential.decommissioning?.providerCleanup ?? {
        status: this.providerManager?.revokeCredential ? 'pending' : 'not_required',
        lastAttemptAt: null,
        failureCode: null
      },
      grantCleanup: credential.decommissioning?.grantCleanup ?? {
        status: this.consumerGrantService?.cleanupForCredential ? 'pending' : 'not_required',
        lastAttemptAt: null,
        failureCode: null
      },
      secretHistoryCleanup: credential.decommissioning?.secretHistoryCleanup ?? {
        status: this.secretVersioningService?.invalidateHistoryForCredential ? 'pending' : 'not_required',
        lastAttemptAt: null,
        failureCode: null
      }
    };
  }

  async #persistDecommissioning(credential, intent, context = {}, lifecycleState = credential.lifecycleState) {
    const next = Credential.from({
      ...credential.toJSON(),
      lifecycleState,
      decommissioning: this.#initialDecommissioning(intent, credential),
      updatedAt: new Date(),
      version: credential.version + 1
    });
    return this.#saveLifecycleIfCurrent(next, { expectedVersion: credential.version });
  }

  async #recordDecommissioningStep(credential, stepName, status, failureCode = null, context = {}) {
    if (!credential.decommissioning) return credential;
    const decommissioning = {
      ...credential.decommissioning,
      [stepName]: {
        status,
        lastAttemptAt: new Date().toISOString(),
        failureCode
      }
    };
    const next = Credential.from({
      ...credential.toJSON(),
      decommissioning,
      updatedAt: new Date(),
      version: credential.version + 1
    });
    return this.#saveLifecycleIfCurrent(next, { expectedVersion: credential.version });
  }

  async #recordDecommissioningFailure(credential, stepName, error, context = {}) {
    const failureCode = String(error?.code ?? 'DECOMMISSIONING_STEP_FAILED')
      .toUpperCase()
      .replace(/[^A-Z0-9_]/g, '_')
      .slice(0, 64);
    try {
      return await this.#recordDecommissioningStep(credential, stepName, 'failed_retryable', failureCode, context);
    } catch {
      // The contained lifecycle state remains authoritative even if recording
      // the derived cleanup detail cannot be persisted in the same attempt.
      return credential;
    }
  }

  #assertCredentialHistory(operation) {
    if (!this.credentialHistoryService) {
      throw new Error(`CredentialManager.${operation}() requires credentialHistoryService`);
    }
  }

  #assertSecretVersioning(operation) {
    if (!this.secretVersioningService) {
      throw new Error(`CredentialManager.${operation}() requires secretVersioningService`);
    }
  }

  async #createIfAvailable(credential) {
    if (this.credentialStore?.create) {
      await this.credentialStore.create(credential);
    } else if (this.credentialStore?.saveConditional) {
      await this.credentialStore.saveConditional(credential, { requireExisting: false });
    } else if (this.credentialStore?.save) {
      await this.credentialStore.save(credential);
    }
  }

  async #assertProviderConfigurationReference(credential) {
    if (this.providerManager?.getProvider) {
      try {
        const provider = this.providerManager.getProvider(credential.providerKey);
        if (!provider) throw new Error('Provider is unavailable');
        const currentProfile = provider.providerProfile?.identity?.() ?? provider.providerProfile ?? null;
        if (credential.providerProfile?.digest && currentProfile?.digest
          && credential.providerProfile.digest !== currentProfile.digest) {
          const error = new Error(`Credential provider '${credential.providerKey}' profile is stale`);
          error.code = 'CREDENTIAL_PROFILE_MISMATCH';
          error.statusCode = 409;
          throw error;
        }
      } catch (error) {
        if (error?.code === 'CREDENTIAL_PROFILE_MISMATCH') throw error;
        const unavailable = new Error(`Credential provider '${credential.providerKey}' is unavailable`);
        unavailable.code = 'CREDENTIAL_PROVIDER_UNKNOWN';
        unavailable.statusCode = 400;
        throw unavailable;
      }
    }
    const configurationId = credential?.providerConfigurationId;
    if (!configurationId || !this.providerConfigurationService?.load) return;
    await this.providerConfigurationService.load(
      configurationId,
      credential.providerKey,
      credential.providerProfile
    );
  }

  async #saveLifecycleIfCurrent(credential, { expectedVersion, allowBindingChange = false } = {}) {
    if (!this.credentialStore?.save) return credential;
    if (typeof this.credentialStore.saveConditional === 'function') {
      return this.credentialStore.saveConditional(credential, {
        expectedVersion,
        requireExisting: true,
        allowBindingChange
      });
    }
    await this.credentialStore.save(credential, { allowBindingChange });
    return credential;
  }

  #isTerminalLifecycle(credential) {
    return credential?.lifecycleState === LifecycleState.REVOKED
      || credential?.lifecycleState === LifecycleState.DELETED;
  }

  #lifecycleConflict(credential, message, details = {}) {
    const error = new Error(message);
    error.code = 'CREDENTIAL_LIFECYCLE_CONFLICT';
    error.details = {
      credentialId: credential?.credentialId ?? null,
      lifecycleState: credential?.lifecycleState ?? null,
      version: credential?.version ?? null,
      ...details
    };
    return error;
  }

  async #recordLifecycleAudit(action, credential, context = {}, details = {}) {
    if (!this.auditLogService?.record) return;

    await this.auditLogService.record({
      userId: context.userId ?? 'system',
      roleKey: context.roleKey,
      action,
      targetType: 'credential',
      targetId: credential.credentialId,
      result: 'success',
      details: {
        providerKey: credential.providerKey,
        lifecycleState: credential.lifecycleState,
        ...details
      }
    });
  }



  #shouldRefresh(token, refreshBeforeDays) {
    if (!token.expiresAt) {
      return false;
    }

    const expiresAt = new Date(token.expiresAt).getTime();

    if (Number.isNaN(expiresAt)) {
      return false;
    }

    const refreshThreshold =
      Date.now() + refreshBeforeDays * 24 * 60 * 60 * 1000;

    return expiresAt <= refreshThreshold;
  }

  #shouldRefreshCredential(credential, refreshBeforeDays) {
    if (credential.lifecycleState !== LifecycleState.ACTIVE) return false;
    const expiresAt = credential.metadata?.expiresAt;
    const accessToken = credential.secrets.find((secret) => secret.name === 'accessToken')?.value;
    const refreshToken = credential.secrets.find((secret) => secret.name === 'refreshToken')?.value;
    if (!accessToken || (!refreshToken && credential.providerKey !== 'threads')) return false;
    return this.#shouldRefresh({ expiresAt }, refreshBeforeDays);
  }

  async #persistOAuthRefresh(credential, oauthResult) {
    const refreshedCredential = this.#credentialFromOAuthResult(credential, oauthResult);
    return this.#saveLifecycleIfCurrent(refreshedCredential, { expectedVersion: credential.version });
  }

  #credentialFromOAuthResult(credential, oauthResult) {
    const current = credential.toJSON();
    const currentMetadata = credential.metadata.toJSON();
    const currentSecrets = new Map(credential.secrets.map((secret) => [secret.name, secret.toJSON()]));
    currentSecrets.set('accessToken', { name: 'accessToken', value: oauthResult.accessToken });
    if (oauthResult.refreshToken) {
      currentSecrets.set('refreshToken', { name: 'refreshToken', value: oauthResult.refreshToken });
    }

    return Credential.from({
      ...current,
      lifecycleState: LifecycleState.ACTIVE,
      externalReference: credential.oauthCredentialBinding
        ? credential.externalReference
        : (oauthResult.accountId ?? credential.externalReference),
      secrets: [...currentSecrets.values()],
      metadata: {
        ...currentMetadata,
        ...(Object.hasOwn(oauthResult, 'expiresAt') ? { expiresAt: oauthResult.expiresAt } : {}),
        ...(oauthResult.scopes?.length ? { scopes: oauthResult.scopes } : {}),
        custom: {
          ...currentMetadata.custom,
          ...oauthResult.metadata
        }
      },
      updatedAt: new Date(),
      version: credential.version + 1
    });
  }

  #assertLegacyTokenWorkflow(operation) {
    if (!this.credentialStore || !this.tokenLifecycleService || !this.providerManager) {
      throw new Error(
        `CredentialManager.${operation}() requires credentialStore, tokenLifecycleService and providerManager during MS7 migration`
      );
    }
  }

  #assertStore(operation) {
    if (!this.credentialStore) {
      throw new Error(`CredentialManager.${operation}() requires a credentialStore`);
    }
  }
}
