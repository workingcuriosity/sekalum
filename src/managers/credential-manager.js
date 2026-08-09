import { ProviderResult } from '../models/provider-result.js';
import { Credential } from '../models/credential.js';
import { LifecycleState } from '../models/lifecycle-state.js';
import { OAuthResult } from '../models/oauth-result.js';
import { ConnectionTargetPolicy } from '../services/connection-target-policy.js';

export class CredentialManager {
  constructor({
    credentialStore = null,
    providerManager = null,
    tokenLifecycleService = null,
    config = null,
    logger = null,
    secretVersioningService = null,
    credentialHistoryService = null,
    connectionTargetPolicy = null
  } = {}) {
    this.credentialStore = credentialStore;
    this.providerManager = providerManager;
    this.tokenLifecycleService = tokenLifecycleService;
    this.config = config;
    this.logger = logger;
    this.secretVersioningService = secretVersioningService;
    this.credentialHistoryService = credentialHistoryService;
    this.connectionTargetPolicy = connectionTargetPolicy ?? new ConnectionTargetPolicy({
      allowPrivateNetworks: String(config?.get?.('CONNECTION_TEST_ALLOW_PRIVATE_NETWORKS', 'false')).toLowerCase() === 'true'
    });
  }

  async register(credentialInput) {
    const credential = Credential.from(credentialInput);
    this.#validateCreationContract(credential);
    try {
      await this.#saveIfAvailable(credential);
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
      if (error.code?.startsWith('CREDENTIAL_')) throw error;
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

    let existing = null;
    try {
      existing = await this.credentialStore.load(oauthResult.providerId);
    } catch (error) {
      if (error?.code !== 'NOT_FOUND') throw error;
    }

    const credential = Credential.from({
      ...(existing?.toJSON?.() ?? {}),
      credentialId: existing?.credentialId ?? oauthResult.providerId,
      ...(existing ? { credentialKey: existing.credentialKey } : {}),
      providerKey: oauthResult.provider,
      credentialMethodKey: existing?.credentialMethodKey ?? 'oauth2',
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
          ...oauthResult.metadata
        }
      },
      createdAt: existing?.createdAt ?? new Date(),
      updatedAt: new Date(),
      version: (existing?.version ?? 0) + 1
    });

    await this.credentialStore.save(credential);
    return credential;
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

  async listCredentials(options = {}) {
    this.#assertStore('listCredentials');

    const credentials = await this.credentialStore.list();

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
    const secretNames = (value?.secrets ?? []).map((secret) => secret.name);

    if (secretNames.includes('apiKey')) return 'api-key';
    if (secretNames.includes('host') || secretNames.includes('password') || secretNames.includes('privateKey')) return 'connection';
    if (secretNames.includes('accessToken') || secretNames.includes('refreshToken')) return 'oauth';

    return value?.metadata?.custom?.credentialType ?? 'unknown';
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

    if (!credentialId) {
      throw new Error('CredentialManager.updateCredential() requires a credentialId');
    }

    const existingCredential = await this.getCredential(credentialId);

    if (!existingCredential) {
      throw new Error(`CredentialManager.updateCredential() could not find credential '${credentialId}'`);
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

    this.#validateCreationContract(nextCredential);
    await this.credentialStore.save(nextCredential);
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
    if (!this.credentialStore?.save) {
      this.logger?.error?.('Credential secret versioning failed and update rollback is unavailable', {
        credentialId: nextCredential.credentialId,
        versioningCode: versionError?.code ?? 'SECRET_VERSIONING_FAILED',
        rollbackCode: 'CREDENTIAL_ROLLBACK_UNAVAILABLE'
      });
      return false;
    }

    try {
      await this.credentialStore.save(existingCredential);
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
    const allowedMetadata = new Set(['displayName', 'description', 'tags', 'scopes', 'custom']);
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
      await this.credentialStore.save(next);
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
    if (typeof credentialMethodKey !== 'string' || credentialMethodKey.trim() === '') {
      throw this.#creationError('CREDENTIAL_METHOD_REQUIRED', 'credentialMethodKey is required for migration', 400, 'credential.migration.methodRequired');
    }
    const existingCredential = await this.getCredential(credentialId);
    if (!existingCredential) {
      throw this.#creationError('CREDENTIAL_NOT_FOUND', 'Credential not found', 404, 'credential.migration.notFound');
    }
    const migrated = Credential.from({
      ...existingCredential.toJSON(),
      credentialMethodKey: credentialMethodKey.trim(),
      updatedAt: new Date(),
      version: existingCredential.version + 1
    });
    this.#validateCreationContract(migrated);
    await this.credentialStore.save(migrated);
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

  async deleteCredential(credentialId) {
    this.#assertStore('deleteCredential');

    if (!credentialId) {
      throw new Error('CredentialManager.deleteCredential() requires a credentialId');
    }

    const credential = await this.getCredential(credentialId);

    if (!credential) {
      throw new Error(`CredentialManager.deleteCredential() could not find credential '${credentialId}'`);
    }

    return this.delete(credential);
  }

  async delete(credentialOrId) {
    const credential = await this.#resolveCredential(credentialOrId);

    if (this.providerManager?.revokeCredential && credential.lifecycleState !== LifecycleState.REVOKED) {
      await this.revoke(credential);
    }

    const deletedCredential = credential.withLifecycleState(LifecycleState.DELETED);
    await this.#saveIfAvailable(deletedCredential);

    if (this.credentialStore?.delete) {
      await this.credentialStore.delete(deletedCredential.credentialId);
    }

    return deletedCredential;
  }

  async validate(credentialOrId) {
    const credential = await this.#resolveCredential(credentialOrId);
    let connectionCredential;

    try {
      connectionCredential = await this.#prepareConnectionCredential(credential);
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
    await this.#saveIfAvailable(validatedCredential);

    return ProviderResult.success({
      credential: validatedCredential,
      provider: result.data
    });
  }

  async testConnection(draftInput) {
    let credential;

    try {
      credential = this.#draftCredentialFrom(draftInput);
      const provider = this.#connectionTestProvider(credential.providerKey);
      this.#validateCreationContract(credential);
      credential = await this.#prepareConnectionCredential(credential);

      const result = await this.providerManager.validateCredential(credential);
      if (!result?.success) throw this.#connectionTestProviderError(result?.error, credential);

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
        error?.details?.field ? { field: error.details.field } : {}
      );
    }
  }

  async refresh(credentialOrId) {
    const credential = await this.#resolveCredential(credentialOrId);
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

    await this.#saveIfAvailable(refreshedCredential);
    await this.#recordSecretVersion(refreshedCredential, { reason: 'refresh' });

    return ProviderResult.success({
      credential: refreshedCredential,
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

  async revoke(credentialOrId) {
    const credential = await this.#resolveCredential(credentialOrId);
    const result = await this.#executeProviderAction('revokeCredential', credential);

    if (!result.success) return result;

    const revokedCredential = credential.withLifecycleState(LifecycleState.REVOKED);
    await this.#saveIfAvailable(revokedCredential);

    return ProviderResult.success({
      credential: revokedCredential,
      provider: result.data
    });
  }

  async healthCheck(credentialOrId) {
    const credential = await this.#resolveCredential(credentialOrId);
    let connectionCredential;

    try {
      connectionCredential = await this.#prepareConnectionCredential(credential);
    } catch (error) {
      return ProviderResult.failure(error);
    }
    return this.#executeProviderAction('healthCheckCredential', connectionCredential);
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

    return Credential.from({
      providerKey: input.providerKey,
      credentialMethodKey: input.credentialMethodKey ?? null,
      externalReference: input.externalReference ?? null,
      lifecycleState: LifecycleState.REGISTERED,
      metadata: input.metadata ?? {},
      secrets
    });
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

  async #prepareConnectionCredential(credential) {
    if (!['ftp', 'sftp'].includes(credential.providerKey)) return credential;

    const metadata = credential.metadata.toJSON();
    const hostSecret = credential.secrets.find((secret) => secret.name === 'host');
    const host = hostSecret?.value ?? metadata.custom?.host;
    const target = await this.connectionTargetPolicy.resolveAllowedTarget(host);
    const secrets = credential.secrets.map((secret) => secret.name === 'host'
      ? { name: secret.name, value: target.address, metadata: secret.metadata }
      : secret.toJSON());

    return Credential.from({
      ...credential.toJSON(),
      secrets,
      metadata: {
        ...metadata,
        custom: {
          ...(metadata.custom ?? {}),
          ...(hostSecret ? {} : { host: target.address }),
          connectionVerificationHost: target.host
        }
      }
    });
  }

  #connectionTestProviderError(error = {}, credential = null) {
    const code = String(error?.code ?? '').toUpperCase();
    const statusCode = Number(error?.statusCode ?? error?.status ?? 0);
    const name = String(error?.name ?? '');
    const message = String(error?.message ?? '').toLowerCase();
    const field = credential?.providerKey === 'openai' ? 'apiKey' : credential?.providerKey === 'ftp' || credential?.providerKey === 'sftp' ? 'host' : null;
    const targetField = credential?.providerKey === 'ftp' || credential?.providerKey === 'sftp' ? 'host' : field;

    if (code.includes('TIMEOUT') || code.includes('TIMEDOUT') || code === 'ABORT_ERR' || name === 'AbortError') {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_TIMEOUT',
        'Credential connection test timed out',
        504,
        'credential.connectionTest.timeout',
        targetField ? { field: targetField } : {}
      );
    }

    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || message.includes('dns')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_DNS_FAILED',
        'Credential connection target could not be resolved',
        422,
        'credential.connectionTest.dnsFailed',
        targetField ? { field: targetField } : {}
      );
    }

    if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH' || message.includes('host unreachable')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_HOST_UNREACHABLE',
        'Credential connection host is unreachable',
        422,
        'credential.connectionTest.hostUnreachable',
        targetField ? { field: targetField } : {}
      );
    }

    if (code === 'ECONNREFUSED' || message.includes('connection refused')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_REFUSED',
        'Credential connection was refused',
        422,
        'credential.connectionTest.refused',
        targetField ? { field: targetField } : {}
      );
    }

    if (code.includes('HOST_KEY') || message.includes('host key')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_HOST_KEY_FAILED',
        'Credential connection host key could not be verified',
        422,
        'credential.connectionTest.hostKeyFailed',
        { field: 'host' }
      );
    }

    if (code.includes('PRIVATE_KEY') || message.includes('private key')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_INVALID_PRIVATE_KEY',
        'Credential private key is invalid',
        422,
        'credential.connectionTest.invalidPrivateKey',
        { field: 'privateKey' }
      );
    }

    if (code.includes('TLS') || code.includes('CERT') || message.includes('certificate')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_TLS_FAILED',
        'Credential connection TLS verification failed',
        422,
        'credential.connectionTest.tlsFailed',
        field ? { field } : {}
      );
    }

    if (statusCode === 429 || code.includes('RATE')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_RATE_LIMITED',
        'Credential connection test is rate limited',
        429,
        'credential.connectionTest.rateLimited',
        field ? { field } : {}
      );
    }

    if (statusCode === 401 || code.includes('AUTH')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_AUTHENTICATION_FAILED',
        'Credential authentication was rejected',
        422,
        'credential.connectionTest.authenticationFailed',
        field ? { field } : {}
      );
    }

    if (statusCode === 403 || code.includes('PERMISSION') || code.includes('FORBIDDEN')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_PERMISSION_DENIED',
        'Credential permission was denied',
        422,
        'credential.connectionTest.permissionDenied',
        field ? { field } : {}
      );
    }

    if (statusCode >= 500 || code.includes('UNAVAILABLE')) {
      return this.#connectionTestError(
        'CREDENTIAL_CONNECTION_PROVIDER_UNAVAILABLE',
        'Credential provider is unavailable',
        503,
        'credential.connectionTest.providerUnavailable',
        field ? { field } : {}
      );
    }

    return this.#connectionTestError(
      'CREDENTIAL_CONNECTION_FAILED',
      'Credential connection test failed',
      422,
      'credential.connectionTest.failed',
      field ? { field } : {}
    );
  }

  #connectionTestError(code, message, statusCode, messageKey, details = {}) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    error.messageKey = messageKey;
    error.details = details;
    return error;
  }

  async executeBulkAction({ credentialIds = [], action } = {}) {
    if (!Array.isArray(credentialIds) || credentialIds.length === 0) {
      const error = new Error('CredentialManager.executeBulkAction() requires at least one credentialId');
      error.code = 'INVALID_BULK_CREDENTIAL_IDS';
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

    for (const credentialId of credentialIds) {
      try {
        const result = await execute(credentialId);
        results.push({
          credentialId,
          success: true,
          data: result
        });
      } catch (error) {
        results.push({
          credentialId,
          success: false,
          error: {
            code: error.code ?? 'BULK_ACTION_FAILED',
            message: error.message ?? 'Bulk credential action failed'
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

  async #executeProviderAction(actionName, credential) {
    if (!this.providerManager?.[actionName]) {
      return ProviderResult.failure(
        new Error(`ProviderManager does not support credential action '${actionName}'`)
      );
    }

    return this.providerManager[actionName](this.#providerOperationCredential(credential));
  }

  #providerOperationCredential(credential) {
    const secrets = new Map(credential.secrets.map((secret) => [secret.name, secret.value]));
    if (!secrets.has('accessToken') && !secrets.has('refreshToken')) return credential;
    const metadata = credential.metadata.toJSON();

    return {
      ...credential,
      provider: credential.providerKey,
      providerId: credential.credentialId,
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

  async #saveIfAvailable(credential) {
    if (this.credentialStore?.save) {
      await this.credentialStore.save(credential);
    }
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
    await this.credentialStore.save(refreshedCredential);
    return refreshedCredential;
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
      externalReference: oauthResult.accountId ?? credential.externalReference,
      secrets: [...currentSecrets.values()],
      metadata: {
        ...currentMetadata,
        ...(oauthResult.expiresAt ? { expiresAt: oauthResult.expiresAt } : {}),
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
