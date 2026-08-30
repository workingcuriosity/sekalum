import { safeError, safeErrorMessage, sanitizeDiagnostic } from '../utils/safe-diagnostics.js';
import { authenticatedUserId } from '../utils/authenticated-user.js';
import { CredentialMetadata, CredentialMetadataPolicy } from '../models/credential-metadata.js';

export const MAX_BULK_CREDENTIAL_IDS = 100;

export class CredentialController {
  constructor({ credentialManager, providerManager = null, credentialTransferService = null }) {
    this.credentialManager = credentialManager;
    this.providerManager = providerManager;
    this.credentialTransferService = credentialTransferService;
  }

  async list(req, res) {
    try {
      this.#assertCredentialManager('listCredentialMetadata', 'listCredentials');

      const { limit, offset, page, pageSize } = this.#paginationFrom(req.query);
      const list = this.credentialManager.listCredentialMetadata ?? this.credentialManager.listCredentials;
      const credentials = await list.call(this.credentialManager, this.#listOptionsFrom(req.query));
      const pagedCredentials = credentials.slice(offset, offset + limit);

      res.status(200).json({
        success: true,
        data: pagedCredentials.map((credential) => this.#toListJSON(credential)),
        pagination: {
          limit,
          offset,
          page,
          pageSize,
          count: pagedCredentials.length,
          total: credentials.length
        },
        meta: {
          query: this.#queryMetadata(req.query),
          availableFilters: this.#filterMetadata()
        }
      });
    } catch (error) {
      this.#sendError(res, this.#normalizeListError(error));
    }
  }


  async create(req, res) {
    try {
      this.#assertCredentialManager('register');

      if (!req.body || Object.keys(req.body).length === 0) {
        throw this.#badRequest('request body is required');
      }

      const credential = await this.credentialManager.register(req.body);

      res.status(201).json({
        success: true,
        data: this.#toDetailJSON(credential)
      });
    } catch (error) {
      this.#sendError(res, this.#normalizeCreationError(error));
    }
  }


  async bulk(req, res) {
    try {
      this.#assertCredentialManager('executeBulkAction');

      const { action, credentialIds } = req.body ?? {};

      if (!Array.isArray(credentialIds) || credentialIds.length === 0 || credentialIds.length > MAX_BULK_CREDENTIAL_IDS) {
        throw this.#badRequest(`credentialIds must contain between 1 and ${MAX_BULK_CREDENTIAL_IDS} credential ids`);
      }

      if (credentialIds.some((credentialId) => typeof credentialId !== 'string' || credentialId.trim() === '')) {
        throw this.#badRequest('credentialIds must only contain non-empty strings');
      }

      const normalizedIds = [...new Set(credentialIds.map((credentialId) => credentialId.trim()))];
      if (normalizedIds.length !== credentialIds.length) throw this.#badRequest('credentialIds must not contain duplicates');
      const result = await this.credentialManager.executeBulkAction({
        action,
        credentialIds: normalizedIds
      });

      res.status(200).json({
        success: result.failed === 0,
        data: this.#toBulkJSON(result)
      });
    } catch (error) {
      this.#sendError(res, this.#normalizeBulkError(error));
    }
  }




  async export(req, res) {
    try {
      this.#assertCredentialTransferService('exportCredentials');

      const result = await this.credentialTransferService.exportCredentials(req.body ?? {}, this.#contextFromRequest(req));

      res.status(200).json({
        success: true,
        data: {
          format: result.format,
          schemaVersion: result.schemaVersion,
          generatedAt: result.generatedAt,
          filename: result.filename,
          contentType: result.contentType,
          encrypted: result.encrypted,
          payload: result.payload,
          content: result.content
        }
      });
    } catch (error) {
      this.#sendError(res, this.#normalizeTransferError(error));
    }
  }

  async importPreview(req, res) {
    try {
      this.#assertCredentialTransferService('previewImport');

      const { transfer, payload, content, password, encryptionPassword, sourceFormat, format } = req.body ?? {};
      const transferInput = transfer ?? payload ?? content;
      if (transferInput === undefined || transferInput === null) {
        throw this.#badRequest('transfer payload is required');
      }

      const importFormat = String(sourceFormat ?? format ?? 'transfer').trim().toLowerCase();
      const result = importFormat === 'csv'
        ? await this.credentialTransferService.previewCsvImport(
          transferInput,
          { source: 'csv-import' },
          this.#contextFromRequest(req)
        )
        : await this.credentialTransferService.previewImport(
          transferInput,
          { password, encryptionPassword },
          this.#contextFromRequest(req)
        );

      res.status(200).json({ success: true, data: result });
    } catch (error) {
      this.#sendError(res, this.#normalizeTransferError(error));
    }
  }

  async import(req, res) {
    try {
      this.#assertCredentialTransferService('importCredentials');

      const { transfer, payload, content, password, encryptionPassword, conflictStrategy, sourceFormat, format } = req.body ?? {};
      const transferInput = transfer ?? payload ?? content;
      if (transferInput === undefined || transferInput === null) {
        throw this.#badRequest('transfer payload is required');
      }

      const importFormat = String(sourceFormat ?? format ?? 'transfer').trim().toLowerCase();
      const result = importFormat === 'csv'
        ? await this.credentialTransferService.importCsvCredentials(
          transferInput,
          { conflictStrategy, source: 'csv-import' },
          this.#contextFromRequest(req)
        )
        : await this.credentialTransferService.importCredentials(
          transferInput,
          { password, encryptionPassword, conflictStrategy },
          this.#contextFromRequest(req)
        );

      res.status(200).json({ success: true, data: result });
    } catch (error) {
      this.#sendError(res, this.#normalizeTransferError(error));
    }
  }


  async meta(req, res) {
    try {
      res.status(200).json({
        success: true,
        data: this.#apiMetadata(req.baseUrl)
      });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async get(req, res) {
    try {
      this.#assertCredentialManager('getCredentialMetadata', 'getCredential');

      const load = this.credentialManager.getCredentialMetadata ?? this.credentialManager.getCredential;
      const credential = await load.call(this.credentialManager, req.params.credentialId);

      if (!credential) {
        throw this.#notFound('Credential not found');
      }

      res.status(200).json({
        success: true,
        data: this.#toDetailJSON(credential)
      });
    } catch (error) {
      this.#sendError(res, error);
    }
  }


  async update(req, res) {
    try {
      this.#assertCredentialManager('updateCredential');

      const credential = await this.credentialManager.updateCredential(
        req.params.credentialId,
        req.body ?? {},
        { userUpdate: true }
      );

      res.status(200).json({
        success: true,
        data: this.#toDetailJSON(credential)
      });
    } catch (error) {
      this.#sendError(res, this.#normalizeNotFoundError(error));
    }
  }


  async delete(req, res) {
    try {
      this.#assertCredentialManager('deleteCredential');

      await this.credentialManager.deleteCredential(req.params.credentialId, this.#contextFromRequest(req));

      res.status(204).send();
    } catch (error) {
      this.#sendError(res, this.#normalizeNotFoundError(error));
    }
  }


  async validate(req, res) {
    await this.#runLifecycleAction(req, res, 'validate');
  }


  async refresh(req, res) {
    await this.#runLifecycleAction(req, res, 'refresh');
  }


  async revoke(req, res) {
    await this.#runLifecycleAction(req, res, 'revoke');
  }


  async healthCheck(req, res) {
    await this.#runLifecycleAction(req, res, 'healthCheck');
  }

  async testConnection(req, res) {
    try {
      this.#assertCredentialManager('testConnection');
      const result = await this.credentialManager.testConnection(req.body ?? {});

      res.status(200).json({
        success: true,
        data: {
          providerKey: result.providerKey,
          status: result.status,
          messageKey: result.messageKey,
          checkedAt: result.checkedAt
        }
      });
    } catch (error) {
      this.#sendError(res, this.#normalizeConnectionTestError(error));
    }
  }

  async #runLifecycleAction(req, res, actionName) {
    try {
      this.#assertCredentialManager('getCredential');
      this.#assertCredentialManager(actionName);

      const credential = await this.credentialManager.getCredential(req.params.credentialId);

      if (!credential) {
        throw this.#notFound('Credential not found');
      }

      const result = await this.credentialManager[actionName](credential, this.#contextFromRequest(req));

      if (!result?.success) {
        const message = result?.error?.message ?? `Credential lifecycle action '${actionName}' failed`;
        throw this.#badRequest(message);
      }

      res.status(200).json({
        success: true,
        data: this.#toLifecycleResponseJSON(result.data)
      });
    } catch (error) {
      this.#sendError(res, this.#normalizeNotFoundError(error));
    }
  }

  #paginationFrom(query) {
    const pageSize = this.#numberQueryParam(query.pageSize ?? query.limit, 50, query.pageSize !== undefined ? 'pageSize' : 'limit');
    const page = this.#numberQueryParam(query.page, null, 'page');
    const offset = page === null
      ? this.#numberQueryParam(query.offset, 0, 'offset')
      : (page - 1) * pageSize;

    if (pageSize < 1) {
      throw this.#badRequest('pageSize must be greater than 0');
    }

    if (page !== null && page < 1) {
      throw this.#badRequest('page must be greater than 0');
    }

    if (offset < 0) {
      throw this.#badRequest('offset must be greater than or equal to 0');
    }

    return { limit: pageSize, offset, page: page ?? Math.floor(offset / pageSize) + 1, pageSize };
  }

  #listOptionsFrom(query) {
    return {
      search: query.search,
      provider: query.provider,
      type: query.type,
      state: query.state,
      sort: query.sort,
      order: query.order
    };
  }

  #numberQueryParam(value, defaultValue, name) {
    if (value === undefined || value === null) return defaultValue;

    const parsed = Number(value);

    if (!Number.isInteger(parsed)) {
      throw this.#badRequest(`${name} must be an integer`);
    }

    return parsed;
  }

  #assertCredentialManager(...operations) {
    if (!operations.some((operation) => typeof this.credentialManager?.[operation] === 'function')) {
      const operation = operations[operations.length - 1];
      throw new Error(`CredentialController requires CredentialManager.${operation}()`);
    }
  }

  #assertCredentialTransferService(operation) {
    if (!this.credentialTransferService?.[operation]) {
      throw new Error(`CredentialController requires CredentialTransferService.${operation}()`);
    }
  }

  #contextFromRequest(req) {
    return {
      userId: authenticatedUserId(req) ?? 'system',
      roleKey: req.auth?.roleKey ?? null,
      authMethod: req.auth?.authMethod ?? null
    };
  }

  #badRequest(message) {
    const error = new Error(message);
    error.statusCode = 400;
    error.code = 'BAD_REQUEST';
    return error;
  }

  #notFound(message) {
    const error = new Error(message);
    error.statusCode = 404;
    error.code = 'NOT_FOUND';
    return error;
  }

  #normalizeListError(error) {
    if (error.statusCode) return error;

    if (['UNSUPPORTED_SORT_FIELD', 'UNSUPPORTED_SORT_ORDER'].includes(error.code)) {
      return this.#badRequest(safeErrorMessage(error));
    }

    return error;
  }

  #normalizeBulkError(error) {
    if (error.statusCode) return error;

    if (['UNSUPPORTED_BULK_ACTION', 'INVALID_BULK_CREDENTIAL_IDS'].includes(error.code)) {
      return this.#badRequest(safeErrorMessage(error));
    }

    return error;
  }


  #normalizeInputError(error) {
    const message = safeErrorMessage(error, '');

    if (error.statusCode) return error;

    if (message.startsWith('Credential:') || message.startsWith('CredentialStore.save()')) {
      return this.#badRequest(message);
    }

    return error;
  }

  #normalizeCreationError(error) {
    if (error.code?.startsWith('CREDENTIAL_')) return error;
    const normalized = this.#normalizeInputError(error);
    if (normalized.statusCode) {
      normalized.code = normalized.code === 'BAD_REQUEST' ? 'CREDENTIAL_CREATE_INVALID' : normalized.code;
      normalized.messageKey = 'credential.create.invalid';
      return normalized;
    }
    const failure = new Error('Credential could not be created');
    failure.statusCode = 500;
    failure.code = 'CREDENTIAL_CREATE_FAILED';
    failure.messageKey = 'credential.create.failed';
    return failure;
  }

  #normalizeConnectionTestError(error) {
    if (error.code?.startsWith('CREDENTIAL_CONNECTION_')) return error;

    const failure = new Error('Credential connection test failed');
    failure.statusCode = 500;
    failure.code = 'CREDENTIAL_CONNECTION_FAILED';
    failure.messageKey = 'credential.connectionTest.failed';
    return failure;
  }



  #normalizeTransferError(error) {
    if (error.statusCode) return error;
    if (error.code === 'BAD_REQUEST') return this.#badRequest(safeErrorMessage(error));
    if (error.code === 'NOT_FOUND') return this.#notFound(safeErrorMessage(error, 'Credential not found'));
    return error;
  }

  #normalizeNotFoundError(error) {
    if (error.statusCode) return error;

    const message = safeErrorMessage(error, '');

    if (message.includes('not found') || message.includes('not exist') || message.includes('unknown')) {
      return this.#notFound('Credential not found');
    }

    return error;
  }

  #sendError(res, error) {
    const safe = safeError(error);
    const statusCode = safe.statusCode ?? 500;
    const code = safe.code ?? (statusCode === 404 ? 'NOT_FOUND' : 'INTERNAL_ERROR');
    const messageKey = safe.messageKey ?? error.messageKey ?? 'errors.unexpected';

    const diagnosticClassification = safe.classification ?? error.classification;
    res.status(statusCode).json({
      success: false,
      code,
      messageKey,
      message: safe.message,
      error: {
        code,
        messageKey,
        message: safe.message,
        ...(diagnosticClassification ? { classification: diagnosticClassification } : {}),
        details: safe.details ?? (error.details ? sanitizeDiagnostic(error.details) : undefined)
      }
    });
  }



  #apiMetadata(basePath = '') {
    const path = (pathname) => `${basePath}${pathname}`;
    return {
      resource: 'credentials',
      endpoints: {
        list: {
          method: 'GET',
          path: path('/api/v1/credentials'),
          queryParameters: this.#queryParameterMetadata()
        },
        meta: {
          method: 'GET',
          path: path('/api/v1/credentials/meta')
        },
        detail: {
          method: 'GET',
          path: path('/api/v1/credentials/:credentialId')
        },
        create: {
          method: 'POST',
          path: path('/api/v1/credentials')
        },
        update: {
          method: 'PUT',
          path: path('/api/v1/credentials/:credentialId')
        },
        delete: {
          method: 'DELETE',
          path: path('/api/v1/credentials/:credentialId')
        },
        bulk: {
          method: 'POST',
          path: path('/api/v1/credentials/bulk'),
          actions: this.#bulkActions()
        },
        export: {
          method: 'POST',
          path: path('/api/v1/credentials/export')
        },
        importPreview: {
          method: 'POST',
          path: path('/api/v1/credentials/import/preview'),
          sourceFormats: ['transfer', 'csv']
        },
        import: {
          method: 'POST',
          path: path('/api/v1/credentials/import'),
          sourceFormats: ['transfer', 'csv']
        },
        testConnection: {
          method: 'POST',
          path: path('/api/v1/credentials/test-connection'),
          persistence: 'none'
        }
      },
      filters: this.#filterMetadata(),
      sorting: {
        fields: this.#sortFields(),
        orders: ['asc', 'desc'],
        default: { field: 'createdAt', order: 'asc' }
      },
      pagination: {
        defaultPageSize: 50,
        supportsPage: true,
        supportsOffset: true,
        legacyParameters: ['limit', 'offset'],
        preferredParameters: ['page', 'pageSize']
      },
      actions: {
        lifecycle: ['validate', 'refresh', 'revoke', 'health-check'],
        bulk: this.#bulkActions()
      },
      responseShapes: {
        listItem: ['credentialId', 'providerKey', 'credentialMethodKey', 'providerName', 'credentialType', 'status', 'expiresAt', 'lastValidatedAt', 'lastRefreshAt', 'healthStatus', 'supportedActions'],
        detail: ['provider', 'credentialMethod', 'lifecycle', 'display', 'secretInventory', 'supportedActions'],
        error: ['success', 'error.code', 'error.message']
      }
    };
  }

  #queryParameterMetadata() {
    return {
      search: { type: 'string', required: false },
      provider: { type: 'string', required: false },
      type: { type: 'string', required: false, values: this.#credentialTypes() },
      state: { type: 'string', required: false, values: this.#lifecycleStates() },
      sort: { type: 'string', required: false, values: this.#sortFields(), default: 'createdAt' },
      order: { type: 'string', required: false, values: ['asc', 'desc'], default: 'asc' },
      page: { type: 'integer', required: false, minimum: 1 },
      pageSize: { type: 'integer', required: false, minimum: 1, default: 50 },
      limit: { type: 'integer', required: false, minimum: 1, compatibility: true },
      offset: { type: 'integer', required: false, minimum: 0, compatibility: true }
    };
  }

  #queryMetadata(query = {}) {
    return {
      search: query.search ?? null,
      provider: query.provider ?? null,
      type: query.type ?? null,
      state: query.state ?? null,
      sort: query.sort ?? 'createdAt',
      order: query.order ?? 'asc'
    };
  }

  #filterMetadata() {
    return {
      provider: { type: 'string' },
      type: { values: this.#credentialTypes() },
      state: { values: this.#lifecycleStates() },
      search: { fields: ['credentialId', 'providerKey', 'externalReference', 'displayName', 'description', 'tags'] }
    };
  }

  #sortFields() {
    return ['name', 'provider', 'type', 'state', 'expiresAt', 'createdAt', 'updatedAt'];
  }

  #credentialTypes() {
    return ['oauth', 'api-key', 'connection', 'unknown'];
  }

  #lifecycleStates() {
    return ['registered', 'active', 'expired', 'revoked', 'deleted'];
  }

  #bulkActions() {
    return ['validate', 'refresh', 'revoke', 'health-check', 'delete'];
  }

  #toBulkJSON(result) {
    return {
      action: result.action,
      requested: result.requested,
      succeeded: result.succeeded,
      failed: result.failed,
      results: result.results.map((entry) => ({
        credentialId: entry.credentialId,
        success: entry.success,
        data: entry.success ? this.#toLifecycleResponseJSON(entry.data) : undefined,
        error: entry.success ? undefined : entry.error
      }))
    };
  }

  #toLifecycleResponseJSON(value) {
    if (this.#isCredentialValue(value)) {
      return this.#toLifecycleCredentialJSON(value);
    }

    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return value;
    }

    const response = {};
    if (value.action !== undefined) response.action = value.action;
    if (value.credential !== undefined) response.credential = this.#toLifecycleCredentialJSON(value.credential);
    if (value.credentialId !== undefined) response.credentialId = value.credentialId;
    if (value.deleted !== undefined) response.deleted = Boolean(value.deleted);
    if (value.idempotent !== undefined) response.idempotent = Boolean(value.idempotent);
    if (value.provider !== undefined) {
      const provider = this.#safeProviderOutcome(value.provider);
      if (Object.keys(provider).length > 0) response.provider = provider;
    }

    if (Object.keys(response).length > 0) return response;
    return this.#safeProviderOutcome(value);
  }

  #toLifecycleCredentialJSON(value) {
    const raw = this.#toJSON(value) ?? {};
    const metadata = raw.metadata ?? {};
    const secretNames = Array.isArray(raw.secretNames)
      ? raw.secretNames
      : (Array.isArray(raw.secrets) ? raw.secrets.map((secret) => secret.name) : []);
    const type = raw.credentialMethodKey
      ?? metadata.type
      ?? metadata.credentialType
      ?? metadata.custom?.type
      ?? this.#inferCredentialType({ ...raw, secretNames });
    const safeMetadata = this.#safeMetadata(metadata);
    const safe = {
      credentialId: raw.credentialId,
      credentialKey: raw.credentialKey,
      providerKey: raw.providerKey,
      credentialMethodKey: raw.credentialMethodKey ?? null,
      externalReference: raw.externalReference ?? null,
      lifecycleState: raw.lifecycleState ?? null,
      status: raw.lifecycleState ?? null,
      metadata: safeMetadata,
      secretNames,
      secretInventory: secretNames.map((name) => ({ name })),
      providerName: raw.providerName ?? raw.providerKey,
      credentialType: type,
      expiresAt: safeMetadata.expiresAt,
      createdAt: raw.createdAt ?? null,
      updatedAt: raw.updatedAt ?? null,
      version: raw.version ?? null,
      supportedActions: this.#supportedActionsFor(type, raw.lifecycleState)
    };

    if (raw.providerProfile && typeof raw.providerProfile === 'object') {
      safe.providerProfile = Object.fromEntries(
        ['providerKey', 'version', 'providerKind', 'digest']
          .filter((key) => raw.providerProfile[key] !== undefined)
          .map((key) => [key, raw.providerProfile[key]])
      );
    }

    return safe;
  }

  #isCredentialValue(value) {
    if (!value || typeof value !== 'object') return false;
    if (typeof value.toMetadataJSON === 'function') return true;
    if (typeof value.toJSON === 'function') {
      const raw = value.toJSON();
      return raw && typeof raw === 'object'
        && ('credentialId' in raw || 'secrets' in raw || 'lifecycleState' in raw);
    }
    return 'credentialId' in value
      && ('providerKey' in value || 'secrets' in value || 'lifecycleState' in value);
  }

  #safeProviderOutcome(value) {
    const raw = value && typeof value.toJSON === 'function' ? value.toJSON() : value;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};

    const allowedKeys = [
      'available',
      'checkedAt',
      'classification',
      'code',
      'healthy',
      'healthStatus',
      'latencyMs',
      'messageKey',
      'providerKey',
      'status',
      'validated'
    ];

    return Object.fromEntries(allowedKeys
      .filter((key) => Object.hasOwn(raw, key) && (typeof raw[key] !== 'object' || raw[key] === null))
      .map((key) => [key, raw[key]]));
  }

  #toDetailJSON(value) {
    const raw = this.#toJSON(value);
    const data = this.#toListJSON(value);
    const metadata = data.metadata ?? {};
    const provider = this.#providerSummaryFor(data.providerKey);
    const supportedActions = this.#supportedActionsForProvider(
      provider?.capabilities,
      data.credentialType,
      data.lifecycleState,
      data.credentialMethodKey,
      provider
    );

    return {
      ...data,
      provider,
      credentialMethod: this.#credentialMethodSummary(provider, data.credentialMethodKey),
      status: data.lifecycleState,
      lifecycle: {
        state: data.lifecycleState,
        createdAt: data.createdAt ?? null,
        updatedAt: data.updatedAt ?? null,
        expiresAt: data.expiresAt ?? null,
        lastValidatedAt: data.lastValidatedAt ?? null,
        lastRefreshAt: data.lastRefreshAt ?? null,
        healthStatus: data.healthStatus ?? null
      },
      secretInventory: this.#secretInventory(raw.secretInventory ?? raw.secrets),
      display: {
        name: metadata.displayName ?? data.externalReference ?? data.credentialId,
        description: metadata.description ?? null,
        tags: metadata.tags ?? []
      },
      supportedActions
    };
  }

  #providerSummaryFor(providerKey) {
    if (!providerKey || typeof this.providerManager?.getProvider !== 'function') {
      return {
        providerKey,
        key: providerKey,
        displayName: providerKey,
        description: null,
        capabilities: []
      };
    }

    try {
      const provider = this.providerManager.getProvider(providerKey);
      const key = provider.key ?? provider.providerKey ?? providerKey;

      return {
        providerKey: key,
        key,
        displayName: provider.displayName ?? key,
        description: provider.description ?? null,
        capabilities: provider.capabilities?.toArray?.() ?? provider.capabilities ?? [],
        credentialMethods: provider.credentialMethods ?? [],
        providerMethodBindings: provider.providerMethodBindings ?? []
      };
    } catch {
      return {
        providerKey,
        key: providerKey,
        displayName: providerKey,
        description: null,
        capabilities: []
      };
    }
  }

  #secretInventory(secrets = []) {
    return secrets.map((secret) => ({
      name: secret.name,
      type: secret.type ?? null,
      required: secret.required ?? null,
      hasValue: secret.hasValue ?? (secret.value !== undefined && secret.value !== null && secret.value !== ''),
      valueMasked: (secret.hasValue ?? (secret.value !== undefined && secret.value !== null && secret.value !== ''))
        ? '********'
        : null
    }));
  }

  #credentialMethodSummary(provider, credentialMethodKey) {
    if (!credentialMethodKey) return null;
    const method = (provider?.credentialMethods ?? []).find((candidate) => candidate.key === credentialMethodKey);
    const binding = (provider?.providerMethodBindings ?? []).find((candidate) => candidate.methodKey === credentialMethodKey);
    if (!method || !binding) return { key: credentialMethodKey, available: false };
    return {
      key: method.key,
      displayName: binding.displayName ?? method.displayName,
      description: binding.description ?? method.description ?? null,
      operationCapabilities: method.operationCapabilities ?? []
    };
  }

  #supportedActionsForProvider(capabilities = [], type, lifecycleState, credentialMethodKey = null, provider = null) {
    if (lifecycleState === 'deleted') return [];

    if (credentialMethodKey) {
      const method = (provider?.credentialMethods ?? []).find((candidate) => candidate.key === credentialMethodKey);
      if (!method) return [];
      const operations = new Set(method.operationCapabilities ?? []);
      const actions = [];
      if (operations.has('validation')) actions.push('validate');
      if (operations.has('health-check')) actions.push('health-check');
      if (operations.has('refresh')) actions.push('refresh');
      if (operations.has('revoke') && lifecycleState !== 'revoked') actions.push('revoke');
      return actions;
    }

    const capabilitySet = new Set(capabilities ?? []);

    if (capabilitySet.size === 0) {
      return this.#supportedActionsFor(type, lifecycleState);
    }

    const actions = [];

    if (capabilitySet.has('validation')) actions.push('validate');
    if (capabilitySet.has('health-check')) actions.push('health-check');
    if (capabilitySet.has('refresh')) actions.push('refresh');
    if (capabilitySet.has('revoke') && lifecycleState !== 'revoked') actions.push('revoke');

    return actions;
  }

  #toListJSON(value) {
    const data = this.#toJSON(value);
    const metadata = data.metadata ?? {};
    const type = data.credentialMethodKey ?? metadata.type ?? metadata.credentialType ?? metadata.custom?.type ?? this.#inferCredentialType(data);
    const safeMetadata = this.#safeMetadata(metadata);

    return {
      credentialId: data.credentialId,
      credentialGeneration: data.credentialGeneration,
      credentialKey: data.credentialKey,
      providerKey: data.providerKey,
      credentialMethodKey: data.credentialMethodKey ?? null,
      externalReference: data.externalReference ?? null,
      lifecycleState: data.lifecycleState ?? null,
      metadata: safeMetadata,
      ...(Array.isArray(data.secretNames) ? { secretNames: [...data.secretNames] } : {}),
      ...(Array.isArray(data.secretInventory) ? { secretInventory: this.#secretInventory(data.secretInventory) } : {}),
      createdAt: data.createdAt ?? null,
      updatedAt: data.updatedAt ?? null,
      version: data.version ?? null,
      ...(data.providerProfile && typeof data.providerProfile === 'object'
        ? { providerProfile: Object.fromEntries(['providerKey', 'version', 'providerKind', 'digest']
          .filter((key) => data.providerProfile[key] !== undefined)
          .map((key) => [key, data.providerProfile[key]])) }
        : {}),
      providerName: safeMetadata.providerName ?? data.providerKey,
      credentialType: type,
      status: data.lifecycleState,
      expiresAt: safeMetadata.expiresAt ?? null,
      lastValidatedAt: safeMetadata.lastValidatedAt ?? null,
      lastRefreshAt: safeMetadata.lastRefreshAt ?? null,
      healthStatus: safeMetadata.healthStatus ?? null,
      supportedActions: this.#supportedActionsFor(type, data.lifecycleState)
    };
  }

  #safeMetadata(metadata = {}) {
    const raw = metadata && typeof metadata === 'object' ? metadata : {};
    const custom = raw.custom && typeof raw.custom === 'object' ? raw.custom : {};
    const flatCustom = Object.fromEntries(
      [...CredentialMetadataPolicy.publicCustomKeys]
        .filter((key) => Object.hasOwn(raw, key) && !Object.hasOwn(custom, key))
        .map((key) => [key, raw[key]])
    );
    return CredentialMetadata.from({ ...raw, custom: { ...custom, ...flatCustom } }).toPublicJSON();
  }

  #inferCredentialType(data) {
    const secretNames = data.secretNames ?? (data.secrets ?? []).map((secret) => secret.name);

    if (secretNames.includes('apiKey')) return 'api-key';
    if (secretNames.includes('host') || secretNames.includes('password') || secretNames.includes('privateKey')) return 'connection';
    if (secretNames.includes('accessToken') || secretNames.includes('refreshToken')) return 'oauth';

    return 'unknown';
  }

  #supportedActionsFor(type, lifecycleState) {
    if (lifecycleState === 'deleted') return [];

    const actions = ['validate', 'health-check'];

    if (type === 'oauth') actions.push('refresh');
    if (lifecycleState !== 'revoked') actions.push('revoke');

    return actions;
  }

  #toJSON(value) {
    if (value && typeof value.toJSON === 'function') {
      return value.toJSON();
    }

    return value;
  }
}
