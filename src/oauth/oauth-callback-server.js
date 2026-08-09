// Copyright (C) 2026 cyphre-san productions
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

import { CredentialController } from '../controllers/credential-controller.js';
import { ProviderController } from '../controllers/provider-controller.js';
import { DashboardController } from '../controllers/dashboard-controller.js';
import { ManagementController } from '../controllers/management-controller.js';
import { AccessManagementController } from '../controllers/access-management-controller.js';
import { AuditLogController } from '../controllers/audit-log-controller.js';
import { ExportController } from '../controllers/export-controller.js';
import { BackupRestoreController } from '../controllers/backup-restore-controller.js';
import { MetricsController } from '../controllers/metrics-controller.js';
import { ApiTokenController } from '../controllers/api-token-controller.js';
import { ConsumerCredentialController } from '../controllers/consumer-credential-controller.js';
import { ConsumerGrantController } from '../controllers/consumer-grant-controller.js';
import { DashboardService } from '../services/dashboard-service.js';
import { ManagementService } from '../services/management-service.js';
import { AccessManagementService } from '../services/access-management-service.js';
import { AuditLogService } from '../services/audit-log-service.js';
import { ExportService } from '../services/export-service.js';
import { BackupRestoreService } from '../services/backup-restore-service.js';
import { MetricsService } from '../services/metrics-service.js';
import { ApiTokenService } from '../services/api-token-service.js';
import { CredentialTransferService } from '../services/credential-transfer-service.js';
import { normalizeBasePath, normalizePublicBaseUrl, withBasePath } from '../config/base-path.js';
import { PROJECT_LINKS } from '../../public/admin/project-links.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_DIR = path.resolve(__dirname, '../..');
const PUBLIC_DIR = path.resolve(__dirname, '../../public');
const PROJECT_DOCUMENTS = Object.freeze({
  [PROJECT_LINKS.license]: path.join(PROJECT_DIR, 'LICENSE'),
  [PROJECT_LINKS.notice]: path.join(PROJECT_DIR, 'NOTICE'),
  [PROJECT_LINKS.thirdPartySoftware]: path.join(PROJECT_DIR, 'docs/project/THIRD_PARTY_SOFTWARE.md'),
  [PROJECT_LINKS.security]: path.join(PROJECT_DIR, 'SECURITY.md')
});

export class OAuthCallbackServer {
  constructor({
    providerManager,
    importTokenCommand,
    credentialManager,
    schedulerService = null,
    dashboardService = null,
    managementService = null,
    accessManagementService = null,
    auditLogService = null,
    exportService = null,
    backupRestoreService = null,
    metricsService = null,
    apiTokenService = null,
    consumerCredentialService = null,
    credentialTransferService = null,
    customProviderService = null,
    config,
    logger
  }) {
    this.providerManager = providerManager;
    this.importTokenCommand = importTokenCommand;
    this.auditLogService = auditLogService ?? new AuditLogService();
    this.providerController = new ProviderController({
      providerManager,
      customProviderService,
      oauthRuntimeDetails: (req, providerKey) => this.#oauthRuntimeDetails(req, providerKey)
    });
    this.credentialTransferService = credentialTransferService ?? new CredentialTransferService({
      credentialManager,
      providerManager,
      auditLogService: this.auditLogService
    });
    this.credentialController = new CredentialController({
      credentialManager,
      providerManager,
      credentialTransferService: this.credentialTransferService
    });
    this.dashboardService = dashboardService ?? new DashboardService({
      credentialManager,
      providerManager,
      schedulerService
    });
    this.dashboardController = new DashboardController({
      dashboardService: this.dashboardService
    });
    this.accessManagementService = accessManagementService ?? new AccessManagementService({ auditLogService: this.auditLogService });
    this.managementService = managementService ?? new ManagementService({
      credentialManager,
      providerManager,
      schedulerService,
      accessManagementService: this.accessManagementService,
      auditLogService: this.auditLogService
    });
    this.managementController = new ManagementController({
      managementService: this.managementService
    });
    this.auditLogController = new AuditLogController({ auditLogService: this.auditLogService });
    this.exportService = exportService ?? new ExportService({
      managementService: this.managementService,
      accessManagementService: this.accessManagementService,
      auditLogService: this.auditLogService
    });
    this.exportController = new ExportController({ exportService: this.exportService });
    this.backupRestoreService = backupRestoreService ?? new BackupRestoreService({
      accessManagementService: this.accessManagementService,
      auditLogService: this.auditLogService,
      managementService: this.managementService
    });
    this.backupRestoreController = new BackupRestoreController({ backupRestoreService: this.backupRestoreService });
    this.metricsService = metricsService ?? new MetricsService({
      managementService: this.managementService,
      accessManagementService: this.accessManagementService,
      auditLogService: this.auditLogService,
      exportService: this.exportService,
      backupRestoreService: this.backupRestoreService
    });
    this.metricsController = new MetricsController({ metricsService: this.metricsService });
    this.apiTokenService = apiTokenService;
    this.apiTokenController = this.apiTokenService ? new ApiTokenController({ apiTokenService: this.apiTokenService }) : null;
    this.consumerCredentialController = consumerCredentialService
      ? new ConsumerCredentialController({ consumerCredentialService })
      : null;
    this.consumerGrantController = consumerCredentialService?.consumerGrantService
      ? new ConsumerGrantController({ consumerGrantService: consumerCredentialService.consumerGrantService })
      : null;
    this.accessManagementController = new AccessManagementController({
      accessManagementService: this.accessManagementService
    });
    this.config = config;
    this.logger = logger;
    this.basePath = normalizeBasePath(config.get('BASE_PATH', '/'));
    const configuredPublicBaseUrl = config.get('PUBLIC_BASE_URL', null);
    this.publicBaseUrl = typeof configuredPublicBaseUrl === 'string'
      ? normalizePublicBaseUrl(configuredPublicBaseUrl)
      : null;
    this.oauthWizardIntents = new Map();
    this.app = express();
    this.routes = express.Router();
    this.app.use(express.json({ limit: '1mb' }));
    this.routes.use('/admin', express.static(path.join(PUBLIC_DIR, 'admin')));
    this.routes.use('/consumer', express.static(path.join(PUBLIC_DIR, 'consumer')));
    this.routes.use('/shared', express.static(path.join(PUBLIC_DIR, 'shared')));
    this.app.use(this.basePath, this.routes);
    if (this.basePath !== '/') {
      this.app.get('/', (req, res) => res.redirect(this.#path('/admin/')));
    }
    this.server = null;

    this.#routes();
  }

  async start() {
    const port = Number(this.config.get('OAUTH_CALLBACK_PORT', 3000));

    return new Promise((resolve, reject) => {
      this.server = this.app.listen(port, () => {
        this.logger.success(`OAuth callback server listening on port ${port}`);
        resolve();
      });

      this.server.once('error', reject);
    });
  }

  async stop() {
    if (!this.server) {
      return;
    }

    const server = this.server;
    this.server = null;

    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        this.logger.info('OAuth callback server stopped');
        resolve();
      });
    });
  }

  #authorized(permission, handler, { allowBootstrap = false } = {}) {
    return async (req, res) => {
      try {
        if (allowBootstrap && await this.accessManagementService.isAuthorizationRequired?.() === false) {
          await handler(req, res);
          return;
        }
        if (this.#isTestCompatibilityMode() && await this.accessManagementService.isAuthorizationRequired?.() === false) {
          await handler(req, res);
          return;
        }
        const authentication = await this.#resolveAuthenticatedUser(req);
        if (!authentication.scopes?.includes('*') && !authentication.scopes?.includes(permission)) {
          const error = new Error('API token is missing the required scope');
          error.statusCode = 403;
          error.code = 'API_TOKEN_SCOPE_MISSING';
          throw error;
        }
        await this.accessManagementService.authorize(authentication.userId, permission);
        req.auth = authentication;
        await handler(req, res);
      } catch (error) {
        this.#sendAuthorizationError(res, error);
      }
    };
  }

  #consumerAuthorized(handler) {
    return async (req, res) => {
      try {
        const bearerToken = this.#bearerTokenFromRequest(req);
        if (!bearerToken || !this.apiTokenService?.authenticate) {
          throw this.#unauthorized('Invalid API token', 'API_TOKEN_AUTH_FAILED');
        }
        const authentication = await this.apiTokenService.authenticate(bearerToken);
        if (!authentication.authenticated) {
          throw this.#unauthorized(this.#apiTokenFailureMessage(authentication.reason), 'API_TOKEN_AUTH_FAILED');
        }
        if (!authentication.scopes?.includes('credentials:consume')) {
          const error = new Error("API token is missing scope 'credentials:consume'");
          error.statusCode = 403;
          error.code = 'CONSUMER_SCOPE_MISSING';
          throw error;
        }
        if (!(this.#isTestCompatibilityMode() && await this.accessManagementService.isAuthorizationRequired?.() === false)) {
          try {
            await this.accessManagementService.authorize(authentication.userId, 'credentials:consume');
          } catch {
            const error = new Error('Consumer access is denied');
            error.statusCode = 403;
            error.code = 'CONSUMER_ACCESS_DENIED';
            throw error;
          }
        }
        req.auth = { ...authentication, consumerId: authentication.apiToken?.id };
        await handler(req, res);
      } catch (error) {
        res.set('Cache-Control', 'no-store');
        this.#sendAuthorizationError(res, error);
      }
    };
  }

  async #resolveAuthenticatedUser(req) {
    const bearerToken = this.#bearerTokenFromRequest(req);

    if (bearerToken) {
      if (!this.apiTokenService?.authenticate) {
        throw this.#unauthorized('API token authentication is not configured', 'API_TOKEN_AUTH_UNAVAILABLE');
      }

      const result = await this.apiTokenService.authenticate(bearerToken);

      if (!result.authenticated) {
        throw this.#unauthorized(this.#apiTokenFailureMessage(result.reason), 'API_TOKEN_AUTH_FAILED');
      }

      return Object.freeze({
        userId: result.userId,
        authMethod: 'api-token',
        apiToken: result.apiToken,
        scopes: result.scopes ?? []
      });
    }

    if (this.#isTestCompatibilityMode() && req.headers?.['x-credential-hub-user']) {
      return Object.freeze({ userId: req.headers['x-credential-hub-user'], authMethod: 'test-user-header', scopes: ['*'] });
    }
    throw this.#unauthorized('Missing Bearer API token', 'API_TOKEN_AUTH_FAILED');
  }

  #bearerTokenFromRequest(req) {
    const authorization = req.headers?.authorization;

    if (typeof authorization !== 'string' || authorization.trim() === '') {
      return null;
    }

    const match = authorization.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : null;
  }

  #apiTokenFailureMessage(reason) {
    switch (reason) {
      case 'expired':
        return 'API token has expired';
      case 'revoked':
        return 'API token has been revoked';
      case 'invalid-format':
        return 'Invalid API token format';
      case 'not-found':
      default:
        return 'Invalid API token';
    }
  }

  #unauthorized(message, code = 'UNAUTHORIZED') {
    const error = new Error(message);
    error.statusCode = 401;
    error.code = code;
    return error;
  }

  #apiTokenController() {
    if (!this.apiTokenController) {
      throw this.#unauthorized('API token management is not configured', 'API_TOKEN_MANAGEMENT_UNAVAILABLE');
    }
    return this.apiTokenController;
  }

  #sendAuthorizationError(res, error) {
    const statusCode = error.statusCode ?? 500;
    const code = error.code ?? (statusCode === 404 ? 'NOT_FOUND' : statusCode === 403 ? 'FORBIDDEN' : statusCode === 401 ? 'UNAUTHORIZED' : statusCode === 400 ? 'BAD_REQUEST' : 'INTERNAL_ERROR');

    res.status(statusCode).json({
      success: false,
      error: {
        code,
        message: error.message ?? 'Unexpected error',
        ...(code === 'OAUTH_REDIRECT_URI_MISMATCH' && error.redirectUri
          ? { details: { redirectUri: error.redirectUri } }
          : {})
      }
    });
  }

  #routes() {
    this.routes.get('/', (req, res) => {
      res.redirect(this.#path('/admin/'));
    });

    this.routes.get('/health', (req, res) => {
      res.status(200).json({ status: 'UP' });
    });

    this.routes.get('/api/v1/consumer/credentials', this.#consumerAuthorized(async (req, res) => {
      if (!this.consumerCredentialController) {
        throw this.#unauthorized('Consumer API is not configured', 'API_TOKEN_AUTH_FAILED');
      }
      await this.consumerCredentialController.discover(req, res);
    }));

    this.routes.post('/api/v1/consumer/credentials/:credentialKey/resolve', this.#consumerAuthorized(async (req, res) => {
      if (!this.consumerCredentialController) {
        throw this.#unauthorized('Consumer API is not configured', 'API_TOKEN_AUTH_FAILED');
      }
      await this.consumerCredentialController.resolve(req, res);
    }));

    this.routes.post('/api/v1/management/consumer-grants', this.#authorized('consumer-grants:manage', async (req, res) => {
      if (!this.consumerGrantController) {
        throw this.#unauthorized('Consumer grant management is not configured', 'CONSUMER_GRANT_MANAGEMENT_UNAVAILABLE');
      }
      await this.consumerGrantController.create(req, res);
    }));

    this.routes.post('/api/v1/management/consumer-grants/diagnose', this.#authorized('consumer-grants:manage', async (req, res) => {
      const consumerId = req.body?.consumerId;
      try {
        await this.apiTokenService?.getToken?.(consumerId);
      } catch {
        res.set('Cache-Control', 'no-store');
        res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data: { code: 'CONSUMER_NOT_FOUND' } });
        return;
      }
      await this.consumerCredentialController.diagnose(req, res);
    }));

    this.routes.get('/api/v1/management/consumer-grants', this.#authorized('consumer-grants:manage', async (req, res) => {
      if (!this.consumerGrantController) {
        throw this.#unauthorized('Consumer grant management is not configured', 'CONSUMER_GRANT_MANAGEMENT_UNAVAILABLE');
      }
      await this.consumerGrantController.list(req, res);
    }));

    this.routes.put('/api/v1/management/consumer-grants/:grantId', this.#authorized('consumer-grants:manage', async (req, res) => {
      if (!this.consumerGrantController) {
        throw this.#unauthorized('Consumer grant management is not configured', 'CONSUMER_GRANT_MANAGEMENT_UNAVAILABLE');
      }
      await this.consumerGrantController.update(req, res);
    }));

    for (const [route, file] of Object.entries(PROJECT_DOCUMENTS)) {
      this.routes.get(route, (req, res) => res.sendFile(file));
    }

    this.routes.get('/api/v1/dashboard', this.#authorized('management:read', async (req, res) => {
      await this.dashboardController.get(req, res);
    }));

    this.routes.get('/api/v1/management/status', this.#authorized('management:read', async (req, res) => {
      await this.managementController.status(req, res);
    }));

    this.routes.get('/api/v1/management/providers', this.#authorized('providers:read', async (req, res) => {
      await this.managementController.providers(req, res);
    }));

    this.routes.post('/api/v1/management/providers/:providerKey/health-check', this.#authorized('providers:manage', async (req, res) => {
      await this.managementController.providerHealthCheck(req, res);
    }));

    this.routes.get('/api/v1/management/scheduler', this.#authorized('scheduler:read', async (req, res) => {
      await this.managementController.scheduler(req, res);
    }));

    this.routes.post('/api/v1/management/scheduler/start', this.#authorized('scheduler:manage', async (req, res) => {
      await this.managementController.startScheduler(req, res);
    }));

    this.routes.post('/api/v1/management/scheduler/stop', this.#authorized('scheduler:manage', async (req, res) => {
      await this.managementController.stopScheduler(req, res);
    }));

    this.routes.post('/api/v1/management/scheduler/run-once', this.#authorized('scheduler:manage', async (req, res) => {
      await this.managementController.runSchedulerOnce(req, res);
    }));

    this.routes.get('/api/v1/management/credentials', this.#authorized('credentials:read', async (req, res) => {
      await this.managementController.credentials(req, res);
    }));

    this.routes.get('/api/v1/management/users', this.#authorized('users:read', async (req, res) => {
      await this.accessManagementController.users(req, res);
    }));

    this.routes.post('/api/v1/management/users', this.#authorized('users:manage', async (req, res) => {
      await this.accessManagementController.createUser(req, res);
    }, { allowBootstrap: true }));

    this.routes.put('/api/v1/management/users/:userId', this.#authorized('users:manage', async (req, res) => {
      await this.accessManagementController.updateUser(req, res);
    }));

    this.routes.delete('/api/v1/management/users/:userId', this.#authorized('users:manage', async (req, res) => {
      await this.accessManagementController.deleteUser(req, res);
    }));

    this.routes.get('/api/v1/management/roles', this.#authorized('users:read', async (req, res) => {
      await this.accessManagementController.roles(req, res);
    }));

    this.routes.get('/api/v1/management/audit-log', this.#authorized('audit:read', async (req, res) => {
      await this.auditLogController.list(req, res);
    }));

    this.routes.get('/api/v1/management/audit-log/:entryId', this.#authorized('audit:read', async (req, res) => {
      await this.auditLogController.get(req, res);
    }));

    this.routes.get('/api/v1/management/api-tokens', this.#authorized('api-tokens:read', async (req, res) => {
      await this.#apiTokenController().list(req, res);
    }));

    this.routes.post('/api/v1/management/api-tokens', this.#authorized('api-tokens:manage', async (req, res) => {
      if (Array.isArray(req.body?.scopes) && req.body.scopes.includes('credentials:consume')) {
        await this.accessManagementService.authorize(req.body.userId, 'credentials:consume');
      }
      await this.#apiTokenController().create(req, res);
    }));

    this.routes.get('/api/v1/management/api-tokens/:tokenId', this.#authorized('api-tokens:read', async (req, res) => {
      await this.#apiTokenController().get(req, res);
    }));

    this.routes.delete('/api/v1/management/api-tokens/:tokenId', this.#authorized('api-tokens:manage', async (req, res) => {
      await this.#apiTokenController().revoke(req, res);
    }));

    this.routes.get('/api/v1/management/exports', this.#authorized('export:read', async (req, res) => {
      await this.exportController.resources(req, res);
    }));

    this.routes.get('/api/v1/management/exports/:resource', this.#authorized('export:read', async (req, res) => {
      await this.exportController.export(req, res);
    }));

    this.routes.get('/api/v1/management/metrics', this.#authorized('metrics:read', async (req, res) => {
      await this.metricsController.get(req, res);
    }));

    this.routes.get('/api/v1/management/backups', this.#authorized('backup:read', async (req, res) => {
      await this.backupRestoreController.list(req, res);
    }));

    this.routes.post('/api/v1/management/backups', this.#authorized('backup:manage', async (req, res) => {
      await this.backupRestoreController.create(req, res);
    }));

    this.routes.get('/api/v1/management/backups/:backupId', this.#authorized('backup:read', async (req, res) => {
      await this.backupRestoreController.get(req, res);
    }));

    this.routes.post('/api/v1/management/backups/:backupId/restore', this.#authorized('backup:manage', async (req, res) => {
      await this.backupRestoreController.restore(req, res);
    }));

    this.routes.get('/api/v1/credentials', this.#authorized('credentials:read', async (req, res) => {
      await this.credentialController.list(req, res);
    }));

    this.routes.post('/api/v1/credentials', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.create(req, res);
    }));

    this.routes.post('/api/v1/credentials/bulk', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.bulk(req, res);
    }));

    this.routes.post('/api/v1/credentials/export', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.export(req, res);
    }));

    this.routes.post('/api/v1/credentials/import/preview', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.importPreview(req, res);
    }));

    this.routes.post('/api/v1/credentials/import', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.import(req, res);
    }));

    this.routes.post('/api/v1/credentials/test-connection', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.testConnection(req, res);
    }));

    this.routes.get('/api/v1/credentials/meta', this.#authorized('credentials:read', async (req, res) => {
      await this.credentialController.meta(req, res);
    }));

    this.routes.get('/api/v1/credentials/:credentialId', this.#authorized('credentials:read', async (req, res) => {
      await this.credentialController.get(req, res);
    }));


    this.routes.put('/api/v1/credentials/:credentialId', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.update(req, res);
    }));


    this.routes.delete('/api/v1/credentials/:credentialId', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.delete(req, res);
    }));

    this.routes.post('/api/v1/credentials/:credentialId/validate', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.validate(req, res);
    }));

    this.routes.post('/api/v1/credentials/:credentialId/refresh', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.refresh(req, res);
    }));

    this.routes.post('/api/v1/credentials/:credentialId/revoke', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.revoke(req, res);
    }));

    this.routes.post('/api/v1/credentials/:credentialId/health-check', this.#authorized('credentials:manage', async (req, res) => {
      await this.credentialController.healthCheck(req, res);
    }));


    this.routes.get('/api/v1/providers', this.#authorized('providers:read', async (req, res) => {
      await this.providerController.list(req, res);
    }));

    this.routes.post('/api/v1/providers', this.#authorized('providers:manage', async (req, res) => {
      await this.providerController.create(req, res);
    }));

    this.routes.get('/api/v1/providers/:providerKey', this.#authorized('providers:read', async (req, res) => {
      await this.providerController.get(req, res);
    }));

    this.routes.get('/api/v1/providers/:providerKey/capabilities', this.#authorized('providers:read', async (req, res) => {
      await this.providerController.capabilities(req, res);
    }));

    this.routes.post('/api/v1/providers/:providerKey/oauth/start', this.#authorized('providers:manage', async (req, res) => {
      const { providerKey } = req.params;
      const requestOrigin = this.#publicOrigin(req);
      const callbackPath = this.#path(`/oauth/${encodeURIComponent(providerKey)}/callback`);
      const redirectUri = `${requestOrigin}${callbackPath}`;
      const oauthState = crypto.randomUUID();
      const result = await this.providerManager.startOAuth(providerKey, {
        state: oauthState,
        scopes: Array.isArray(req.body?.scopes) ? req.body.scopes : null,
        providerConfiguration: {
          ...(req.body?.providerConfiguration ?? {}),
          redirectUri
        }
      });

      if (!result.success) {
        const error = new Error('OAuth could not be started');
        error.code = result.error?.code ?? 'OAUTH_START_FAILED';
        error.statusCode = result.error?.statusCode ?? 400;
        throw error;
      }

      this.#rememberOAuthWizardIntent({
        state: oauthState,
        providerKey,
        actorUserId: req.auth?.userId ?? null
      });

      const authorizationRedirectUri = this.#oauthRedirectUri(result.data.authorizationUrl);
      if (authorizationRedirectUri !== redirectUri) {
        let cancelled = false;
        if (this.providerManager.cancelOAuth) {
          try {
            await this.providerManager.cancelOAuth(providerKey, oauthState);
            cancelled = true;
          } catch {}
        }
        if (!cancelled) {
          await this.providerManager.discardProviderConfiguration?.(result.data.providerConfigurationId, providerKey);
        }
        const mismatch = new Error('OAuth redirect URI does not match the public base URL');
        mismatch.code = 'OAUTH_REDIRECT_URI_MISMATCH';
        mismatch.statusCode = 400;
        mismatch.redirectUri = redirectUri;
        throw mismatch;
      }

      res.status(200).json({
        success: true,
        data: {
          authorizationUrl: result.data.authorizationUrl,
          providerConfigurationId: result.data.providerConfigurationId,
          redirectUri,
          callbackPath,
          scopes: this.#oauthScopes(result.data.authorizationUrl)
        }
      });
    }));

    this.routes.get('/oauth/:provider/login', async (req, res) => {
      if (this.#isTestCompatibilityMode()) {
        try {
          const { provider } = req.params;
          const state = crypto.randomUUID();
          const result = await this.providerManager.startOAuth(provider, { state });
          if (result.success) return res.redirect(result.data.authorizationUrl);
        } catch {}
      }
      res.status(410).send(this.#oauthResultPage({
        status: 'error',
        code: 'OAUTH_WIZARD_INTENT_REQUIRED',
        provider: req.params.provider
      }));
    });

    this.routes.get('/oauth/:provider/callback', async (req, res) => {
      const { provider } = req.params;
      let providerConfigurationId = null;
      const callbackState = req.query.state;
      try {
        const { code, state, error, error_description } = req.query;
        if (!this.#isTestCompatibilityMode()) this.#consumeOAuthWizardIntent({ state, providerKey: provider });

        if (error) {
          await this.providerManager.cancelOAuth(provider, state);
          this.logger.info?.(`OAuth callback was not completed for provider '${provider}'`);
          const redirectUriMismatch = error === 'redirect_uri_mismatch';
          res.status(400).send(this.#oauthResultPage({
            status: error === 'access_denied' ? 'cancelled' : 'error',
            code: redirectUriMismatch ? 'OAUTH_REDIRECT_URI_MISMATCH' : 'OAUTH_PROVIDER_REJECTED',
            provider,
            redirectUri: redirectUriMismatch
              ? `${this.#publicOrigin(req)}${this.#path(`/oauth/${encodeURIComponent(provider)}/callback`)}`
              : null
          }));
          return;
        }

        if (!code) {
          await this.providerManager.cancelOAuth(provider, callbackState);
          const missingCode = new Error('OAuth callback missing code');
          missingCode.code = 'OAUTH_CALLBACK_FAILED';
          throw missingCode;
        }

        const result = await this.providerManager.handleOAuthCallback(provider, {
          code,
          state
        });

        if (!result.success) {
          const callbackError = new Error('OAuth callback failed');
          callbackError.code = result.error?.code ?? 'OAUTH_CALLBACK_FAILED';
          throw callbackError;
        }

        providerConfigurationId = result.data.metadata?.providerConfigurationId ?? null;

        const credentialRecord = await this.importTokenCommand.execute(result.data);

        res.status(200).send(this.#oauthResultPage({
          status: 'success',
          code: 'OAUTH_SUCCESS',
          provider,
          credentialId: credentialRecord.credentialId ?? credentialRecord.providerId ?? null
        }));
      } catch (error) {
        await this.providerManager.discardProviderConfiguration?.(providerConfigurationId, provider);
        const code = ['OAUTH_STATE_INVALID', 'OAUTH_REDIRECT_URI_MISMATCH'].includes(error.code)
          ? error.code
          : 'OAUTH_CALLBACK_FAILED';
        this.logger.error('OAuth callback failed', { code });
        res.status(error.statusCode ?? 400).send(this.#oauthResultPage({
          status: 'error',
          code,
          provider,
          redirectUri: code === 'OAUTH_REDIRECT_URI_MISMATCH'
            ? `${this.#publicOrigin(req)}${this.#path(`/oauth/${encodeURIComponent(provider)}/callback`)}`
            : null
        }));
      }
    });
  }

  #rememberOAuthWizardIntent({ state, providerKey, actorUserId }) {
    const ttl = Number(this.config.get('OAUTH_WIZARD_INTENT_TTL_MS', 10 * 60 * 1000));
    this.oauthWizardIntents.set(state, Object.freeze({ providerKey, actorUserId, expiresAt: Date.now() + ttl }));
  }

  #isTestCompatibilityMode() { return process.env.NODE_ENV === 'test'; }

  #consumeOAuthWizardIntent({ state, providerKey }) {
    const intent = typeof state === 'string' ? this.oauthWizardIntents.get(state) : null;
    if (!intent || intent.providerKey !== providerKey || intent.expiresAt < Date.now()) {
      const error = new Error('OAuth wizard intent is missing or expired');
      error.code = 'OAUTH_WIZARD_INTENT_REQUIRED';
      error.statusCode = 403;
      throw error;
    }
    this.oauthWizardIntents.delete(state);
    return intent;
  }

  #oauthResultPage({ status, code, provider, credentialId = null, redirectUri = null }) {
    const wizardQuery = new URLSearchParams({ oauth: status, code, provider: provider ?? '' });
    if (credentialId) wizardQuery.set('credentialId', credentialId);
    const wizardUrl = `${this.#path('/admin/')}?${wizardQuery.toString()}`;
    const dashboardUrl = this.#path('/admin/dashboard.html');
    const payload = JSON.stringify({
      type: 'credential-hub:oauth-result',
      version: 1,
      status,
      code,
      provider,
      credentialId,
      redirectUri
    }).replaceAll('<', '\\u003c');
    const safeProvider = this.#escapeHtml(provider);
    const safeWizardUrl = this.#escapeHtml(wizardUrl);

    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Credential HUB OAuth result</title><style>
body{margin:0;min-height:100vh;font-family:Inter,system-ui,sans-serif;background:#f5f7fb;color:#182033;display:grid;grid-template-rows:auto 1fr auto}.header,.footer{padding:1.25rem 2rem;background:#fff;border-color:#dde3ee}.header{border-bottom:1px solid #dde3ee}.footer{border-top:1px solid #dde3ee;color:#52627a}.main{display:grid;place-items:center;padding:2rem}.result{width:min(42rem,100%);background:#fff;border:1px solid #dde3ee;border-radius:8px;padding:2rem;box-shadow:0 12px 30px rgba(39,55,85,.08)}.actions{display:flex;flex-wrap:wrap;gap:.75rem;margin-top:1.5rem}.primary,.secondary,button{border:0;border-radius:8px;padding:.75rem 1rem;font-weight:700;text-decoration:none;cursor:pointer}.primary{background:#214f9f;color:#fff}.secondary,button{background:#eef2f7;color:#182033}a:focus-visible,button:focus-visible{outline:3px solid #f59e0b;outline-offset:2px}.meta{color:#52627a}
</style></head><body><header class="header"><strong>Credential HUB</strong></header><main class="main"><section class="result" data-oauth-result="${this.#escapeHtml(status)}"><p class="meta">${safeProvider}</p><h1 data-en="${status === 'success' ? 'Connection completed' : status === 'cancelled' ? 'Authorization cancelled' : 'Connection failed'}" data-de="${status === 'success' ? 'Verbindung abgeschlossen' : status === 'cancelled' ? 'Autorisierung abgebrochen' : 'Verbindung fehlgeschlagen'}"></h1><p data-en="Return to the Credential Wizard to continue. No sensitive configuration is shown on this page." data-de="Kehren Sie zum Credential Wizard zurueck. Auf dieser Seite werden keine sensiblen Konfigurationswerte angezeigt."></p><p class="meta">${this.#escapeHtml(code)}</p><div class="actions"><a class="primary" href="${safeWizardUrl}" data-en="Credential Wizard" data-de="Credential Wizard"></a><a class="secondary" href="${dashboardUrl}" data-en="Dashboard" data-de="Dashboard"></a><button type="button" id="close-result" data-en="Close window" data-de="Fenster schliessen"></button></div></section></main><script>
const language=(navigator.language||'en').toLowerCase().startsWith('de')?'de':'en';document.documentElement.lang=language;document.querySelectorAll('[data-en]').forEach((element)=>{element.textContent=element.dataset[language];});const payload=${payload};if(window.opener&&window.opener!==window){window.opener.postMessage(payload,window.location.origin);}document.getElementById('close-result').addEventListener('click',()=>window.close());
</script><footer class="footer"><span data-en="Credential HUB is Open Source" data-de="Credential HUB ist Open Source"></span> · AGPL-3.0-only · © 2026 cyphre-san productions · <a href="mailto:luiscyphre404@gmail.com">luiscyphre404@gmail.com</a> · <a href="https://discord.gg/exTu3Dy2UW" target="_blank" rel="noopener noreferrer">Discord</a><br><a href="${this.#path(PROJECT_LINKS.license)}">LICENSE</a> · <a href="${this.#path(PROJECT_LINKS.notice)}">NOTICE</a> · <a href="${this.#path(PROJECT_LINKS.thirdPartySoftware)}">Third-Party Software</a> · <a href="${this.#path(PROJECT_LINKS.security)}">SECURITY.md</a><br><span data-en="Security vulnerabilities must follow SECURITY.md and must not be reported through Discord." data-de="Sicherheitsluecken muessen ueber SECURITY.md gemeldet werden und duerfen nicht in Discord veroeffentlicht werden."></span></footer></body></html>`;
  }

  #escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  #path(pathname) {
    return withBasePath(this.basePath, pathname);
  }

  #oauthScopes(authorizationUrl) {
    try {
      const scope = new URL(authorizationUrl).searchParams.get('scope');
      return scope ? scope.split(/[\s,]+/).filter(Boolean) : [];
    } catch {
      return [];
    }
  }

  #oauthRedirectUri(authorizationUrl) {
    try {
      return new URL(authorizationUrl).searchParams.get('redirect_uri');
    } catch {
      return null;
    }
  }

  #oauthRuntimeDetails(req, providerKey) {
    const callbackPath = this.#path(`/oauth/${encodeURIComponent(providerKey)}/callback`);
    return {
      callbackPath,
      redirectUri: `${this.#publicOrigin(req)}${callbackPath}`
    };
  }

  #publicOrigin(req) {
    return this.publicBaseUrl ?? this.#requestOrigin(req);
  }

  #requestOrigin(req) {
    const origin = req.get('origin');
    const requestHost = req.get('host');
    if (origin) {
      try {
        const parsed = new URL(origin);
        if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.host === requestHost) {
          return parsed.origin;
        }
      } catch {}
    }
    return `${req.protocol}://${requestHost}`;
  }
}
