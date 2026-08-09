import path from 'path';

import { ServiceProvider } from './service-provider.js';
import { TOKENS } from './tokens.js';
import { HttpClient } from '../api/http-client.js';
import { RefreshExpiredTokensCommand } from '../commands/refresh-expired-tokens-command.js';

import { Config } from '../config/config.js';
import { Logger } from '../logging/logger.js';
import { ProviderRegistry } from '../registry/provider-registry.js';
import { OAuthManager } from '../managers/oauth-manager.js';
import { OAuthSecurityService } from '../oauth/oauth-security-service.js';
import { ProviderManager } from '../managers/provider-manager.js';
import { CredentialManager } from '../managers/credential-manager.js';
import { SchedulerService } from '../scheduler/scheduler-service.js';
import { Application } from '../app/application.js';

import { JsonStore } from '../storage/json-store.js';
import { EncryptedJsonStore } from '../storage/encrypted-json-store.js';
import { TokenStore } from '../storage/token-store.js';
import { CredentialStore } from '../storage/credential-store.js';
import { CredentialCollectionStoreAdapter } from '../storage/credential-collection-store-adapter.js';
import { CompositeCredentialStoreAdapter } from '../storage/composite-credential-store-adapter.js';
import { BackupStore } from '../storage/backup-store.js';
import { AccessManagementStore } from '../storage/access-management-store.js';
import { ApiTokenStore } from '../storage/api-token-store.js';
import { AuditLogStore } from '../storage/audit-log-store.js';
import { ManagementBackupStore } from '../storage/management-backup-store.js';
import { CredentialPolicyStore } from '../storage/credential-policy-store.js';
import { CredentialSecretVersionStore } from '../storage/credential-secret-version-store.js';
import { LifecycleNotificationStore } from '../storage/lifecycle-notification-store.js';
import { ProviderConfigurationStore } from '../storage/provider-configuration-store.js';
import { CustomProviderDefinitionStore } from '../storage/custom-provider-definition-store.js';
import { ConsumerGrantStore } from '../storage/consumer-grant-store.js';

import { TokenLifecycleService } from '../services/token-lifecycle-service.js';
import { DashboardService } from '../services/dashboard-service.js';
import { ManagementService } from '../services/management-service.js';
import { AccessManagementService } from '../services/access-management-service.js';
import { ApiTokenService } from '../services/api-token-service.js';
import { AuditLogService } from '../services/audit-log-service.js';
import { ExportService } from '../services/export-service.js';
import { BackupRestoreService } from '../services/backup-restore-service.js';
import { MetricsService } from '../services/metrics-service.js';
import { CredentialPolicyService } from '../services/credential-policy-service.js';
import { CredentialRotationService } from '../services/credential-rotation-service.js';
import { CredentialSecretVersionService } from '../services/credential-secret-version-service.js';
import { CredentialHistoryService } from '../services/credential-history-service.js';
import { LifecycleNotificationService } from '../services/lifecycle-notification-service.js';
import { ProviderRotationFramework } from '../services/provider-rotation-framework.js';
import { ProviderConfigurationService } from '../services/provider-configuration-service.js';
import { RuntimePublicProjectionService } from '../services/runtime-public-projection-service.js';
import { CustomProviderService } from '../services/custom-provider-service.js';
import { ConsumerGrantService } from '../services/consumer-grant-service.js';
import { ConsumerCredentialService } from '../services/consumer-credential-service.js';
import { ImportTokenCommand } from '../commands/import-token-command.js';
import { OAuthCallbackServer } from '../oauth/oauth-callback-server.js';

import { StartOAuthCommand } from '../commands/start-oauth-command.js';

export class ApplicationServiceProvider extends ServiceProvider {
  register(container) {
    const storagePath = path.resolve(process.cwd(), 'storage');

    container.singleton(TOKENS.CONTAINER, () => container);

    container.singleton(TOKENS.LOGGER, () => new Logger());

    container.singleton(TOKENS.CONFIG, () => {
      return new Config(process.env);
    });

    container.singleton(TOKENS.PROVIDER_REGISTRY, (c) => {
      return new ProviderRegistry({
        logger: c.resolve(TOKENS.LOGGER)
      });
    });

    container.singleton(TOKENS.OAUTH_SECURITY_SERVICE, () => {
      return new OAuthSecurityService();
    });

    container.singleton(TOKENS.OAUTH_MANAGER, (c) => {
      return new OAuthManager({
        providerRegistry: c.resolve(TOKENS.PROVIDER_REGISTRY),
        oauthSecurityService: c.resolve(TOKENS.OAUTH_SECURITY_SERVICE),
        logger: c.resolve(TOKENS.LOGGER)
      });
    });

    container.singleton(TOKENS.PROVIDER_MANAGER, (c) => {
      return new ProviderManager({
        providerRegistry: c.resolve(TOKENS.PROVIDER_REGISTRY),
        oauthSecurityService: c.resolve(TOKENS.OAUTH_SECURITY_SERVICE),
        providerConfigurationService: c.resolve(TOKENS.PROVIDER_CONFIGURATION_SERVICE),
        logger: c.resolve(TOKENS.LOGGER)
      });
    });

    container.singleton(TOKENS.SCHEDULER, (c) => {
  return new SchedulerService({
    logger: c.resolve(TOKENS.LOGGER),
    config: c.resolve(TOKENS.CONFIG),
    refreshExpiredTokensCommand: c.resolve(
      TOKENS.REFRESH_EXPIRED_TOKENS_COMMAND
    ),
    credentialRotationService: c.resolve(TOKENS.CREDENTIAL_ROTATION_SERVICE)
  });
});

    container.singleton(TOKENS.HTTP_CLIENT, () => {
      return new HttpClient();
    });

    container.singleton(TOKENS.JSON_STORE, () => {
      return new JsonStore();
    });

    container.singleton(TOKENS.SECURE_JSON_STORE, (c) => {
      return new EncryptedJsonStore({
        jsonStore: c.resolve(TOKENS.JSON_STORE),
        config: c.resolve(TOKENS.CONFIG)
      });
    });

    container.singleton(TOKENS.TOKEN_STORE, (c) => {
      return new TokenStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath,
        logger: c.resolve(TOKENS.LOGGER)
      });
    });

    container.singleton(TOKENS.CREDENTIAL_STORE, (c) => {
      return new CredentialStore({
        storageAdapter: new CompositeCredentialStoreAdapter({
          primary: new CredentialCollectionStoreAdapter({
            jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
            basePath: storagePath
          })
        })
      });
    });

    container.singleton(TOKENS.BACKUP_STORE, (c) => {
      return new BackupStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.ACCESS_MANAGEMENT_STORE, (c) => {
      return new AccessManagementStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.API_TOKEN_STORE, (c) => {
      return new ApiTokenStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.AUDIT_LOG_STORE, (c) => {
      return new AuditLogStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.MANAGEMENT_BACKUP_STORE, (c) => {
      return new ManagementBackupStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.CREDENTIAL_POLICY_STORE, (c) => {
      return new CredentialPolicyStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.CREDENTIAL_SECRET_VERSION_STORE, (c) => {
      return new CredentialSecretVersionStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.LIFECYCLE_NOTIFICATION_STORE, (c) => {
      return new LifecycleNotificationStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.PROVIDER_CONFIGURATION_STORE, (c) => {
      return new ProviderConfigurationStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.CUSTOM_PROVIDER_DEFINITION_STORE, (c) => {
      return new CustomProviderDefinitionStore({
        jsonStore: c.resolve(TOKENS.JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.CONSUMER_GRANT_STORE, (c) => {
      return new ConsumerGrantStore({
        jsonStore: c.resolve(TOKENS.SECURE_JSON_STORE),
        basePath: storagePath
      });
    });

    container.singleton(TOKENS.PROVIDER_CONFIGURATION_SERVICE, (c) => {
      return new ProviderConfigurationService({
        store: c.resolve(TOKENS.PROVIDER_CONFIGURATION_STORE)
      });
    });

    container.singleton(TOKENS.RUNTIME_PUBLIC_PROJECTION_SERVICE, (c) => {
      return new RuntimePublicProjectionService({
        providerConfigurationService: c.resolve(TOKENS.PROVIDER_CONFIGURATION_SERVICE),
        providerRegistry: c.resolve(TOKENS.PROVIDER_REGISTRY)
      });
    });

    container.singleton(TOKENS.CUSTOM_PROVIDER_SERVICE, (c) => {
      return new CustomProviderService({
        store: c.resolve(TOKENS.CUSTOM_PROVIDER_DEFINITION_STORE),
        providerRegistry: c.resolve(TOKENS.PROVIDER_REGISTRY)
      });
    });

    container.singleton(TOKENS.TOKEN_LIFECYCLE_SERVICE, (c) => {
      return new TokenLifecycleService({
        tokenStore: c.resolve(TOKENS.TOKEN_STORE),
        backupStore: c.resolve(TOKENS.BACKUP_STORE),
        logger: c.resolve(TOKENS.LOGGER)
      });
    });

    container.singleton(TOKENS.CREDENTIAL_MANAGER, (c) => {
      return new CredentialManager({
        credentialStore: c.resolve(TOKENS.CREDENTIAL_STORE),
        providerManager: c.resolve(TOKENS.PROVIDER_MANAGER),
        tokenLifecycleService: c.resolve(TOKENS.TOKEN_LIFECYCLE_SERVICE),
        config: c.resolve(TOKENS.CONFIG),
        logger: c.resolve(TOKENS.LOGGER),
        secretVersioningService: c.resolve(TOKENS.CREDENTIAL_SECRET_VERSION_SERVICE),
        credentialHistoryService: c.resolve(TOKENS.CREDENTIAL_HISTORY_SERVICE)
      });
    });

    container.singleton(TOKENS.CREDENTIAL_SECRET_VERSION_SERVICE, (c) => {
      return new CredentialSecretVersionService({
        store: c.resolve(TOKENS.CREDENTIAL_SECRET_VERSION_STORE),
        credentialManagerRef: () => c.resolve(TOKENS.CREDENTIAL_MANAGER),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE)
      });
    });

    container.singleton(TOKENS.CREDENTIAL_HISTORY_SERVICE, (c) => {
      return new CredentialHistoryService({
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE),
        secretVersioningService: c.resolve(TOKENS.CREDENTIAL_SECRET_VERSION_SERVICE)
      });
    });

    container.singleton(TOKENS.LIFECYCLE_NOTIFICATION_SERVICE, (c) => {
      return new LifecycleNotificationService({
        store: c.resolve(TOKENS.LIFECYCLE_NOTIFICATION_STORE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE)
      });
    });

    container.singleton(TOKENS.DASHBOARD_SERVICE, (c) => {
      return new DashboardService({
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER),
        providerManager: c.resolve(TOKENS.PROVIDER_MANAGER),
        consumerGrantService: c.resolve(TOKENS.CONSUMER_GRANT_SERVICE),
        schedulerService: c.resolve(TOKENS.SCHEDULER),
        credentialPolicyService: c.resolve(TOKENS.CREDENTIAL_POLICY_SERVICE),
        credentialRotationService: c.resolve(TOKENS.CREDENTIAL_ROTATION_SERVICE),
        credentialHistoryService: c.resolve(TOKENS.CREDENTIAL_HISTORY_SERVICE),
        lifecycleNotificationService: c.resolve(TOKENS.LIFECYCLE_NOTIFICATION_SERVICE)
      });
    });

    container.singleton(TOKENS.AUDIT_LOG_SERVICE, (c) => {
      return new AuditLogService({
        store: c.resolve(TOKENS.AUDIT_LOG_STORE)
      });
    });

    container.singleton(TOKENS.ACCESS_MANAGEMENT_SERVICE, (c) => {
      return new AccessManagementService({
        store: c.resolve(TOKENS.ACCESS_MANAGEMENT_STORE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE)
      });
    });

    container.singleton(TOKENS.API_TOKEN_SERVICE, (c) => {
      return new ApiTokenService({
        store: c.resolve(TOKENS.API_TOKEN_STORE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE)
      });
    });

    container.singleton(TOKENS.CONSUMER_GRANT_SERVICE, (c) => {
      return new ConsumerGrantService({
        store: c.resolve(TOKENS.CONSUMER_GRANT_STORE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE),
        apiTokenService: c.resolve(TOKENS.API_TOKEN_SERVICE),
        credentialStore: c.resolve(TOKENS.CREDENTIAL_STORE),
        providerRegistry: c.resolve(TOKENS.PROVIDER_REGISTRY)
      });
    });

    container.singleton(TOKENS.CONSUMER_CREDENTIAL_SERVICE, (c) => {
      return new ConsumerCredentialService({
        credentialStore: c.resolve(TOKENS.CREDENTIAL_STORE),
        consumerGrantService: c.resolve(TOKENS.CONSUMER_GRANT_SERVICE),
        providerRegistry: c.resolve(TOKENS.PROVIDER_REGISTRY),
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER),
        runtimePublicProjectionService: c.resolve(TOKENS.RUNTIME_PUBLIC_PROJECTION_SERVICE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE)
      });
    });

    container.singleton(TOKENS.CREDENTIAL_POLICY_SERVICE, (c) => {
      return new CredentialPolicyService({
        store: c.resolve(TOKENS.CREDENTIAL_POLICY_STORE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE)
      });
    });

    container.singleton(TOKENS.CREDENTIAL_ROTATION_SERVICE, (c) => {
      return new CredentialRotationService({
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER),
        credentialPolicyService: c.resolve(TOKENS.CREDENTIAL_POLICY_SERVICE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE),
        lifecycleNotificationService: c.resolve(TOKENS.LIFECYCLE_NOTIFICATION_SERVICE),
        providerRotationFramework: c.resolve(TOKENS.PROVIDER_ROTATION_FRAMEWORK)
      });
    });

    container.singleton(TOKENS.PROVIDER_ROTATION_FRAMEWORK, (c) => {
      return new ProviderRotationFramework({
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER),
        providerManager: c.resolve(TOKENS.PROVIDER_MANAGER),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE),
        lifecycleNotificationService: c.resolve(TOKENS.LIFECYCLE_NOTIFICATION_SERVICE)
      });
    });

    container.singleton(TOKENS.MANAGEMENT_SERVICE, (c) => {
      return new ManagementService({
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER),
        providerManager: c.resolve(TOKENS.PROVIDER_MANAGER),
        schedulerService: c.resolve(TOKENS.SCHEDULER),
        accessManagementService: c.resolve(TOKENS.ACCESS_MANAGEMENT_SERVICE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE)
      });
    });

    container.singleton(TOKENS.EXPORT_SERVICE, (c) => {
      return new ExportService({
        managementService: c.resolve(TOKENS.MANAGEMENT_SERVICE),
        accessManagementService: c.resolve(TOKENS.ACCESS_MANAGEMENT_SERVICE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE)
      });
    });

    container.singleton(TOKENS.BACKUP_RESTORE_SERVICE, (c) => {
      return new BackupRestoreService({
        accessManagementService: c.resolve(TOKENS.ACCESS_MANAGEMENT_SERVICE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE),
        managementService: c.resolve(TOKENS.MANAGEMENT_SERVICE),
        store: c.resolve(TOKENS.MANAGEMENT_BACKUP_STORE)
      });
    });

    container.singleton(TOKENS.METRICS_SERVICE, (c) => {
      return new MetricsService({
        managementService: c.resolve(TOKENS.MANAGEMENT_SERVICE),
        accessManagementService: c.resolve(TOKENS.ACCESS_MANAGEMENT_SERVICE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE),
        exportService: c.resolve(TOKENS.EXPORT_SERVICE),
        backupRestoreService: c.resolve(TOKENS.BACKUP_RESTORE_SERVICE)
      });
    });

    container.singleton(TOKENS.IMPORT_TOKEN_COMMAND, (c) => {
      return new ImportTokenCommand({
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER)
      });
    });

    container.singleton(TOKENS.START_OAUTH_COMMAND, (c) => {
  return new StartOAuthCommand({
    providerManager: c.resolve(TOKENS.PROVIDER_MANAGER)
  });
});


    container.singleton(TOKENS.REFRESH_EXPIRED_TOKENS_COMMAND, (c) => {
      return new RefreshExpiredTokensCommand({
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER)
      });
    });

    container.singleton(TOKENS.OAUTH_CALLBACK_SERVER, (c) => {
      return new OAuthCallbackServer({
        providerManager: c.resolve(TOKENS.PROVIDER_MANAGER),
        importTokenCommand: c.resolve(TOKENS.IMPORT_TOKEN_COMMAND),
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER),
        schedulerService: c.resolve(TOKENS.SCHEDULER),
        dashboardService: c.resolve(TOKENS.DASHBOARD_SERVICE),
        managementService: c.resolve(TOKENS.MANAGEMENT_SERVICE),
        accessManagementService: c.resolve(TOKENS.ACCESS_MANAGEMENT_SERVICE),
        auditLogService: c.resolve(TOKENS.AUDIT_LOG_SERVICE),
        exportService: c.resolve(TOKENS.EXPORT_SERVICE),
        backupRestoreService: c.resolve(TOKENS.BACKUP_RESTORE_SERVICE),
        metricsService: c.resolve(TOKENS.METRICS_SERVICE),
        apiTokenService: c.resolve(TOKENS.API_TOKEN_SERVICE),
        consumerCredentialService: c.resolve(TOKENS.CONSUMER_CREDENTIAL_SERVICE),
        customProviderService: c.resolve(TOKENS.CUSTOM_PROVIDER_SERVICE),
        config: c.resolve(TOKENS.CONFIG),
        logger: c.resolve(TOKENS.LOGGER)
      });
    });

    container.singleton(TOKENS.APPLICATION, (c) => {
      return new Application({
        config: c.resolve(TOKENS.CONFIG),
        logger: c.resolve(TOKENS.LOGGER),
        container: c.resolve(TOKENS.CONTAINER),
        providerRegistry: c.resolve(TOKENS.PROVIDER_REGISTRY),
        oauthManager: c.resolve(TOKENS.OAUTH_MANAGER),
        providerManager: c.resolve(TOKENS.PROVIDER_MANAGER),
        credentialManager: c.resolve(TOKENS.CREDENTIAL_MANAGER),
        schedulerService: c.resolve(TOKENS.SCHEDULER),
        oauthCallbackServer: c.resolve(TOKENS.OAUTH_CALLBACK_SERVER),
        refreshExpiredTokensCommand: c.resolve(TOKENS.REFRESH_EXPIRED_TOKENS_COMMAND)
      });
    });
  }
}
