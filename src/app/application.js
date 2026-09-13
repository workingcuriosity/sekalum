export class Application {
  constructor({
    config,
    logger,
    container,
    providerRegistry,
    oauthManager,
    providerManager,
    providerConfigurationService,
    credentialManager,
    secureJsonStore,
    storagePath,
    schedulerService,
    refreshExpiredTokensCommand,
    oauthCallbackServer
  }) {
    if (!secureJsonStore || typeof secureJsonStore.migrateBeforeServing !== 'function' || typeof storagePath !== 'string' || storagePath.trim() === '') {
      throw new Error('Application requires secureJsonStore and storagePath for secure startup');
    }
    this.config = config;
    this.logger = logger;
    this.container = container;
    this.providerRegistry = providerRegistry;
    this.oauthManager = oauthManager;
    this.providerManager = providerManager;
    this.providerConfigurationService = providerConfigurationService;
    this.credentialManager = credentialManager;
    this.secureJsonStore = secureJsonStore;
    this.storagePath = storagePath;
    this.schedulerService = schedulerService;
    this.refreshExpiredTokensCommand = refreshExpiredTokensCommand;
    this.oauthCallbackServer = oauthCallbackServer;
  }

  async start() {
    await this.secureJsonStore.migrateBeforeServing({
      rootPath: this.storagePath,
      rootFiles: [
        'credentials.json',
        'credential-metadata.json',
        'access-management.json',
        'access-management-tombstones.json',
        'api-tokens.json',
        'audit-log.json',
        'consumer-grants.json',
        'credential-policies.json',
        'credential-secret-versions.json',
        'lifecycle-notifications.json',
        'provider-configurations.json'
      ],
      recursiveDirectories: ['tokens', 'backups', 'management-backups']
    });
    await this.providerManager.cleanupExpiredOAuthContexts?.();
    await this.#cleanupExpiredTemporaryProviderConfigurations();
    const migratedCredentialIds = await this.credentialManager.migrateLegacyCredentialMethods();
    if (migratedCredentialIds.length > 0) {
      this.logger.info(`Migrated credential methods: ${migratedCredentialIds.length}`);
    }
    await this.oauthCallbackServer.start();

    await this.schedulerService.start();

    this.logger.success('Application started');
    this.logger.info(`Registered providers: ${this.providerRegistry.count()}`);
    this.logger.info(
      `Registered scheduler jobs: ${this.schedulerService.listJobs().length}`
    );
  }

  async #cleanupExpiredTemporaryProviderConfigurations() {
    if (!this.providerConfigurationService?.removeExpiredTemporaryFlowConfigurations) return;
    const credentials = await this.credentialManager.listCredentials();
    const referenced = credentials.flatMap((credential) => {
      const value = typeof credential?.toJSON === 'function' ? credential.toJSON() : credential;
      return [
        value?.providerConfigurationId,
        value?.metadata?.providerConfigurationId,
        value?.metadata?.custom?.providerConfigurationId
      ];
    });
    const result = await this.providerConfigurationService.removeExpiredTemporaryFlowConfigurations(referenced);
    if (result.failed.length > 0) {
      this.logger.warn?.(`Provider configuration cleanup failed for ${result.failed.length} record(s)`);
    }
    if (result.removed.length > 0) {
      this.logger.info?.(`Removed ${result.removed.length} unreferenced provider configuration(s)`);
    }
  }

  async stop() {
    this.schedulerService.stop();
    await this.oauthCallbackServer.stop();
    this.logger.info('Application stopped');
  }

  async runRefresh() {
    return this.refreshExpiredTokensCommand.execute();
  }
}
