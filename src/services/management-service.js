import { safeError } from '../utils/safe-diagnostics.js';

export class ManagementService {
  constructor({ credentialManager, providerManager, customProviderService = null, schedulerService = null, accessManagementService = null, auditLogService = null } = {}) {
    this.credentialManager = credentialManager;
    this.providerManager = providerManager;
    this.customProviderService = customProviderService;
    this.schedulerService = schedulerService;
    this.accessManagementService = accessManagementService;
    this.auditLogService = auditLogService;
  }

  async getStatus() {
    const [credentials, providers, scheduler, access] = await Promise.all([
      this.getCredentials(),
      this.getProviders(),
      this.getScheduler(),
      this.getAccessManagement()
    ]);

    return {
      generatedAt: new Date().toISOString(),
      status: this.#overallStatus({ credentials, providers, scheduler }),
      credentials,
      providers,
      scheduler,
      access
    };
  }

  async getCredentials(options = {}) {
    this.#assertCredentialManager('listCredentialMetadata', 'listCredentials');

    const list = this.credentialManager.listCredentialMetadata ?? this.credentialManager.listCredentials;
    const credentials = await list.call(this.credentialManager, options);
    const items = credentials.map((credential) => this.#credentialItem(credential));

    return {
      total: items.length,
      byLifecycleState: this.#countBy(items, (item) => item.lifecycleState ?? 'unknown'),
      byProvider: this.#countBy(items, (item) => item.providerKey ?? 'unknown'),
      items
    };
  }

  async getProviders() {
    this.#assertProviderManager('listProviders');

    const providers = await this.providerManager.listProviders();
    const itemsByKey = new Map(providers.map((provider) => {
      const item = this.#providerItem(provider);
      return [item.providerKey, item];
    }));

    if (typeof this.customProviderService?.listManagement === 'function') {
      for (const lifecycleProvider of await this.customProviderService.listManagement()) {
        const current = itemsByKey.get(lifecycleProvider.providerKey) ?? {
          providerKey: lifecycleProvider.providerKey,
          key: lifecycleProvider.providerKey,
          displayName: lifecycleProvider.displayName,
          description: lifecycleProvider.description,
          capabilities: []
        };
        itemsByKey.set(lifecycleProvider.providerKey, {
          ...current,
          ...lifecycleProvider,
          capabilities: current.capabilities ?? []
        });
      }
    }

    const items = [...itemsByKey.values()];

    return {
      total: items.length,
      byCapability: this.#providerCapabilitySummary(items),
      items
    };
  }

  async getAccessManagement() {
    if (typeof this.accessManagementService?.getSummary !== 'function') {
      return { available: false, users: { total: 0, byRole: {}, byStatus: {} }, roles: { total: 0, items: [] } };
    }

    const summary = await this.accessManagementService.getSummary();

    return {
      available: true,
      ...summary
    };
  }

  async getScheduler() {
    if (typeof this.schedulerService?.getStatus === 'function') {
      const status = this.schedulerService.getStatus();
      const jobs = (status.jobs ?? []).map((job) => ({ ...job }));

      return {
        available: true,
        started: Boolean(status.started),
        running: Boolean(status.running),
        startedAt: status.startedAt ?? null,
        lastRunAt: status.lastRunAt ?? null,
        lastSuccessAt: status.lastSuccessAt ?? null,
        lastErrorAt: status.lastErrorAt ?? null,
        lastErrorMessage: status.lastErrorMessage ?? null,
        nextRunAt: status.nextRunAt ?? null,
        runCount: Number(status.runCount ?? 0),
        failureCount: Number(status.failureCount ?? 0),
        jobs,
        jobCount: Number(status.jobCount ?? jobs.length)
      };
    }

    const jobs = typeof this.schedulerService?.listJobs === 'function'
      ? this.schedulerService.listJobs().map((job) => ({ ...job }))
      : [];

    return {
      available: Boolean(this.schedulerService),
      started: Boolean(this.schedulerService?.timer),
      running: Boolean(this.schedulerService?.running),
      startedAt: null,
      lastRunAt: null,
      lastSuccessAt: null,
      lastErrorAt: null,
      lastErrorMessage: null,
      nextRunAt: null,
      runCount: 0,
      failureCount: 0,
      jobs,
      jobCount: jobs.length
    };
  }

  async runSchedulerOnce(options = {}) {
    this.#assertScheduler('runOnce');
    try {
      await this.schedulerService.runOnce();
      await this.#audit({
        action: 'scheduler.run_once',
        targetType: 'scheduler',
        targetId: 'refresh-expired-tokens',
        result: 'success',
        actorUserId: options.actorUserId
      });
      return this.getScheduler();
    } catch (error) {
      await this.#audit({
        action: 'scheduler.run_once',
        targetType: 'scheduler',
        targetId: 'refresh-expired-tokens',
        result: 'failure',
        actorUserId: options.actorUserId,
        details: { error: safeError(error) }
      });
      throw error;
    }
  }

  startScheduler(options = {}) {
    this.#assertScheduler('start');
    return this.#callSchedulerAction('start', {
      auditAction: 'scheduler.started',
      actorUserId: options.actorUserId
    });
  }

  stopScheduler(options = {}) {
    this.#assertScheduler('stop');
    return this.#callSchedulerAction('stop', {
      auditAction: 'scheduler.stopped',
      actorUserId: options.actorUserId
    });
  }

  async executeProviderHealthCheck(providerKey, options = {}) {
    const normalizedProviderKey = this.#normalizeRequiredString(providerKey, 'providerKey');
    this.#assertProviderManager('healthCheck');

    const result = await this.providerManager.healthCheck(normalizedProviderKey);
    const success = Boolean(result?.success);

    await this.#audit({
      action: 'provider.health_check',
      targetType: 'provider',
      targetId: normalizedProviderKey,
      result: success ? 'success' : 'failure',
      actorUserId: options.actorUserId,
      details: success ? null : { error: result?.error ?? null }
    });

    return this.#providerResultItem({ providerKey: normalizedProviderKey, action: 'health-check', result });
  }

  async executeCredentialBulkAction({ credentialIds = [], action } = {}) {
    this.#assertCredentialManager('executeBulkAction');
    return this.credentialManager.executeBulkAction({ credentialIds, action });
  }

  async executeCredentialLifecycleAction(credentialId, action) {
    this.#assertCredentialManager('executeLifecycleAction');
    return this.credentialManager.executeLifecycleAction(credentialId, action);
  }

  async #callSchedulerAction(action, { auditAction, actorUserId } = {}) {
    try {
      const result = this.schedulerService[action]();

      if (result && typeof result.then === 'function') {
        await result;
      }

      await this.#audit({
        action: auditAction,
        targetType: 'scheduler',
        targetId: 'refresh-expired-tokens',
        result: 'success',
        actorUserId
      });
      return this.getScheduler();
    } catch (error) {
      await this.#audit({
        action: auditAction,
        targetType: 'scheduler',
        targetId: 'refresh-expired-tokens',
        result: 'failure',
        actorUserId,
        details: { error: safeError(error) }
      });
      throw error;
    }
  }

  #providerResultItem({ providerKey, action, result }) {
    return {
      providerKey,
      action,
      success: Boolean(result?.success),
      data: result?.data ?? null,
      error: result?.error ?? null
    };
  }

  async #audit({ action, targetType, targetId, result, actorUserId = null, details = null }) {
    if (!this.auditLogService?.record) {
      return;
    }

    await this.auditLogService.record({
      userId: actorUserId ?? null,
      action,
      targetType,
      targetId,
      result,
      details
    });
  }

  #overallStatus({ credentials, providers, scheduler }) {
    if (!scheduler.available) return 'degraded';
    if (scheduler.failureCount > 0 && !scheduler.lastSuccessAt) return 'degraded';
    if (credentials.total === 0 && providers.total === 0) return 'empty';
    return 'ok';
  }

  #credentialItem(credential) {
    const value = this.#toJSON(credential);
    const metadata = value?.metadata ?? {};

    return {
      credentialId: value?.credentialId ?? null,
      providerKey: value?.providerKey ?? null,
      lifecycleState: value?.lifecycleState ?? null,
      displayName: metadata.displayName ?? null,
      description: metadata.description ?? null,
      expiresAt: metadata.expiresAt ?? value?.expiresAt ?? null,
      createdAt: value?.createdAt ?? null,
      updatedAt: value?.updatedAt ?? null,
      version: value?.version ?? null
    };
  }

  #providerItem(provider) {
    const key = provider?.key ?? provider?.providerKey ?? provider?.name ?? null;
    const capabilities = provider?.capabilities?.toArray?.() ?? provider?.capabilities ?? [];

    return {
      providerKey: key,
      key,
      displayName: provider?.displayName ?? key,
      description: provider?.description ?? null,
      capabilities: [...capabilities]
    };
  }

  #providerCapabilitySummary(providers) {
    const capabilities = new Set();

    for (const provider of providers) {
      for (const capability of provider.capabilities ?? []) {
        capabilities.add(capability);
      }
    }

    return [...capabilities].sort().reduce((counts, capability) => {
      counts[capability] = providers.filter((provider) =>
        (provider.capabilities ?? []).includes(capability)
      ).length;
      return counts;
    }, {});
  }

  #countBy(items, keyFn) {
    return items.reduce((counts, item) => {
      const key = keyFn(item);
      counts[key] = (counts[key] ?? 0) + 1;
      return counts;
    }, {});
  }

  #assertCredentialManager(...operations) {
    if (!operations.some((operation) => typeof this.credentialManager?.[operation] === 'function')) {
      throw new Error(`ManagementService requires CredentialManager.${operations[operations.length - 1]}()`);
    }
  }

  #assertProviderManager(operation) {
    if (typeof this.providerManager?.[operation] !== 'function') {
      throw new Error(`ManagementService requires ProviderManager.${operation}()`);
    }
  }

  #normalizeRequiredString(value, name) {
    if (typeof value !== 'string' || value.trim() === '') {
      const error = new Error(`${name} must be a non-empty string`);
      error.statusCode = 400;
      error.code = 'BAD_REQUEST';
      throw error;
    }

    return value.trim();
  }

  #assertScheduler(operation) {
    if (typeof this.schedulerService?.[operation] !== 'function') {
      throw new Error(`ManagementService requires SchedulerService.${operation}()`);
    }
  }

  #toJSON(value) {
    if (value && typeof value.toJSON === 'function') {
      return value.toJSON();
    }

    return value;
  }
}
