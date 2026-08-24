import { safeErrorMessage } from '../utils/safe-diagnostics.js';

export class SchedulerService {
  constructor({ logger, config, refreshExpiredTokensCommand, credentialRotationService = null }) {
    this.logger = logger;
    this.config = config;
    this.refreshExpiredTokensCommand = refreshExpiredTokensCommand;
    this.credentialRotationService = credentialRotationService;

    this.timer = null;
    this.running = false;

    this.startedAt = null;
    this.lastRunAt = null;
    this.lastSuccessAt = null;
    this.lastErrorAt = null;
    this.lastErrorMessage = null;
    this.nextRunAt = null;
    this.runCount = 0;
    this.failureCount = 0;

    this.jobs = [
      {
        name: 'refresh-expired-tokens',
        intervalHours: Number(this.config.get('CHECK_INTERVAL_HOURS', 12))
      },
      {
        name: 'rotate-due-credentials',
        intervalHours: Number(this.config.get('CHECK_INTERVAL_HOURS', 12))
      }
    ];
  }

  listJobs() {
    return this.jobs;
  }

  getStatus() {
    return {
      started: Boolean(this.timer),
      running: this.running,
      startedAt: this.startedAt,
      lastRunAt: this.lastRunAt,
      lastSuccessAt: this.lastSuccessAt,
      lastErrorAt: this.lastErrorAt,
      lastErrorMessage: this.lastErrorMessage,
      nextRunAt: this.nextRunAt,
      runCount: this.runCount,
      failureCount: this.failureCount,
      jobs: this.listJobs().map((job) => ({ ...job })),
      jobCount: this.jobs.length
    };
  }

  async start() {
    if (this.timer) return;

    const intervalMs = this.jobs[0].intervalHours * 60 * 60 * 1000;
    this.startedAt = new Date().toISOString();

    this.logger.info(`Scheduler started (${this.jobs[0].intervalHours} hour interval)`);

    await this.runOnce();

    this.nextRunAt = new Date(Date.now() + intervalMs).toISOString();

    this.timer = setInterval(async () => {
      await this.runOnce();
    }, intervalMs);
  }

  stop() {
    if (!this.timer) return;

    clearInterval(this.timer);
    this.timer = null;
    this.nextRunAt = null;

    this.logger.info('Scheduler stopped');
  }

  async runOnce() {
    if (this.running) {
      this.logger.warn('Skipping scheduled refresh because previous run is still active.');
      return;
    }

    this.running = true;
    this.lastRunAt = new Date().toISOString();

    try {
      this.logger.info('Running scheduled refresh...');

      await this.refreshExpiredTokensCommand.execute();

      if (this.credentialRotationService?.rotateDueCredentials) {
        await this.credentialRotationService.rotateDueCredentials();
      }

      this.runCount += 1;
      this.lastSuccessAt = new Date().toISOString();
      this.lastErrorMessage = null;

      this.logger.info('Scheduled refresh completed.');
    } catch (error) {
      this.runCount += 1;
      this.failureCount += 1;
      this.lastErrorAt = new Date().toISOString();
      this.lastErrorMessage = safeErrorMessage(error, 'Scheduled refresh failed');

      this.logger.error(`Scheduled refresh failed: ${this.lastErrorMessage}`);
    } finally {
      this.running = false;

      if (this.timer) {
        const intervalMs = this.jobs[0].intervalHours * 60 * 60 * 1000;
        this.nextRunAt = new Date(Date.now() + intervalMs).toISOString();
      }
    }
  }
}
