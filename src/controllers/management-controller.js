import { safeError } from '../utils/safe-diagnostics.js';

export class ManagementController {
  constructor({ managementService }) {
    if (!managementService?.getStatus) {
      throw new Error('ManagementController requires ManagementService.getStatus()');
    }

    this.managementService = managementService;
  }

  async status(req, res) {
    try {
      const data = await this.managementService.getStatus();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async providers(req, res) {
    try {
      this.#assertManagementService('getProviders');
      const data = await this.managementService.getProviders();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async scheduler(req, res) {
    try {
      this.#assertManagementService('getScheduler');
      const data = await this.managementService.getScheduler();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async credentials(req, res) {
    try {
      this.#assertManagementService('getCredentials');
      const data = await this.managementService.getCredentials();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }


  async startScheduler(req, res) {
    try {
      this.#assertManagementService('startScheduler');
      const data = await this.managementService.startScheduler({ actorUserId: this.#userIdFromRequest(req) });
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async stopScheduler(req, res) {
    try {
      this.#assertManagementService('stopScheduler');
      const data = await this.managementService.stopScheduler({ actorUserId: this.#userIdFromRequest(req) });
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async runSchedulerOnce(req, res) {
    try {
      this.#assertManagementService('runSchedulerOnce');
      const data = await this.managementService.runSchedulerOnce({ actorUserId: this.#userIdFromRequest(req) });
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async providerHealthCheck(req, res) {
    try {
      this.#assertManagementService('executeProviderHealthCheck');
      const data = await this.managementService.executeProviderHealthCheck(req.params.providerKey, { actorUserId: this.#userIdFromRequest(req) });
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  #userIdFromRequest(req) {
    return req.headers?.['x-credential-hub-user'] ?? null;
  }

  #assertManagementService(operation) {
    if (typeof this.managementService?.[operation] !== 'function') {
      throw new Error(`ManagementController requires ManagementService.${operation}()`);
    }
  }

  #sendSuccess(res, data) {
    res.status(200).json({
      success: true,
      meta: {
        apiVersion: 'v1'
      },
      data
    });
  }

  #sendError(res, error) {
    const safe = safeError(error);
    const statusCode = safe.statusCode ?? 500;
    const code = safe.code ?? (statusCode === 400 ? 'BAD_REQUEST' : 'INTERNAL_ERROR');

    res.status(statusCode).json({
      success: false,
      error: {
        code,
        message: safe.message
      }
    });
  }
}
