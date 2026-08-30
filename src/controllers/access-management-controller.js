import { safeError } from '../utils/safe-diagnostics.js';
import { authenticatedUserId } from '../utils/authenticated-user.js';

export class AccessManagementController {
  constructor({ accessManagementService }) {
    if (!accessManagementService?.listUsers) {
      throw new Error('AccessManagementController requires AccessManagementService');
    }

    this.accessManagementService = accessManagementService;
  }

  async requirePermission(req, res, permission, handler) {
    try {
      const required = await this.accessManagementService.isAuthorizationRequired?.();

      if (required === false) {
        await handler();
        return;
      }

      await this.accessManagementService.authorize(this.#userIdFromRequest(req), permission);
      await handler();
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async users(req, res) {
    try {
      const data = await this.accessManagementService.listUsers();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async createUser(req, res) {
    try {
      const data = await this.accessManagementService.createUser({ ...(req.body ?? {}), actorUserId: this.#userIdFromRequest(req) });
      this.#sendSuccess(res, data, 201);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async bootstrapFirstAdministrator(req, res) {
    try {
      const data = await this.accessManagementService.bootstrapFirstAdministrator(
        req.body ?? {},
        req.get('x-admin-bootstrap-token')
      );
      this.#sendSuccess(res, data, 201);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async updateUser(req, res) {
    try {
      const data = await this.accessManagementService.updateUser(req.params.userId, { ...(req.body ?? {}), actorUserId: this.#userIdFromRequest(req) });
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async deleteUser(req, res) {
    try {
      await this.accessManagementService.deleteUser(req.params.userId, { actorUserId: this.#userIdFromRequest(req) });
      res.status(204).send();
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async roles(req, res) {
    try {
      const data = await this.accessManagementService.listRoles();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  #userIdFromRequest(req) {
    return authenticatedUserId(req);
  }

  #sendSuccess(res, data, statusCode = 200) {
    res.status(statusCode).json({
      success: true,
      meta: { apiVersion: 'v1' },
      data
    });
  }

  #sendError(res, error) {
    const safe = safeError(error);
    const statusCode = safe.statusCode ?? 500;
    const code = safe.code ?? (statusCode === 404 ? 'NOT_FOUND' : statusCode === 403 ? 'FORBIDDEN' : statusCode === 401 ? 'UNAUTHORIZED' : statusCode === 400 ? 'BAD_REQUEST' : 'INTERNAL_ERROR');

    res.status(statusCode).json({
      success: false,
      error: {
        code,
        message: safe.message
      }
    });
  }
}
