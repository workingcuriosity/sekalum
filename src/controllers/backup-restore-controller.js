import { safeError } from '../utils/safe-diagnostics.js';
import { authenticatedUserId } from '../utils/authenticated-user.js';

export class BackupRestoreController {
  constructor({ backupRestoreService }) {
    if (!backupRestoreService) {
      throw new Error('BackupRestoreController requires BackupRestoreService');
    }
    this.backupRestoreService = backupRestoreService;
  }

  async list(req, res) {
    try {
      const data = await this.backupRestoreService.listBackups();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async create(req, res) {
    try {
      const data = await this.backupRestoreService.createBackup({ actorUserId: this.#userIdFromRequest(req) });
      this.#sendSuccess(res, data, 201);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async get(req, res) {
    try {
      const data = await this.backupRestoreService.getBackup(req.params.backupId);
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async restore(req, res) {
    try {
      const data = await this.backupRestoreService.restoreBackup(req.params.backupId, { actorUserId: this.#userIdFromRequest(req) });
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  #userIdFromRequest(req) {
    return authenticatedUserId(req);
  }

  #sendSuccess(res, data, statusCode = 200) {
    res.status(statusCode).json({ success: true, meta: { apiVersion: 'v1' }, data });
  }

  #sendError(res, error) {
    const safe = safeError(error);
    const statusCode = safe.statusCode ?? 500;
    const code = safe.code ?? (statusCode === 400 ? 'BAD_REQUEST' : 'INTERNAL_ERROR');
    res.status(statusCode).json({ success: false, error: { code, message: safe.message } });
  }
}
