import { safeError } from '../utils/safe-diagnostics.js';

export class AuditLogController {
  constructor({ auditLogService }) {
    if (!auditLogService?.list || !auditLogService?.get) {
      throw new Error('AuditLogController requires AuditLogService');
    }

    this.auditLogService = auditLogService;
  }

  async list(req, res) {
    try {
      const data = await this.auditLogService.list(req.query ?? {});
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async get(req, res) {
    try {
      const data = await this.auditLogService.get(req.params.entryId);
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
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
    const code = safe.code ?? (statusCode === 404 ? 'NOT_FOUND' : statusCode === 400 ? 'BAD_REQUEST' : 'INTERNAL_ERROR');

    res.status(statusCode).json({
      success: false,
      error: {
        code,
        message: safe.message
      }
    });
  }
}
