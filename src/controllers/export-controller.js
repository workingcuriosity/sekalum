import { safeError } from '../utils/safe-diagnostics.js';

export class ExportController {
  constructor({ exportService }) {
    if (!exportService?.export || !exportService?.listResources) {
      throw new Error('ExportController requires ExportService');
    }

    this.exportService = exportService;
  }

  async resources(req, res) {
    try {
      const data = await this.exportService.listResources();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async export(req, res) {
    try {
      const result = await this.exportService.export(req.params.resource, {
        format: req.query?.format ?? 'json',
        filters: req.query ?? {}
      });

      res.setHeader('content-type', result.contentType);
      res.setHeader('content-disposition', `attachment; filename="${result.filename}"`);
      res.status(200).send(result.content);
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
