import { safeError } from '../utils/safe-diagnostics.js';

export class MetricsController {
  constructor({ metricsService }) {
    if (!metricsService?.getMetrics) {
      throw new Error('MetricsController requires MetricsService.getMetrics()');
    }

    this.metricsService = metricsService;
  }

  async get(req, res) {
    try {
      const data = await this.metricsService.getMetrics();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  #sendSuccess(res, data) {
    res.status(200).json({
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
