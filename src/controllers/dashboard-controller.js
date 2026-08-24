import { safeError } from '../utils/safe-diagnostics.js';

export class DashboardController {
  constructor({ dashboardService }) {
    if (!dashboardService?.getDashboard) {
      throw new Error('DashboardController requires DashboardService.getDashboard()');
    }

    this.dashboardService = dashboardService;
  }

  async get(req, res) {
    try {
      const data = await this.dashboardService.getDashboard({
        expiringWithinDays: req.query.expiringWithinDays
      });

      res.status(200).json({
  success: true,
  meta: {
    apiVersion: 'v1'
  },
  data
});
    } catch (error) {
      this.#sendError(res, error);
    }
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
