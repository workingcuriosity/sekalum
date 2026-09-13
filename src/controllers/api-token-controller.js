import { safeError } from '../utils/safe-diagnostics.js';
import { authenticatedUserId } from '../utils/authenticated-user.js';

export class ApiTokenController {
  constructor({ apiTokenService }) {
    if (!apiTokenService?.createToken || !apiTokenService?.listTokens) {
      throw new Error('ApiTokenController requires ApiTokenService');
    }

    this.apiTokenService = apiTokenService;
  }

  async list(req, res) {
    try {
      const data = await this.apiTokenService.listTokens();
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async get(req, res) {
    try {
      const data = await this.apiTokenService.getToken(req.params.tokenId);
      this.#sendSuccess(res, data);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async create(req, res) {
    try {
      const created = await this.apiTokenService.createToken({
        ...(req.body ?? {}),
        createdBy: this.#userIdFromRequest(req),
        issuer: req.auth ?? null
      });

      this.#sendSuccess(res, {
        token: created.token,
        apiToken: created.publicToken
      }, 201);
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async revoke(req, res) {
    try {
      const data = await this.apiTokenService.revokeToken(req.params.tokenId, {
        revokedBy: this.#userIdFromRequest(req)
      });
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
