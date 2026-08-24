import { safeError } from '../utils/safe-diagnostics.js';

export class ConsumerGrantController {
  constructor({ consumerGrantService }) {
    if (!consumerGrantService?.createGrant || !consumerGrantService?.listGrants || !consumerGrantService?.updateGrant) {
      throw new Error('ConsumerGrantController requires ConsumerGrantService');
    }
    this.consumerGrantService = consumerGrantService;
  }

  async create(req, res) {
    try {
      const grant = await this.consumerGrantService.createGrant(req.body ?? {}, { actorUserId: req.auth.userId });
      res.status(201).json({ success: true, meta: { apiVersion: 'v1' }, data: grant.toJSON() });
    } catch (error) {
      const safe = safeError(error, { fallbackMessage: 'Invalid consumer grant' });
      res.status(safe.statusCode ?? 400).json({
        success: false,
        error: { code: safe.code ?? 'BAD_REQUEST', message: safe.message }
      });
    }
  }

  async list(req, res) {
    try {
      const grants = await this.consumerGrantService.listGrants({
        consumerId: req.query?.consumerId,
        credentialId: req.query?.credentialId,
        providerKey: req.query?.providerKey
      });
      res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data: grants.map((grant) => grant.toJSON()) });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async update(req, res) {
    try {
      const grant = await this.consumerGrantService.updateGrant(req.params.grantId, req.body ?? {}, { actorUserId: req.auth.userId });
      res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data: grant.toJSON() });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  #sendError(res, error) {
    const safe = safeError(error, { fallbackMessage: 'Invalid consumer grant' });
    res.status(safe.statusCode ?? 400).json({
      success: false,
      error: { code: safe.code ?? 'BAD_REQUEST', message: safe.message }
    });
  }
}
