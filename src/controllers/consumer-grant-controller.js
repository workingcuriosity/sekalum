import { safeError } from '../utils/safe-diagnostics.js';

export class ConsumerGrantController {
  constructor({ consumerGrantService, consumerCredentialService = null }) {
    if (!consumerGrantService?.createGrant || !consumerGrantService?.listGrants || !consumerGrantService?.updateGrant) {
      throw new Error('ConsumerGrantController requires ConsumerGrantService');
    }
    this.consumerGrantService = consumerGrantService;
    this.consumerCredentialService = consumerCredentialService;
  }

  async create(req, res) {
    try {
      const grant = await this.consumerGrantService.createGrant(req.body ?? {}, { actorUserId: req.auth.userId });
      res.status(201).json({ success: true, meta: { apiVersion: 'v1' }, data: grant.toJSON() });
    } catch (error) {
      const safe = safeError(error, { fallbackMessage: 'Invalid consumer grant' });
      res.status(safe.statusCode ?? 400).json({
        success: false,
        error: this.#errorPayload(safe)
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

  async delete(req, res) {
    try {
      await this.consumerGrantService.deleteGrant(req.params.grantId, { actorUserId: req.auth.userId });
      res.status(204).send();
    } catch (error) { this.#sendError(res, error); }
  }

  async accessScope(req, res) {
    try {
      if (!this.consumerCredentialService?.getAccessScope) throw new Error('Consumer access scope is not configured');
      const data = await this.consumerCredentialService.getAccessScope({ consumerId: req.query?.consumerId });
      res.set('Cache-Control', 'no-store');
      res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data });
    } catch (error) { this.#sendError(res, error); }
  }

  async preview(req, res) {
    try {
      if (!this.consumerCredentialService?.previewGrant) throw new Error('Consumer access scope is not configured');
      const data = await this.consumerCredentialService.previewGrant(req.body ?? {});
      res.set('Cache-Control', 'no-store');
      res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data });
    } catch (error) { this.#sendError(res, error); }
  }

  async credentialAccessScope(req, res) {
    try {
      if (!this.consumerCredentialService?.getCredentialAccessScope) throw new Error('Consumer access scope is not configured');
      const data = await this.consumerCredentialService.getCredentialAccessScope({ credentialId: req.params.credentialId });
      res.set('Cache-Control', 'no-store');
      res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data });
    } catch (error) { this.#sendError(res, error); }
  }

  #sendError(res, error) {
    const safe = safeError(error, { fallbackMessage: 'Invalid consumer grant' });
    res.status(safe.statusCode ?? 400).json({
      success: false,
      error: this.#errorPayload(safe)
    });
  }

  #errorPayload(safe) {
    const payload = { code: safe.code ?? 'BAD_REQUEST', message: safe.message };
    if (safe.details?.binding) {
      const binding = safe.details.binding;
      payload.binding = {
        decision: binding.decision,
        pathId: binding.pathId,
        referenceType: binding.referenceType,
        referenceOwner: binding.referenceOwner,
        ...(binding.reasonCode ? { reasonCode: binding.reasonCode } : {}),
        ...(binding.reason ? { reason: binding.reason } : {}),
        ...(binding.remediationHint ? { remediationHint: binding.remediationHint } : {}),
        ...(binding.checkedAt ? { checkedAt: binding.checkedAt } : {})
      };
      if (binding.reasonCode) payload.remediationHint = binding.remediationHint;
    }
    return payload;
  }
}
