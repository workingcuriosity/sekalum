import { ResolveDiagnosticCode, resolveDiagnostic } from '../services/resolve-diagnostics.js';

export class ConsumerCredentialController {
  constructor({ consumerCredentialService }) {
    if (!consumerCredentialService?.resolve) throw new Error('ConsumerCredentialController requires ConsumerCredentialService');
    this.consumerCredentialService = consumerCredentialService;
  }

  async discover(req, res) {
    try {
      const data = await this.consumerCredentialService.discover({
        consumerId: req.auth.consumerId
      });
      res.set('Cache-Control', 'no-store');
      res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data });
    } catch {
      res.set('Cache-Control', 'no-store');
      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Credential discovery could not be completed'
        }
      });
    }
  }

  async resolve(req, res) {
    try {
      const data = await this.consumerCredentialService.resolve({
        consumerId: req.auth.consumerId,
        apiTokenId: req.auth.apiToken?.id ?? null,
        credentialKey: req.params.credentialKey,
        secretNames: req.body?.secretNames
      });
      res.set('Cache-Control', 'no-store');
      res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data });
    } catch (error) {
      const diagnostic = resolveDiagnostic(error.code, { publicResponse: true });
      const invalidRequest = error.code === ResolveDiagnosticCode.INVALID_SECRET_REQUEST;
      const internal = !error.code || error.code === 'INTERNAL_ERROR';
      res.set('Cache-Control', 'no-store');
      res.status(internal ? 500 : diagnostic.statusCode).json({
        success: false,
        error: {
          code: internal ? 'INTERNAL_ERROR' : invalidRequest ? error.code : diagnostic.code,
          message: internal ? 'Credential resolution could not be completed' : diagnostic.message
        }
      });
    }
  }

  async diagnose(req, res) {
    const data = await this.consumerCredentialService.diagnose(req.body ?? {});
    res.set('Cache-Control', 'no-store');
    res.status(200).json({ success: true, meta: { apiVersion: 'v1' }, data });
  }
}
