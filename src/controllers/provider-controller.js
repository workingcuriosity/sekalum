import { safeError } from '../utils/safe-diagnostics.js';
import { authenticatedUserId } from '../utils/authenticated-user.js';

export class ProviderController {
  constructor({ providerManager, customProviderService = null, oauthRuntimeDetails = null }) {
    this.providerManager = providerManager;
    this.customProviderService = customProviderService;
    this.oauthRuntimeDetails = oauthRuntimeDetails;
  }

  async list(req, res) {
    try {
      this.#assertProviderManager('listProviders');

      const providers = await this.providerManager.listProviders();

      res.status(200).json({
        success: true,
        data: providers.map((provider) => this.#toProviderJSON(provider, req))
      });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async get(req, res) {
    try {
      this.#assertProviderManager('getProvider');

      const provider = await this.providerManager.getProvider(req.params.providerKey);

      if (!provider) {
        throw this.#notFound('Provider not found');
      }

      res.status(200).json({
        success: true,
        data: this.#toProviderJSON(provider, req)
      });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async capabilities(req, res) {
    try {
      this.#assertProviderManager('getProviderCapabilities');

      const capabilities = await this.providerManager.getProviderCapabilities(req.params.providerKey);

      if (!capabilities) {
        throw this.#notFound('Provider not found');
      }

      res.status(200).json({
        success: true,
        data: {
          providerKey: req.params.providerKey,
          capabilities
        }
      });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async create(req, res) {
    try {
      if (!this.customProviderService?.create) throw new Error('Custom provider onboarding is not configured');
      const provider = await this.customProviderService.create(req.body, {
        actorUserId: authenticatedUserId(req)
      });
      const summary = await this.providerManager.getProvider(provider.key);
      res.status(201).json({ success: true, data: this.#toProviderJSON(summary, req) });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async disable(req, res) {
    try {
      if (!this.customProviderService?.disable) throw new Error('Custom provider lifecycle is not configured');
      const result = await this.customProviderService.disable(req.params.providerKey, {
        actorUserId: authenticatedUserId(req)
      });
      res.status(200).json({ success: true, data: result });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async update(req, res) {
    try {
      if (!this.customProviderService?.update) throw new Error('Custom provider management is not configured');
      const result = await this.customProviderService.update(req.params.providerKey, req.body, {
        actorUserId: authenticatedUserId(req)
      });
      const summary = await this.providerManager.getProvider(req.params.providerKey);
      res.status(200).json({ success: true, data: this.#toProviderJSON(summary, req), classification: result.classification ?? null });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async delete(req, res) {
    try {
      if (!this.customProviderService?.delete) throw new Error('Custom provider management is not configured');
      const result = await this.customProviderService.delete(req.params.providerKey, {
        actorUserId: authenticatedUserId(req)
      });
      res.status(200).json({ success: true, data: result });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  async enable(req, res) {
    try {
      if (!this.customProviderService?.enable) throw new Error('Custom provider lifecycle is not configured');
      const result = await this.customProviderService.enable(req.params.providerKey, {
        actorUserId: authenticatedUserId(req)
      });
      res.status(200).json({ success: true, data: result });
    } catch (error) {
      this.#sendError(res, error);
    }
  }

  #assertProviderManager(operation) {
    if (!this.providerManager?.[operation]) {
      throw new Error(`ProviderController requires ProviderManager.${operation}()`);
    }
  }

  #notFound(message) {
    const error = new Error(message);
    error.statusCode = 404;
    error.code = 'NOT_FOUND';
    return error;
  }

  #sendError(res, error) {
    const safe = safeError(error);
    const statusCode = safe.statusCode ?? (safe.code === 'NOT_FOUND' ? 404 : 500);
    const code = safe.code ?? (statusCode === 404 ? 'NOT_FOUND' : 'INTERNAL_ERROR');

    res.status(statusCode).json({
      success: false,
      error: {
        code,
        message: safe.message
      }
    });
  }

  #toProviderJSON(providerSummary, req) {
    const key = providerSummary.key ?? providerSummary.name;
    const oauthTechnical = providerSummary.oauthTechnical
      ? {
          ...providerSummary.oauthTechnical,
          ...(this.oauthRuntimeDetails?.(req, key) ?? {})
        }
      : null;

    return {
      providerKey: key,
      key,
      displayName: providerSummary.displayName ?? key,
      description: providerSummary.description ?? null,
      category: providerSummary.category ?? null,
      customProvider: Boolean(providerSummary.customProvider),
      capabilities: providerSummary.capabilities?.toArray?.() ?? providerSummary.capabilities ?? [],
      credentialFields: providerSummary.credentialFields ?? [],
      providerConfigurationFields: providerSummary.providerConfigurationFields ?? [],
      credentialMethods: providerSummary.credentialMethods ?? [],
      providerMethodBindings: providerSummary.providerMethodBindings ?? [],
      authType: providerSummary.authType ?? null,
      defaultScopes: providerSummary.defaultScopes ?? [],
      oauthSecurity: providerSummary.oauthSecurity ?? null,
      oauthTechnical
    };
  }
}
