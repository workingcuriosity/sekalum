import { safeErrorMessage } from '../../utils/safe-diagnostics.js';

export class OpenAIConnectionService {
  constructor({ client }) {
    if (!client) {
      throw new Error('OpenAIConnectionService requires client');
    }

    this.client = client;
  }

  async validateCredential(credential, { purpose = 'PROVIDER_VALIDATION' } = {}) {
    const options = this.#optionsFromCredential(credential);
    const result = await this.client.validateApiKey({ ...options, purpose });

    return {
      valid: true,
      provider: 'openai',
      modelCount: result.modelCount ?? 0,
      checkedAt: result.checkedAt ?? new Date().toISOString()
    };
  }

  async healthCheck(credential, context = {}) {
    try {
      const validation = await this.validateCredential(credential, {
        ...context,
        purpose: 'PROVIDER_HEALTH_CHECK'
      });

      return {
        healthy: true,
        status: 'up',
        provider: 'openai',
        modelCount: validation.modelCount,
        checkedAt: validation.checkedAt,
        message: 'OpenAI API key validated successfully'
      };
    } catch (error) {
      return {
        healthy: false,
        status: 'down',
        provider: 'openai',
        checkedAt: new Date().toISOString(),
        message: safeErrorMessage(error, 'OpenAI health check failed'),
        code: error?.code ?? null
      };
    }
  }

  #optionsFromCredential(credential) {
    if (!credential) {
      throw new Error('OpenAI credential is required');
    }

    const secretMap = this.#secretMap(credential);
    const metadata = credential.metadata?.toJSON?.() ?? credential.metadata ?? {};
    const custom = metadata.custom ?? {};

    const apiKey = secretMap.apiKey ?? secretMap.api_key;
    const organizationId = secretMap.organizationId ?? secretMap.organization_id ?? custom.organizationId ?? custom.organization_id ?? null;
    const projectId = secretMap.projectId ?? secretMap.project_id ?? custom.projectId ?? custom.project_id ?? null;
    const timeoutMs = custom.timeoutMs ? Number(custom.timeoutMs) : undefined;

    if (!apiKey) {
      throw new Error('OpenAI credential requires apiKey');
    }

    return {
      apiKey,
      organizationId,
      projectId,
      timeoutMs
    };
  }

  #secretMap(credential) {
    const entries = credential.secrets ?? [];
    const map = {};

    for (const secret of entries) {
      map[secret.name] = secret.value;
    }

    return map;
  }
}
