export class OpenAIClient {
  constructor({ httpClient, baseUrl = 'https://api.openai.com/v1', timeoutMs = 10000 } = {}) {
    if (!httpClient) {
      throw new Error('OpenAIClient requires httpClient');
    }

    this.httpClient = httpClient;
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  async validateApiKey({ apiKey, organizationId = null, projectId = null, timeoutMs = null, purpose = 'PROVIDER_VALIDATION' } = {}) {
    this.#validateOptions({ apiKey });

    const headers = this.#headers({ organizationId, projectId });

    const response = await this.httpClient.get(`${this.baseUrl}/models`, {
      bearerToken: apiKey,
      headers,
      timeout: timeoutMs ?? this.timeoutMs,
      pathId: 'OPENAI-VALIDATE', purpose, providerKey: 'openai', credentialBearing: true
    });

    const models = Array.isArray(response.data?.data) ? response.data.data : [];

    return {
      valid: true,
      provider: 'openai',
      modelCount: models.length,
      checkedAt: new Date().toISOString()
    };
  }

  #headers({ organizationId, projectId }) {
    const headers = {};

    if (organizationId) {
      headers['OpenAI-Organization'] = organizationId;
    }

    if (projectId) {
      headers['OpenAI-Project'] = projectId;
    }

    return headers;
  }

  #validateOptions({ apiKey }) {
    if (!apiKey) {
      throw new Error('OpenAI API key is required');
    }
  }
}
