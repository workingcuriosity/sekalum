import { HttpError } from './http-error.js';
import { requestHttps } from './https-transport.js';
import { EgressError, EgressPolicy } from '../services/egress-policy.js';
import { redactUrl } from '../utils/safe-diagnostics.js';

const DEFAULT_RESPONSE_BYTES = 1024 * 1024;

export class HttpClient {
  constructor({
    egressPolicy = new EgressPolicy(),
    transport = requestHttps,
    maxResponseBytes = DEFAULT_RESPONSE_BYTES
  } = {}) {
    this.egressPolicy = egressPolicy;
    this.transport = transport;
    this.maxResponseBytes = maxResponseBytes;
  }

  async get(url, options = {}) {
    return this.request('GET', url, options);
  }

  async post(url, body = null, options = {}) {
    return this.request('POST', url, {
      ...options,
      body
    });
  }

  async put(url, body = null, options = {}) {
    return this.request('PUT', url, {
      ...options,
      body
    });
  }

  async patch(url, body = null, options = {}) {
    return this.request('PATCH', url, {
      ...options,
      body
    });
  }

  async delete(url, options = {}) {
    return this.request('DELETE', url, options);
  }

  async request(method, url, {
    headers = {},
    body = null,
    query = {},
    bearerToken = null,
    timeout = 30000,
    pathId,
    purpose,
    providerKey = null,
    credentialBearing = undefined
  } = {}) {
    const finalUrl = this.#buildUrl(url, query);
    const route = await this.egressPolicy.admit(finalUrl, {
      pathId,
      purpose,
      providerKey,
      protocol: 'https',
      credentialBearing: credentialBearing ?? Boolean(bearerToken || body || Object.keys(query).length)
    });
    const finalHeaders = { ...headers };
    if (bearerToken) finalHeaders.Authorization = `Bearer ${bearerToken}`;
    const response = await this.transport({
      route,
      url: finalUrl,
      method,
      headers: finalHeaders,
      body,
      timeoutMs: timeout,
      maxResponseBytes: this.maxResponseBytes
    });
    if (Number(response?.status) >= 300 && Number(response?.status) < 400) {
      throw new EgressError('EGRESS_REDIRECT_BLOCKED', null, { statusCode: 502 });
    }
    const normalizedResponse = await this.#normalizeResponse(response, finalUrl);
    const data = await this.#parseResponse(normalizedResponse);
    if (!normalizedResponse.ok) {
      throw new HttpError({
        message: `${method} ${redactUrl(finalUrl)} failed`,
        status: normalizedResponse.status,
        url: finalUrl,
        response: normalizedResponse,
        body: data
      });
    }
    return { status: normalizedResponse.status, headers: normalizedResponse.headers, data };
  }

  #buildUrl(url, query) {

    const finalUrl = new URL(url);

    for (const [key, value] of Object.entries(query)) {

      if (value !== undefined && value !== null) {
        finalUrl.searchParams.set(key, value);
      }

    }

    return finalUrl.toString();

  }

  async #normalizeResponse(response, url) {
    if (!response || typeof response !== 'object') throw new Error('HTTP transport returned no response');
    const headers = response.headers instanceof Headers
      ? response.headers
      : new Headers(response.headers ?? {});
    const status = Number(response.status ?? 0);
    const body = typeof response.body === 'string' || Buffer.isBuffer(response.body)
      ? response.body
      : null;
    if (body !== null && Buffer.byteLength(body) > this.maxResponseBytes) {
      throw new EgressError('EGRESS_RESPONSE_LIMIT_EXCEEDED', null, { statusCode: 502 });
    }
    return {
      ...response,
      status,
      ok: response.ok ?? (status >= 200 && status < 300),
      redirected: false,
      type: response.type ?? 'basic',
      url: response.url ?? url,
      headers,
      body
    };
  }

  async #parseResponse(response) {
    const contentType = response.headers?.get?.('content-type') ?? '';
    if (response.body !== null) {
      const text = Buffer.isBuffer(response.body) ? response.body.toString('utf8') : String(response.body);
      if (!text) return '';
      if (contentType.includes('application/json')) {
        try { return JSON.parse(text); } catch { return text; }
      }
      return text;
    }
    if (contentType.includes('application/json') && typeof response.json === 'function') return response.json();
    if (typeof response.text === 'function') return response.text();
    return null;
  }

}
