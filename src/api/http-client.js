import { HttpError } from './http-error.js';
import { redactUrl } from '../utils/safe-diagnostics.js';

export class HttpClient {

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
    timeout = 30000
  } = {}) {

    const controller = new AbortController();

    const timer = setTimeout(
      () => controller.abort(),
      timeout
    );

    try {

      const finalUrl = this.#buildUrl(url, query);

      const finalHeaders = {
        ...headers
      };

      if (bearerToken) {
        finalHeaders.Authorization = `Bearer ${bearerToken}`;
      }

      const response = await fetch(finalUrl, {
        method,
        headers: finalHeaders,
        body,
        redirect: 'error',
        signal: controller.signal
      });

      const data = await this.#parseResponse(response);

      if (!response.ok) {
        throw new HttpError({
          message: `${method} ${redactUrl(finalUrl)} failed`,
          status: response.status,
          url: finalUrl,
          response,
          body: data
        });
      }

      return {
        status: response.status,
        headers: response.headers,
        data
      };

    } finally {
      clearTimeout(timer);
    }

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

  async #parseResponse(response) {

    const contentType =
      response.headers.get('content-type') ?? '';

    if (contentType.includes('application/json')) {
      return response.json();
    }

    return response.text();

  }

}
