// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { applicationPath } from './base-path.js';

const defaultFetch = (...args) => globalThis.fetch(...args);

function normalizeToken(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function apiError(body, status) {
  const error = new Error(body?.error?.message ?? body?.message ?? (typeof body === 'string' ? body : `HTTP ${status}`));
  error.code = body?.error?.code ?? body?.code;
  error.messageKey = body?.error?.messageKey ?? body?.messageKey;
  error.redirectUri = body?.error?.details?.redirectUri;
  error.status = status;
  return error;
}

export class ConsumerApiClient {
  constructor({ fetchImpl = defaultFetch } = {}) { this.fetchImpl = fetchImpl; }

  async request(path, consumerToken, options = {}) {
    const token = normalizeToken(consumerToken);
    if (!token) throw new Error('Ein Consumer-Token ist erforderlich.');
    const response = await this.fetchImpl(applicationPath(path), {
      ...options,
      headers: { Accept: 'application/json', Authorization: `Bearer ${token}`, ...(options.body ? { 'Content-Type': 'application/json' } : {}) }
    });
    const contentType = response.headers.get('content-type') ?? '';
    const body = contentType.includes('application/json') ? await response.json() : await response.text();
    if (!response.ok || body?.success === false) throw apiError(body, response.status);
    return { body, response };
  }
}
