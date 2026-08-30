import { redactUrl, sanitizeDiagnostic } from '../utils/safe-diagnostics.js';

export class HttpError extends Error {
  constructor({
    message,
    status,
    url,
    response,
    body
  }) {
    const rawUrl = typeof url === 'string' ? url : null;
    const safeUrl = redactUrl(url);
    const messageText = typeof message === 'string' ? message : 'HTTP request failed';
    const safeMessage = rawUrl && messageText.includes(rawUrl)
      ? messageText.replaceAll(rawUrl, safeUrl)
      : sanitizeDiagnostic(messageText);

    super(safeMessage);

    this.name = 'HttpError';

    this.status = status;
    this.url = safeUrl;
    this.response = response && typeof response === 'object'
      ? {
        status: response.status,
        ok: response.ok,
        redirected: response.redirected,
        type: response.type,
        url: redactUrl(response.url)
      }
      : response ?? null;
    this.body = sanitizeDiagnostic(body);

    const providerCode = typeof body?.error === 'string'
      ? body.error
      : body?.error?.code ?? body?.code;
    if (typeof providerCode === 'string' && providerCode.toLowerCase() === 'redirect_uri_mismatch') {
      this.code = 'OAUTH_REDIRECT_URI_MISMATCH';
    }
  }
}
