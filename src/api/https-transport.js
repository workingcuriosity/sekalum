import https from 'node:https';
import { EgressError } from '../services/egress-policy.js';

export function requestHttps({ route, url, method, headers = {}, body = null, timeoutMs = 30000, maxResponseBytes = 1024 * 1024 }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      fail(new EgressError('EGRESS_INVALID_TARGET'));
      return;
    }

    const requestHeaders = { ...headers, Host: route.hostHeader };
    const request = https.request({
      protocol: 'https:',
      hostname: route.verificationHost,
      port: route.port,
      // A pooled socket is only safe when its remote address is part of the
      // pool identity. Node's global HTTPS agent keys by host/port, not by the
      // Core-admitted connectAddress, so disable pooling at this boundary.
      agent: false,
      method,
      path: `${parsed.pathname}${parsed.search}`,
      headers: requestHeaders,
      servername: route.verificationHost,
      lookup(_hostname, _options, callback) {
        callback(null, route.connectAddress, route.addressFamily);
      }
    }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400) {
        response.resume();
        fail(new EgressError('EGRESS_REDIRECT_BLOCKED', null, { statusCode: 502 }));
        return;
      }
      const chunks = [];
      let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > maxResponseBytes) {
          response.destroy();
          fail(new EgressError('EGRESS_RESPONSE_LIMIT_EXCEEDED', null, { statusCode: 502 }));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        if (settled) return;
        settled = true;
        resolve({
          status: response.statusCode,
          ok: response.statusCode >= 200 && response.statusCode < 300,
          redirected: false,
          type: 'basic',
          url,
          headers: response.headers,
          body: Buffer.concat(chunks).toString('utf8')
        });
      });
      response.on('error', (error) => fail(error));
    });

    request.setTimeout(timeoutMs, () => {
      request.destroy();
      fail(new EgressError('EGRESS_TIMEOUT', null, { statusCode: 504 }));
    });
    request.on('error', (error) => {
      if (settled) return;
      if (error?.code === 'ETIMEDOUT') fail(new EgressError('EGRESS_TIMEOUT', null, { statusCode: 504 }));
      else fail(new EgressError('EGRESS_TRANSPORT_FAILED', null, { statusCode: 502 }));
    });

    if (body !== null && body !== undefined) {
      const payload = body instanceof URLSearchParams ? body.toString() : body;
      request.write(payload);
    }
    request.end();
  });
}
