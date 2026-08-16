import { createReadStream, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { createFixtureState } from '../../scripts/ui-test-fixtures.mjs';

const root = process.cwd();
const publicRoot = path.join(root, 'public');
const fixture = createFixtureState({ includeGrant: false });
const credentials = [fixture.credential];
const providers = [fixture.provider];
const tokens = fixture.apiTokens;
const grants = fixture.grant ? [fixture.grant] : [];
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const json = (res, status, body, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(body)); };
const authorized = (req, token) => req.headers.authorization === `Bearer ${token}`;
const readJson = async (req) => {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  return raw ? JSON.parse(raw) : {};
};
const validationError = (res, code, message) => json(res, 422, { success: false, error: { code, message } });
const grantDetail = (grant) => ({ ...grant, secretNames: [...(grant.secretNames ?? [])] });
const credentialDetail = (credential) => ({
  ...credential,
  provider: { key: credential.providerKey, displayName: fixture.provider.displayName },
  credentialMethodKey: null,
  secretInventory: (credential.secretNames ?? []).map((name) => ({ name, hasValue: true }))
});
const tokenDetail = (token) => ({ ...token, token: '[REDACTED]', plaintext: undefined });
const server = createServer((req, res) => {
  const pathname = new URL(req.url, 'http://fixture.local').pathname;
  if (pathname === '/') { res.writeHead(302, { location: '/admin/' }); res.end(); return; }
  if (pathname === '/health') return json(res, 200, { status: 'UP' });
  if (pathname === '/api/v1/dashboard') return authorized(req, fixture.admin.token) ? json(res, 200, { success: true, data: { credentials: { total: 1 }, providers: { total: 1 }, scheduler: {} } }) : json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
  if (pathname === '/api/v1/providers') return authorized(req, fixture.admin.token) ? json(res, 200, { success: true, data: providers }) : json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
  if (pathname === '/api/v1/credentials/meta') return authorized(req, fixture.admin.token) ? json(res, 200, { success: true, data: { fixtureNamespace: fixture.fixture_namespace } }) : json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
  if (pathname === '/api/v1/management/consumer-grants' && req.method === 'GET') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    const query = new URL(req.url, 'http://fixture.local').searchParams;
    const filtered = grants.filter((grant) => ['consumerId', 'credentialId', 'providerKey'].every((key) => !query.get(key) || grant[key] === query.get(key)));
    return json(res, 200, { success: true, data: filtered.map(grantDetail) });
  }
  if (pathname === '/api/v1/management/consumer-grants' && req.method === 'POST') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    return readJson(req).then((body) => {
      const secretNames = Array.isArray(body?.secretNames) ? [...new Set(body.secretNames.filter(Boolean))] : [];
      if (!body?.consumerId || !body?.credentialId || !secretNames.length) return validationError(res, 'INVALID_GRANT', 'Consumer, credential, and at least one secret field are required.');
      const credential = credentials.find((entry) => entry.credentialId === body.credentialId);
      if (!credential) return json(res, 404, { error: { code: 'NOT_FOUND' } });
      if (secretNames.some((name) => !(credential.secretNames ?? []).includes(name))) return validationError(res, 'INVALID_GRANT', 'The selected secret field is not available on this credential.');
      const grant = {
        id: 'ui-test-grant-created', grantId: 'ui-test-grant-created', consumerId: body.consumerId,
        consumerName: body.consumerName || 'UI test consumer', credentialId: credential.credentialId,
        providerKey: credential.providerKey, secretNames, status: 'active',
        createdAt: '2026-08-02T00:00:04.000Z', updatedAt: '2026-08-02T00:00:04.000Z'
      };
      const index = grants.findIndex((entry) => entry.grantId === grant.grantId);
      if (index >= 0) grants.splice(index, 1, grant); else grants.push(grant);
      return json(res, 201, { success: true, data: grantDetail(grant) });
    }).catch(() => validationError(res, 'INVALID_JSON', 'The fixture request was not valid JSON.'));
  }
  if (pathname.startsWith('/api/v1/management/consumer-grants/') && req.method === 'GET') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    const grant = grants.find((entry) => entry.grantId === decodeURIComponent(pathname.slice('/api/v1/management/consumer-grants/'.length)));
    return grant ? json(res, 200, { success: true, data: grantDetail(grant) }) : json(res, 404, { error: { code: 'NOT_FOUND' } });
  }
  if (pathname.startsWith('/api/v1/management/consumer-grants/') && req.method === 'PUT') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    const grantId = decodeURIComponent(pathname.slice('/api/v1/management/consumer-grants/'.length));
    const grant = grants.find((entry) => entry.grantId === grantId);
    if (!grant) return json(res, 404, { error: { code: 'NOT_FOUND' } });
    return readJson(req).then((body) => {
      const secretNames = Array.isArray(body?.secretNames) ? [...new Set(body.secretNames.filter(Boolean))] : [];
      if (!secretNames.length) return validationError(res, 'INVALID_GRANT', 'At least one secret field is required.');
      if (secretNames.some((name) => !(fixture.credential?.secretNames ?? []).includes(name))) return validationError(res, 'INVALID_GRANT', 'The selected secret field is not available on this credential.');
      grant.secretNames = secretNames;
      grant.updatedAt = '2026-08-02T00:00:05.000Z';
      return json(res, 200, { success: true, data: grantDetail(grant) });
    }).catch(() => validationError(res, 'INVALID_JSON', 'The fixture request was not valid JSON.'));
  }
  if (pathname.startsWith('/api/v1/management/api-tokens/') && req.method === 'GET') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    const token = tokens.find((entry) => entry.id === decodeURIComponent(pathname.slice('/api/v1/management/api-tokens/'.length)));
    return token ? json(res, 200, { success: true, data: tokenDetail(token) }) : json(res, 404, { error: { code: 'NOT_FOUND' } });
  }
  if (pathname === '/api/v1/management/api-tokens' && req.method === 'GET') return authorized(req, fixture.admin.token) ? json(res, 200, { success: true, data: tokens.map(tokenDetail) }) : json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
  if (pathname === '/api/v1/management/api-tokens' && req.method === 'POST') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    return readJson(req).then((body) => {
      const consumerToken = Array.isArray(body?.scopes) && body.scopes.includes('credentials:consume');
      const token = { id: consumerToken ? fixture.token.id : 'ui-test-api-token-created', name: body?.name || (consumerToken ? fixture.token.name : 'UI test generated token'), type: 'api', createdAt: '2026-08-02T00:00:03.000Z', expiresAt: body?.expiresAt ?? null, status: 'active', userId: body?.userId || 'admin', tokenPrefix: consumerToken ? 'ch-ui-consumer' : 'ch-ui-created', scopes: Array.isArray(body?.scopes) ? body.scopes : [], credentialId: fixture.credential?.credentialId ?? null, token: '[REDACTED]' };
      const index = tokens.findIndex((entry) => entry.id === token.id);
      if (index >= 0) tokens.splice(index, 1, token); else tokens.push(token);
      return json(res, 201, { success: true, data: tokenDetail(token), token: '[REDACTED]' });
    }).catch(() => validationError(res, 'INVALID_JSON', 'The fixture request was not valid JSON.'));
  }
  if (pathname.startsWith('/api/v1/credentials/') && req.method === 'GET') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    const credentialId = decodeURIComponent(pathname.slice('/api/v1/credentials/'.length));
    const credential = credentials.find((entry) => entry.credentialId === credentialId || entry.id === credentialId);
    return credential ? json(res, 200, { data: credentialDetail(credential) }) : json(res, 404, { error: { code: 'NOT_FOUND' } });
  }
  if (pathname === '/api/v1/credentials' && req.method === 'GET') return authorized(req, fixture.admin.token) ? json(res, 200, { data: credentials }) : json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
  if (pathname === '/api/v1/credentials/test-connection' && req.method === 'POST') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    return readJson(req).then((body) => body?.secrets?.some((secret) => secret.value === fixture.wizardInputs.invalidApiKey)
      ? validationError(res, 'FIXTURE_VALIDATION_FAILED', 'The fixture rejected this credential input.')
      : json(res, 200, { success: true, data: { status: 'validated', fixtureNamespace: fixture.fixture_namespace } }))
      .catch(() => validationError(res, 'INVALID_JSON', 'The fixture request was not valid JSON.'));
  }
  if (pathname === '/api/v1/credentials' && req.method === 'POST') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    return readJson(req).then((body) => {
      const displayName = body?.metadata?.displayName;
      const apiKey = body?.secrets?.find((secret) => secret.name === 'apiKey')?.value;
      if (!displayName || !apiKey || apiKey === fixture.wizardInputs.invalidApiKey) return validationError(res, 'FIXTURE_VALIDATION_FAILED', 'Display name and a valid API key are required.');
      const created = { ...fixture.credential, displayName, id: 'ui-test-created-credential', credentialId: 'ui-test-created-credential', credentialKey: 'ui-test-created-credential-key', metadata: { ...fixture.credential.metadata, displayName }, createdAt: '2026-08-02T00:00:01.000Z', updatedAt: '2026-08-02T00:00:01.000Z' };
      const existingIndex = credentials.findIndex((entry) => entry.credentialId === created.credentialId);
      if (existingIndex >= 0) credentials.splice(existingIndex, 1, created); else credentials.push(created);
      fixture.wizard.createdCredentialIds.push(created.id);
      return json(res, 201, { success: true, data: created });
    }).catch(() => validationError(res, 'INVALID_JSON', 'The fixture request was not valid JSON.'));
  }
  if (pathname === '/api/v1/consumer/handoff' && req.method === 'POST') {
    if (!authorized(req, fixture.admin.token)) return json(res, 401, { error: { code: 'AUTHENTICATION_REQUIRED' } });
    return readJson(req).then((body) => {
      if (body?.consumerToken === fixture.consumer.noGrantToken) return json(res, 403, { error: { code: 'GRANT_MISSING' } });
      if (body?.consumerToken !== fixture.consumer.token) return json(res, 401, { error: { code: 'API_TOKEN_AUTH_FAILED' } });
      return json(res, 200, { success: true, data: { consumerId: fixture.consumer.id, destination: '/consumer/', status: 'ready' } });
    }).catch(() => validationError(res, 'INVALID_JSON', 'The fixture request was not valid JSON.'));
  }
  if (pathname === '/api/v1/consumer/credentials') {
    const token = req.headers.authorization?.replace(/^Bearer\s+/, '');
    if (token === fixture.consumer.invalidToken) return json(res, 401, { error: { code: 'API_TOKEN_AUTH_FAILED' } });
    if (token === fixture.consumer.discoveryErrorToken) return json(res, 500, { error: { code: 'DISCOVERY_UNAVAILABLE' } });
    if (token === fixture.consumer.emptyToken) return json(res, 200, { success: true, data: { credentials: [] } });
    if (![fixture.consumer.token, fixture.consumer.noGrantToken, fixture.consumer.resolveInvalidToken, fixture.consumer.missingCredentialToken, fixture.consumer.deniedSecretToken].includes(token)) return json(res, 401, { error: { code: 'API_TOKEN_AUTH_FAILED' } });
    const missingCredential = token === fixture.consumer.missingCredentialToken;
    const deniedSecret = token === fixture.consumer.deniedSecretToken;
    return json(res, 200, { success: true, data: { credentials: [{ credentialKey: missingCredential ? 'missing-fixture-credential' : fixture.credential.credentialKey, metadata: { displayName: 'UI test credential' }, fields: [{ name: 'apiKey', label: 'API key', required: true, secret: true, visible: true }, ...(deniedSecret ? [{ name: 'apiSecret', label: 'API secret', required: false, secret: true, visible: true }] : [])] }] } });
  }
  if (pathname.endsWith('/resolve') && req.method === 'POST') {
    const token = req.headers.authorization?.replace(/^Bearer\s+/, '');
    const credentialKey = decodeURIComponent(pathname.slice('/api/v1/consumer/credentials/'.length, -'/resolve'.length));
    if (token === fixture.consumer.resolveInvalidToken || token === fixture.consumer.invalidToken) return json(res, 401, { error: { code: 'API_TOKEN_AUTH_FAILED' } });
    if (token === fixture.consumer.noGrantToken) return json(res, 403, { error: { code: 'GRANT_MISSING' } });
    if (token === fixture.consumer.missingCredentialToken || credentialKey === 'missing-fixture-credential') return json(res, 404, { error: { code: 'CREDENTIAL_NOT_FOUND' } });
    if (![fixture.consumer.token, fixture.consumer.deniedSecretToken].includes(token)) return json(res, 401, { error: { code: 'API_TOKEN_AUTH_FAILED' } });
    return readJson(req).then((body) => {
      const secretNames = Array.isArray(body?.secretNames) ? body.secretNames : [];
      if (!secretNames.length || secretNames.some((name) => !['apiKey', 'apiSecret'].includes(name))) return validationError(res, 'INVALID_SECRET_REQUEST', 'Select an allowed secret field.');
      if (token === fixture.consumer.deniedSecretToken && secretNames.includes('apiSecret')) return json(res, 403, { error: { code: 'SECRET_NOT_GRANTED' } });
      if (secretNames.some((name) => name !== 'apiKey')) return json(res, 403, { error: { code: 'SECRET_NOT_GRANTED' } });
      return json(res, 200, { success: true, data: { credentialKey, lifecycleState: 'active', providerKey: fixture.credential.providerKey, secrets: Object.fromEntries(secretNames.map((name) => [name, '[REDACTED]'])) } }, { 'cache-control': 'no-store' });
    }).catch(() => validationError(res, 'INVALID_JSON', 'The fixture request was not valid JSON.'));
  }
  const relative = pathname === '/admin/' ? 'admin/index.html' : pathname === '/consumer/' ? 'consumer/index.html' : pathname.replace(/^\//, '');
  const target = path.resolve(publicRoot, relative);
  if (!target.startsWith(publicRoot) || !existsSync(target)) { res.writeHead(404); res.end('not found'); return; }
  res.writeHead(200, { 'content-type': mime[path.extname(target)] ?? 'application/octet-stream' });
  createReadStream(target).pipe(res);
});
server.listen(process.env.UI_FIXTURE_PORT ?? 4173, '127.0.0.1');
