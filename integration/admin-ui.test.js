import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { OAuthCallbackServer } from '../../src/oauth/oauth-callback-server.js';

function createServer() {
  return new OAuthCallbackServer({
    providerManager: {
      listProviders() { return []; },
      getProvider() { throw new Error('not used'); }
    },
    importTokenCommand: {},
    credentialManager: {
      async listCredentials() { return []; }
    },
    schedulerService: { listJobs() { return []; } },
    config: { get() { return 0; } },
    logger: { success() {}, info() {}, error() {} }
  });
}

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

test('admin UI serves the Credential Wizard shell', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/admin/`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /text\/html/);
    assert.match(body, /Credential Wizard/);
    assert.match(body, /wizard\.js/);
  } finally {
    server.close();
  }
});

test('root route redirects to admin UI', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/`, { redirect: 'manual' });

    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), '/admin/');
  } finally {
    server.close();
  }
});


test('Credential Wizard contains dynamic provider field catalog', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /providerFieldCatalog/);
  assert.match(wizardScript, /getProviderFieldSet/);
  assert.match(wizardScript, /openai/);
  assert.match(wizardScript, /ftp/);
  assert.match(wizardScript, /sftp/);
});

test('Credential Wizard renders provider context and grouped fields', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const adminHtml = fs.readFileSync(path.resolve('public/admin/index.html'), 'utf8');

  assert.match(adminHtml, /provider-context/);
  assert.match(wizardScript, /renderProviderContext/);
  assert.match(wizardScript, /groupFields/);
  assert.match(wizardScript, /field-group/);
});


test('Credential Wizard defines OAuth state machine states', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /wizardStates/);
  assert.match(wizardScript, /SELECT_PROVIDER/);
  assert.match(wizardScript, /CONFIGURE/);
  assert.match(wizardScript, /AUTHORIZE/);
  assert.match(wizardScript, /WAIT_CALLBACK/);
  assert.match(wizardScript, /SUCCESS/);
  assert.match(wizardScript, /ERROR/);
});

test('Credential Wizard contains dedicated OAuth authorization step', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const adminHtml = fs.readFileSync(path.resolve('public/admin/index.html'), 'utf8');

  assert.match(adminHtml, /data-oauth-step="authorize"/);
  assert.match(adminHtml, /oauth-authorization/);
  assert.match(wizardScript, /renderOAuthAuthorizationStep/);
  assert.match(wizardScript, /nextStepForCurrentState/);
});


test('Credential Wizard builds OAuth login URL from selected provider', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /function buildOAuthLoginUrl/);
  assert.match(wizardScript, /encodeURIComponent\(key\)/);
  assert.match(wizardScript, /\/oauth\/\$\{encodeURIComponent\(key\)\}\/login/);
});

test('Credential Wizard starts OAuth login and switches to wait callback state', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /data-oauth-login-start/);
  assert.match(wizardScript, /oauth-authorize-start/);
  assert.match(wizardScript, /function markOAuthRedirectStarted/);
  assert.match(wizardScript, /wizardStates\.WAIT_CALLBACK/);
});


test('Credential Wizard reads OAuth callback success result', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /function readOAuthCallbackResult/);
  assert.match(wizardScript, /new URLSearchParams\(search\)/);
  assert.match(wizardScript, /params\.get\('oauth'\)/);
  assert.match(wizardScript, /params\.get\('provider'\)/);
  assert.match(wizardScript, /params\.get\('credentialId'\)/);
});

test('Credential Wizard applies OAuth callback result to wizard state', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /function applyOAuthCallbackResult/);
  assert.match(wizardScript, /case 'success'/);
  assert.match(wizardScript, /wizardStates\.SUCCESS/);
  assert.match(wizardScript, /case 'error'/);
  assert.match(wizardScript, /wizardStates\.ERROR/);
  assert.match(wizardScript, /case 'cancelled'/);
  assert.match(wizardScript, /wizardStates\.CONFIGURE/);
  assert.match(wizardScript, /state\.oauthResult = result/);
});


test('Credential Wizard maps OAuth providers using backend capability contract', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /oauth: \['oauth'\]/);
  assert.match(wizardScript, /caps\.includes\('oauth'\)/);
  assert.doesNotMatch(wizardScript, /oauth: \['oauth-start'\]/);
  assert.doesNotMatch(wizardScript, /caps\.includes\('oauth-start'\)/);
});

test('Credential Wizard renders provider card UX metadata', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /function providerTypeLabel/);
  assert.match(wizardScript, /provider-type-badge/);
  assert.match(wizardScript, /provider-key/);
  assert.match(wizardScript, /empty-state/);

  assert.match(styles, /\.option-card-header/);
  assert.match(styles, /\.provider-key/);
  assert.match(styles, /\.provider-type-badge/);
  assert.match(styles, /\.empty-state/);
});

test('Credential Wizard renders accessible form field UX metadata', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /function autocompleteForField/);
  assert.match(wizardScript, /autocomplete="\$\{autocompleteForField\(field\)\}"/);
  assert.match(wizardScript, /const fieldId = `credential-field-\$\{field\.name\}`/);
  assert.match(wizardScript, /<label for="\$\{fieldId\}">/);
  assert.match(wizardScript, /required-badge/);

  assert.match(styles, /\.field label/);
  assert.match(styles, /\.required-badge/);
});


test('Credential Wizard renders OAuth waiting UX metadata', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /oauth-info/);
  assert.match(wizardScript, /data-oauth-login-start/);
  assert.match(wizardScript, /Verbindung wird aufgebaut/);
  assert.match(wizardScript, /classList\.add\('disabled'\)/);

  assert.match(styles, /\.oauth-info/);
});

test('Credential Wizard renders finish screen UX metadata', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /summary-ready/);
  assert.match(wizardScript, /Bereit zum Anlegen/);
  assert.match(wizardScript, /Authentifizierung/);
  assert.match(wizardScript, /providerTypeLabel\(providerType\(state\.provider\)\)/);

  assert.match(styles, /\.summary-ready/);
});

test('Dashboard integrates Management REST API status widgets', () => {
  const dashboardHtml = fs.readFileSync(path.resolve('public/admin/dashboard.html'), 'utf8');
  const dashboardScript = fs.readFileSync(path.resolve('public/admin/dashboard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(dashboardHtml, /management-summary/);
  assert.match(dashboardHtml, /management-system-status/);
  assert.match(dashboardHtml, /management-credentials-total/);
  assert.match(dashboardHtml, /management-providers-total/);
  assert.match(dashboardHtml, /management-scheduler-state/);

  assert.match(dashboardScript, /function loadManagementStatus/);
  assert.match(dashboardScript, /function fetchManagementStatus/);
  assert.match(dashboardScript, /\/api\/v1\/management\/status/);
  assert.match(dashboardScript, /function renderManagementStatus/);
  assert.match(dashboardScript, /function showManagementError/);

  assert.match(styles, /\.management-grid/);
  assert.match(styles, /\.management-card/);
});
