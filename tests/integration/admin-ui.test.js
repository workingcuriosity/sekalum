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

test('admin UI gates the Wizard behind a dedicated management-token login', () => {
  const adminHtml = fs.readFileSync(path.resolve('public/admin/index.html'), 'utf8');
  const authScript = fs.readFileSync(path.resolve('public/admin/auth.js'), 'utf8');
  const shellScript = fs.readFileSync(path.resolve('public/admin/admin-shell.js'), 'utf8');
  assert.match(adminHtml, /wizard\.js/);
  assert.match(authScript, /admin-login-page/);
  assert.match(authScript, /api\/v1\/dashboard/);
  assert.match(shellScript, /await authenticateAdmin/);
});

test('admin UI explains management-token purpose and exposes its current status', () => {
  const authScript = fs.readFileSync(path.resolve('public/admin/auth.js'), 'utf8');
  const english = fs.readFileSync(path.resolve('public/admin/locales/en.js'), 'utf8');
  const german = fs.readFileSync(path.resolve('public/admin/locales/de.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(authScript, /management-token-help/);
  assert.match(authScript, /management-token-status/);
  assert.match(authScript, /admin\.managementToken\.required/);
  assert.match(authScript, /admin\.managementToken\.ready/);
  assert.match(english, /admin\.managementToken\.purpose/);
  assert.match(english, /admin\.managementToken\.help/);
  assert.match(german, /admin\.managementToken\.purpose/);
  assert.match(german, /admin\.managementToken\.help/);
  assert.match(styles, /management-token-status\.is-required/);
  assert.match(styles, /management-token-status\.is-ready/);
});

test('consumer UI serves a separate foundation shell without adding an API route', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/consumer/`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /text\/html/);
    assert.match(body, /consumer-token-form/);
    assert.match(body, /consumer\.js/);
    assert.doesNotMatch(body, /admin-shell|management-token/);

    const noSlash = await fetch(`${baseUrl}/consumer`, { redirect: 'manual' });
    assert.ok([301, 302].includes(noSlash.status));
    assert.equal(noSlash.headers.get('location'), '/consumer/');

    const script = await fetch(`${baseUrl}/consumer/consumer.js`);
    assert.equal(script.status, 200);
    assert.match(script.headers.get('content-type') ?? '', /javascript/);

    const styles = await fetch(`${baseUrl}/consumer/styles.css`);
    assert.equal(styles.status, 200);
    assert.match(styles.headers.get('content-type') ?? '', /text\/css/);

    const sharedClient = await fetch(`${baseUrl}/shared/consumer-api.js`);
    assert.equal(sharedClient.status, 200);
    assert.match(sharedClient.headers.get('content-type') ?? '', /javascript/);

    const apiProbe = await fetch(`${baseUrl}/consumer/api/v1/credentials`);
    assert.equal(apiProbe.status, 404);
  } finally {
    server.close();
  }
});

test('consumer UI keeps the token in memory and uses the public discovery boundary', () => {
  const consumerScript = fs.readFileSync(path.resolve('public/consumer/consumer.js'), 'utf8');
  const consumerHtml = fs.readFileSync(path.resolve('public/consumer/index.html'), 'utf8');

  assert.match(consumerHtml, /type="password"/);
  assert.match(consumerScript, /consumerToken: ''/);
  assert.match(consumerScript, /addEventListener\('submit'/);
  assert.match(consumerScript, /\/api\/v1\/consumer\/credentials/);
  assert.match(consumerScript, /ConsumerApiClient/);
  assert.doesNotMatch(consumerScript, /localStorage|sessionStorage|document\.cookie|location\.search/);
  assert.match(consumerScript, /\/api\/v1\/consumer\/credentials\/\$\{encodeURIComponent\(credentialKey\)\}\/resolve/);
  assert.doesNotMatch(consumerScript, /management|credentialId|credentialMethodKey|providerMethodBinding/);
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


test('Credential Wizard reads provider fields from the Provider API', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /getProviderFieldSet/);
  assert.match(wizardScript, /credentialFields/);
  assert.doesNotMatch(wizardScript, /providerFieldCatalog/);
  assert.doesNotMatch(wizardScript, /credentialTypes/);
});

test('Credential Wizard selects generic credential methods before rendering their fields', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const adminHtml = fs.readFileSync(path.resolve('public/admin/index.html'), 'utf8');

  assert.match(adminHtml, /credential-method-selection/);
  assert.match(wizardScript, /credentialMethods/);
  assert.match(wizardScript, /renderCredentialMethodSelection/);
  assert.match(wizardScript, /data-credential-method/);
  assert.match(wizardScript, /credentialMethodKey: selectedCredentialMethod\(\)\.key/);
  assert.match(wizardScript, /selectedCredentialMethod\(\)\?\.credentialFields/);
  assert.doesNotMatch(wizardScript, /method\.key === ['"]webhook['"]/);
});

test('Custom Provider onboarding collects declarative methods and fields without emitting forbidden configuration', () => {
  const providersScript = fs.readFileSync(path.resolve('public/admin/providers.js'), 'utf8');
  const providersHtml = fs.readFileSync(path.resolve('public/admin/providers.html'), 'utf8');

  assert.match(providersHtml, /Provider details/);
  assert.match(providersHtml, /Credential methods/);
  assert.match(providersHtml, /Credential fields and method bindings/);
  assert.match(providersHtml, /Review and create/);
  assert.match(providersScript, /function providerPayload\(\)/);
  assert.match(providersScript, /credentialMethods:/);
  assert.match(providersScript, /providerMethodBindings:/);
  assert.match(providersScript, /credentialFields:/);
  assert.match(providersScript, /section: 'accountCredentials'/);
  assert.match(providersScript, /api\('\/api\/v1\/providers', \{ method: 'POST'/);
  assert.match(providersHtml, /OAuth, provider-configuration fields, runtime operations, code, hooks, scripts, and provider-definition secrets are not supported and are rejected/);
  assert.doesNotMatch(providersScript, /providerConfigurationFields/);
  assert.doesNotMatch(providersScript, /oauthTechnical/);
  assert.doesNotMatch(providersScript, /runtimeOperations/);
  assert.match(providersScript, /identity\.description\.trim\(\) \? \{ description: identity\.description\.trim\(\) \} : \{\}/);
});

test('Custom Provider onboarding preserves field edits when navigating back and locks referenced method IDs', () => {
  const providersScript = fs.readFileSync(path.resolve('public/admin/providers.js'), 'utf8');

  // Step 3 is captured before returning to Step 2, so a subsequent forward
  // navigation renders from the current field state rather than stale state.
  assert.match(providersScript, /function captureCurrentStep\(\)/);
  assert.match(providersScript, /if \(state\.step === 3\) captureFields\(\)/);
  assert.match(providersScript, /captureCurrentStep\(\); if \(state\.step === 3\) renderMethods\(\); setStep\(state\.step - 1\)/);
  // A field's methodKey is a foreign key; the UI and capture path both preserve it.
  assert.match(providersScript, /function methodHasFields\(methodKey\)/);
  assert.match(providersScript, /readonly aria-describedby/);
  assert.match(providersScript, /key: methodHasFields\(method\.key\) \? method\.key/);
});

test('Admin UI loads the shared internationalization layer on every scoped page', () => {
  for (const file of ['wizard.js', 'dashboard.js', 'credentials.js', 'consumer-grants.js', 'api-tokens.js', 'credential-transfer.js', 'providers.js']) {
    const script = fs.readFileSync(path.resolve('public/admin', file), 'utf8');
    assert.match(script, /from '\.\/i18n\.js'/);
    assert.match(script, /initI18n\(\)/);
  }

  const i18n = fs.readFileSync(path.resolve('public/admin/i18n.js'), 'utf8');
  assert.match(i18n, /credentialHub\.language/);
  assert.match(i18n, /startsWith\('de'\)/);
  assert.match(i18n, /aria-pressed/);
});

test('Consumer-grant management UI lists, filters, and updates grants without exposing secret values', () => {
  const script = fs.readFileSync(path.resolve('public/admin/consumer-grants.js'), 'utf8');
  const html = fs.readFileSync(path.resolve('public/admin/consumer-grants.html'), 'utf8');
  const shell = fs.readFileSync(path.resolve('public/admin/admin-shell.js'), 'utf8');

  assert.match(shell, /consumer-grants\.html/);
  assert.match(html, /consumer-grants-filter-form/);
  assert.match(html, /consumer-grant-edit-panel/);
  assert.doesNotMatch(html, /consumerGrants\.beta1Notice/);
  assert.match(html, /id="consumer-grant-edit-consumer" class="readonly-value"/);
  assert.match(html, /id="consumer-grant-edit-credential" class="readonly-value"/);
  assert.doesNotMatch(html, /id="consumer-grant-edit-form"[\s\S]*?<select[^>]+name="consumerId"/);
  assert.doesNotMatch(html, /id="consumer-grant-edit-form"[\s\S]*?<select[^>]+name="credentialId"/);
  assert.match(html, /No default fields are added/);
  assert.match(html, /What is a consumer grant/);
  assert.match(html, /consumerGrants\.explainTitle/);
  assert.match(html, /consumerGrants\.consumerSeesHelp/);
  assert.match(html, /consumerGrants\.consumerNeverSeesHelp/);
  assert.match(html, /consumerGrants\.discoveryResolveHelp/);
  assert.match(html, /consumerGrants\.tokenBoundaryHelp/);
  assert.match(html, /consumer-grant-create-preview/);
  assert.match(html, /consumer-grant-edit-preview/);
  assert.match(html, /aria-busy="false"/);
  assert.match(script, /\/api\/v1\/management\/consumer-grants\$\{filterQuery\(\)\}/);
  assert.match(script, /method: 'PUT'/);
  assert.match(script, /from '\.\/auth\.js'/);
  assert.match(script, /adminApi\.request/);
  assert.doesNotMatch(script, /Authorization: `Bearer/);
  assert.match(script, /secretNames/);
  assert.match(script, /renderLoading/);
  assert.match(script, /lastUpdated/);
  assert.doesNotMatch(script, /localStorage/);
  assert.match(script, /management\/api-tokens/);
  assert.match(script, /credentials\?pageSize=500/);
  assert.match(script, /technicalId/);
  assert.match(script, /void loadGrants\(\)/);
  assert.match(script, /row\.append\(detailCell\(providerLabel\(grant\.providerKey\)\)\)/);
  assert.match(html, /consumerGrants\.areaLabel/);
  assert.match(html, /consumerGrants\.areaHelp/);
  assert.match(script, /consumerId: editGrant\.consumerId/);
  assert.match(script, /credentialId: editGrant\.credentialId/);
  assert.match(script, /providerLabel\(grant\.providerKey\)/);
  assert.match(script, /permissionSummaryText/);
  assert.match(script, /renderCreatePreview/);
  assert.match(script, /previewRuntimePublic/);
  assert.match(script, /previewState/);
  assert.match(script, /previewExcludedUnavailable/);
  assert.match(script, /const selected = \[\.\.\.new Set\(selectedNames\)\]/);
  assert.match(html, /consumerGrants\.readOnlyBindingHelp/);
  assert.doesNotMatch(html, /id="consumer-grant-edit-form"[\s\S]*?name="providerKey"/);
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
  assert.match(wizardScript, /CREDENTIAL_READY/);
  assert.match(wizardScript, /GRANT_CONFIGURE/);
  assert.match(wizardScript, /INTEGRATION_COMPLETE/);
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

test('Credential Wizard exposes one canonical Back button for every step', () => {
  const adminHtml = fs.readFileSync(path.resolve('public/admin/index.html'), 'utf8');
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const backButtons = adminHtml.match(/<button[^>]*data-action="back"[^>]*>/g) ?? [];

  assert.equal(backButtons.length, 1);
  assert.match(adminHtml, /<nav class="actions" aria-label="Wizard-Navigation">[\s\S]*data-testid="credential-wizard-back"/);
  assert.match(wizardScript, /function previousStepForCurrentState\(\) \{[\s\S]*if \(state\.step === 5 && !isOAuthProvider\(\)\) return 3;[\s\S]*return Math\.max\(1, state\.step - 1\);/);
  assert.match(wizardScript, /if \(event\.target\.matches\('\[data-action="back"\]'\)\) \{[\s\S]*return setStep\(previousStepForCurrentState\(\)\);/);
});


test('Credential Wizard starts OAuth through the metadata-driven backend route', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /function providerConfigurationPayload/);
  assert.match(wizardScript, /function startOAuth/);
  assert.match(wizardScript, /\/api\/v1\/providers\/\$\{encodeURIComponent\(providerKey\(\)\)\}\/oauth\/start/);
  assert.match(wizardScript, /providerConfiguration: providerConfigurationPayload\(\)/);
  assert.match(wizardScript, /missingProviderConfigurationFields/);
  assert.match(wizardScript, /markMissingFields/);
  assert.match(wizardScript, /window\.open\('about:blank'/);
  assert.doesNotMatch(wizardScript, /localStorage\.(setItem|getItem)\([^\n]*(clientId|clientSecret|providerConfiguration)/);
});

test('Credential Wizard starts OAuth login and switches to wait callback state', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /data-oauth-login-start/);
  assert.match(wizardScript, /oauth-authorize-start/);
  assert.match(wizardScript, /function markOAuthRedirectStarted/);
  assert.match(wizardScript, /wizardStates\.WAIT_CALLBACK/);
});

test('Credential Wizard resets an unfinished OAuth attempt when returning to credential data', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /function resetOAuthAttempt\(\) \{[\s\S]*state\.oauthWindow\.close\(\);[\s\S]*state\.oauthWindow = null;[\s\S]*state\.oauthPending = false;[\s\S]*state\.oauthResult = null;[\s\S]*\}/);
  assert.match(wizardScript, /if \(event\.target\.matches\('\[data-action="back"\]'\)\) \{\s*if \(state\.step === 4\) resetOAuthAttempt\(\);\s*return setStep\(previousStepForCurrentState\(\)\);\s*\}/);
  assert.match(wizardScript, /state\.oauthPending \? 'disabled' : ''/);
  assert.match(wizardScript, /state\.oauthPending \? t\('wizard\.connecting'\) : t\('wizard\.oauth\.start'\)/);
});


test('Credential Wizard receives OAuth result through an origin-checked message contract', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /window\.addEventListener\('message'/);
  assert.match(wizardScript, /event\.origin !== window\.location\.origin/);
  assert.match(wizardScript, /credential-hub:oauth-result/);
  assert.match(wizardScript, /result\.version !== 1/);
  assert.match(wizardScript, /state\.oauthPending = false/);
  assert.match(wizardScript, /wizardStates\.CREDENTIAL_READY/);
});

test('Credential Wizard keeps OAuth success at Credential ready until a real consumer Resolve completes', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /function renderOAuthOutcome/);
  assert.match(wizardScript, /wizard\.integration\.credentialReady/);
  assert.match(wizardScript, /function verifyRealResolve/);
  assert.match(wizardScript, /\/api\/v1\/consumer\/credentials\/\$\{encodeURIComponent\(credentialKey\)\}\/resolve/);
  assert.match(wizardScript, /response\.headers\.get\('cache-control'\) !== 'no-store'/);
  assert.match(wizardScript, /wizardStates\.INTEGRATION_COMPLETE/);
  assert.match(wizardScript, /state\.consumerTokenPlaintext = null/);
  assert.doesNotMatch(wizardScript, /value="admin"/);
  assert.match(wizardScript, /t\('nav\.dashboard'\)/);
  assert.match(wizardScript, /t\('wizard\.createAnother'\)/);
  assert.match(wizardScript, /integrationComplete\(\) \? `[^`]*dashboard/);
  assert.match(wizardScript, /outcome\?\.status === 'success' && !managementTokenStore\.getToken\(\)/);
  assert.match(wizardScript, /wizard\.integration\.managementTokenRequired/);
});


test('Credential Wizard maps OAuth providers through official ProviderCapability.OAUTH contract', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /providerCapabilities\(provider\)\.includes\('oauth'\)/);
  assert.doesNotMatch(wizardScript, /oauth: \['oauth'\]/);
});

test('Credential Wizard renders provider card UX metadata', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /function authTypeLabel/);
  assert.match(wizardScript, /provider-type-badge/);
  assert.match(wizardScript, /provider-key/);
  assert.match(wizardScript, /aria-pressed/);
  assert.match(wizardScript, /technical-details/);
  assert.match(wizardScript, /empty-state/);

  assert.match(styles, /\.option-card-header/);
  assert.match(styles, /\.provider-key/);
  assert.match(styles, /\.provider-type-badge/);
  assert.match(styles, /\.empty-state/);
  assert.match(wizardScript, /provider-row/);
  assert.match(wizardScript, /auth-type-row/);
  assert.match(wizardScript, /providerAuthGroup/);
  assert.doesNotMatch(wizardScript, /label === t\('errors\.unexpected'\)/);
});

test('Credential Wizard gives actionable guidance for unavailable API and missing authentication selection', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const english = fs.readFileSync(path.resolve('public/admin/locales/en.js'), 'utf8');
  const german = fs.readFileSync(path.resolve('public/admin/locales/de.js'), 'utf8');

  assert.match(wizardScript, /showError\(t\('errors\.apiUnavailable'\)\)/);
  assert.match(wizardScript, /showError\(t\('wizard\.selectAuthError'\)\)/);
  assert.match(english, /errors\.apiUnavailable.*running.*refresh the page/i);
  assert.match(english, /wizard\.selectAuthError.*available methods.*refresh the page/i);
  assert.match(german, /errors\.apiUnavailable.*Dienst nicht erreichen.*laden Sie die Seite neu/i);
  assert.match(german, /wizard\.selectAuthError.*verfuegbare Methode.*Provider-Konfiguration/i);
});

test('Admin pages share BASE_PATH-safe navigation and public support information', () => {
  const shell = fs.readFileSync(path.resolve('public/admin/admin-shell.js'), 'utf8');

  assert.match(shell, /applicationPath\('\/admin\/dashboard\.html'\)/);
  assert.match(shell, /applicationPath\('\/admin\/'\)/);
  assert.match(shell, /https:\/\/discord\.gg\/exTu3Dy2UW/);
  assert.match(shell, /luiscyphre404@gmail\.com/);
  assert.match(shell, /AGPL-3\.0-only/);
  assert.match(shell, /support\.thirdParty/);
  assert.match(shell, /SECURITY\.md/);
  assert.match(shell, /noopener noreferrer/);
  assert.match(shell, /PROJECT_LINKS/);
  assert.doesNotMatch(shell, /feature\/project-ai-knowledge-base/);
  assert.doesNotMatch(shell, /blob\/main/);

  for (const file of ['index.html', 'dashboard.html', 'credentials.html', 'consumer-grants.html', 'api-tokens.html', 'credential-transfer.html']) {
    const html = fs.readFileSync(path.resolve('public/admin', file), 'utf8');
    assert.match(html, /id="app-navigation"/);
    assert.match(html, /id="app-footer"/);
  }
});

test('Credential management UI uses the existing routes with secret-safe edit and delete handling', () => {
  const script = fs.readFileSync(path.resolve('public/admin/credentials.js'), 'utf8');
  const html = fs.readFileSync(path.resolve('public/admin/credentials.html'), 'utf8');

  assert.match(script, /\/api\/v1\/credentials\?pageSize=500/);
  assert.match(script, /method: 'PUT'/);
  assert.match(script, /method: 'DELETE'/);
  assert.match(script, /from '\.\/auth\.js'/);
  assert.match(script, /adminApi\.request/);
  assert.match(script, /secretInventory/);
  assert.match(script, /credentialMethodKey/);
  assert.match(script, /method\?\.credentialFields/);
  assert.match(script, /credentials\.method/);
  assert.match(script, /field\.systemManaged/);
  assert.match(script, /function isEditFieldRequired/);
  assert.match(script, /function validateEditFields/);
  assert.match(script, /credentials\.requiredFields/);
  assert.match(script, /required-badge/);
  assert.match(script, /aria-required/);
  assert.match(script, /if \(raw\.trim\(\)\) secrets\.push/);
  assert.match(script, /async function loadCredentials\(\{ preserveMessages = false \} = \{\}\)/);
  assert.match(script, /await loadCredentials\(\{ preserveMessages: true \}\)\) showSuccess\(t\('credentials\.updateSuccess'\)\)/);
  assert.match(script, /await loadCredentials\(\{ preserveMessages: true \}\)\) showSuccess\(t\('credentials\.deleteSuccess'\)\)/);
  assert.doesNotMatch(script, /innerHTML/);
  assert.match(html, /credential-edit-panel/);
  assert.match(html, /credential-edit-impact/);
  assert.match(html, /credentials\.impactHelp/);
  assert.match(html, /credential-delete-panel/);
  assert.match(html, /aria-modal="true"/);
});

test('public project links are centralized and served independently of repository branches', () => {
  const links = fs.readFileSync(path.resolve('public/admin/project-links.js'), 'utf8');
  const callbackServer = fs.readFileSync(path.resolve('src/oauth/oauth-callback-server.js'), 'utf8');

  assert.match(links, /\/project-documents\/license/);
  assert.match(links, /thirdPartySoftware/);
  assert.match(links, /security/);
  assert.doesNotMatch(links, /feature\/project-ai-knowledge-base|blob\/main|blob\/[0-9a-f]{40}/);
  assert.match(callbackServer, /PROJECT_LINKS\.license/);
  assert.match(callbackServer, /PROJECT_LINKS\.security/);
  assert.match(callbackServer, /PROJECT_DOCUMENTS/);
});

test('project documents return HTTP 200 at stable public routes', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    for (const route of ['/project-documents/license', '/project-documents/notice', '/project-documents/third-party-software', '/project-documents/security']) {
      const response = await fetch(`${baseUrl}${route}`);
      assert.equal(response.status, 200, route);
      assert.ok((await response.text()).length > 100, route);
    }
  } finally {
    server.close();
  }
});

test('Credential Wizard hides system-managed provider fields', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');

  assert.match(wizardScript, /field\.visible !== false/);
  assert.match(wizardScript, /field\.userConfigurable !== false/);
  assert.match(wizardScript, /!field\.systemManaged/);
  assert.doesNotMatch(wizardScript, /field\.key === 'redirectUri'/);
});

test('Credential Wizard shows read-only OAuth registration details and checks the runtime redirect URI', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /function oauthRegistrationDetails/);
  assert.match(wizardScript, /technical\.redirectUri/);
  assert.match(wizardScript, /technical\.authorizationEndpoint/);
  assert.match(wizardScript, /response\.data\.callbackPath/);
  assert.match(wizardScript, /response\.data\.redirectUri/);
  assert.match(styles, /\.oauth-registration-details/);
});

test('Credential Wizard offers a capability-gated, BASE_PATH-safe draft connection test', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const adminHtml = fs.readFileSync(path.resolve('public/admin/index.html'), 'utf8');

  assert.match(adminHtml, /connection-test-panel/);
  assert.match(wizardScript, /function supportsConnectionTest/);
  assert.match(wizardScript, /includes\('validation'\)/);
  assert.match(wizardScript, /function testConnection/);
  assert.match(wizardScript, /\/api\/v1\/credentials\/test-connection/);
  assert.match(wizardScript, /JSON\.stringify\(credentialPayload\(\)\)/);
  assert.match(wizardScript, /state\.connectionTest = null/);
  assert.doesNotMatch(wizardScript, /https?:\/\/api\./);
});

test('Credential management exposes stored validation only for providers with validation capability', () => {
  const script = fs.readFileSync(path.resolve('public/admin/credentials.js'), 'utf8');

  assert.match(script, /function canValidate/);
  assert.match(script, /providerCapabilities/);
  assert.match(script, /actionButton\('validate'/);
  assert.match(script, /\/validate`/);
  assert.match(script, /credentials\.validateSuccess/);
  assert.match(script, /loadCredentials\(\{ preserveMessages: true \}\)/);
});

test('Credential Wizard renders accessible form field UX metadata', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /function autocompleteForField/);
  assert.match(wizardScript, /autocompleteForField\(field\)/);
  assert.match(wizardScript, /const id = `credential-field-\$\{field\.key\}`/);
  assert.match(wizardScript, /<label for="\$\{id\}">/);
  assert.match(wizardScript, /required-badge/);

  assert.match(styles, /\.field label/);
  assert.match(styles, /\.required-badge/);
});


test('Credential Wizard renders OAuth waiting UX metadata', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /oauth-info/);
  assert.match(wizardScript, /data-oauth-login-start/);
  assert.match(wizardScript, /t\('wizard\.connecting'\)/);
  assert.match(wizardScript, /state\.oauthPending/);
  assert.match(wizardScript, /disabled/);

  assert.match(styles, /\.oauth-info/);
});

test('Credential Wizard renders finish screen UX metadata', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /summary-ready/);
  assert.match(wizardScript, /t\('wizard\.ready'\)/);
  assert.match(wizardScript, /t\('wizard\.step\.selectAuth'\)/);
  assert.match(wizardScript, /authTypeLabel\(providerAuthType\(\)\)/);

  assert.match(styles, /\.summary-ready/);
});

test('Credential Wizard renders dedicated credential creation success and failure outcomes', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardScript, /function renderCreationOutcome/);
  assert.match(wizardScript, /wizard\.integration\.credentialReady/);
  assert.match(wizardScript, /wizard\.integration\.grantRequired/);
  assert.match(wizardScript, /wizard\.createFailed/);
  assert.match(wizardScript, /CREDENTIAL_CREATE_FAILED/);
  assert.match(wizardScript, /data-action="edit-credential"/);
  assert.match(wizardScript, /renderConsumerGrantPanel\(\)/);
  assert.doesNotMatch(wizardScript, /result\.textContent = JSON\.stringify\(body/);
  assert.match(styles, /\.creation-error/);
});

test('Dashboard uses one Dashboard API model for overview and management widgets', () => {
  const dashboardHtml = fs.readFileSync(path.resolve('public/admin/dashboard.html'), 'utf8');
  const dashboardScript = fs.readFileSync(path.resolve('public/admin/dashboard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(dashboardHtml, /management-summary/);
  assert.match(dashboardHtml, /management-system-status/);
  assert.match(dashboardHtml, /management-credentials-total/);
  assert.match(dashboardHtml, /management-providers-total/);
  assert.match(dashboardHtml, /management-scheduler-state/);
  assert.match(dashboardHtml, /integration-health-heading/);
  assert.match(dashboardHtml, /integration-health-list/);

  assert.match(dashboardScript, /function loadDashboard/);
  assert.match(dashboardScript, /\/api\/v1\/dashboard/);
  assert.match(dashboardScript, /function renderDashboard/);
  assert.match(dashboardScript, /dashboard-credentials/);
  assert.match(dashboardScript, /management-credentials-total/);
  assert.match(dashboardScript, /function renderIntegrationHealth/);
  assert.match(dashboardScript, /integration-health-/);
  assert.match(dashboardScript, /dashboard\.integration\./);
  assert.match(dashboardScript, /status\.textContent = t\('dashboard\.ready'\)/);

  assert.match(styles, /\.management-grid/);
  assert.match(styles, /\.management-card/);
  assert.match(styles, /\.integration-health-card/);
});

test('Dashboard renders the public OAuth registration details', () => {
  const dashboardHtml = fs.readFileSync(path.resolve('public/admin/dashboard.html'), 'utf8');
  const dashboardScript = fs.readFileSync(path.resolve('public/admin/dashboard.js'), 'utf8');

  assert.match(dashboardHtml, /dashboard-oauth-details/);
  assert.match(dashboardScript, /\/api\/v1\/providers/);
  assert.match(dashboardScript, /function renderOAuthDetails/);
  assert.match(dashboardScript, /oauthTechnical\.redirectUri/);
  assert.match(dashboardScript, /oauthTechnical\.authorizationEndpoint/);
  assert.match(dashboardScript, /oauthTechnical\.callbackPath/);
  assert.match(dashboardScript, /defaultScopes/);
  assert.match(dashboardScript, /code\.textContent/);
});


test('Dashboard links to API token management page', () => {
  const dashboardHtml = fs.readFileSync(path.resolve('public/admin/dashboard.html'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(dashboardHtml, /api-tokens\.html/);
  assert.match(dashboardHtml, /API Tokens/);
  assert.match(styles, /\.management-link/);
});

test('API token admin page renders overview shell', () => {
  const apiTokenHtml = fs.readFileSync(path.resolve('public/admin/api-tokens.html'), 'utf8');
  const apiTokenScript = fs.readFileSync(path.resolve('public/admin/api-tokens.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(apiTokenHtml, /API-Token-Übersicht/);
  assert.match(apiTokenHtml, /api-token-table-body/);
  assert.match(apiTokenHtml, /api-tokens\.js/);
  assert.match(apiTokenScript, /function loadApiTokens/);
  assert.match(apiTokenScript, /\/api\/v1\/management\/api-tokens/);
  assert.match(apiTokenScript, /from '\.\/auth\.js'/);
  assert.match(apiTokenScript, /adminApi\.get/);
  assert.doesNotMatch(apiTokenScript, /x-credential-hub-user/);
  assert.match(apiTokenScript, /function renderApiTokens/);
  assert.match(apiTokenHtml, /apiTokens\.purposeHelp/);
  assert.match(apiTokenHtml, /apiTokens\.scopeHelp/);
  assert.match(apiTokenHtml, /apiTokens\.grantRelationship/);
  assert.match(apiTokenScript, /token\.userId/);
  assert.match(apiTokenScript, /apiTokens\.technicalId/);
  assert.match(apiTokenScript, /function statusLabel/);
  assert.doesNotMatch(apiTokenScript, /tokenHash/);
  assert.match(styles, /\.data-table/);
  assert.match(styles, /\.status-pill/);
});

test('admin layout lets responsive table containers handle narrow-screen overflow', () => {
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(styles, /\.layout > \* \{ min-width: 0; \}/);
  assert.match(styles, /\.table-card \{[\s\S]*?overflow-x: auto;/);
});


test('API token admin page renders create token dialog and one-time secret handling', () => {
  const apiTokenHtml = fs.readFileSync(path.resolve('public/admin/api-tokens.html'), 'utf8');
  const apiTokenScript = fs.readFileSync(path.resolve('public/admin/api-tokens.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(apiTokenHtml, /create-api-token-form/);
  assert.match(apiTokenHtml, /api-token-name/);
  assert.match(apiTokenHtml, /api-token-user-id/);
  assert.match(apiTokenHtml, /api-token-expires-at/);
  assert.match(apiTokenHtml, /api-token-scopes/);
  assert.match(apiTokenHtml, /created-api-token-value/);
  assert.match(apiTokenHtml, /nicht erneut angezeigt/);

  assert.match(apiTokenScript, /function createApiToken/);
  assert.match(apiTokenScript, /adminApi\.post/);
  assert.match(apiTokenScript, /function parseScopes/);
  assert.match(apiTokenScript, /function showCreatedToken/);
  assert.match(apiTokenScript, /navigator\.clipboard\.writeText/);
  assert.doesNotMatch(apiTokenScript, /tokenHash/);

  assert.match(styles, /\.dialog-card/);
  assert.match(styles, /\.success-card/);
});

test('API token admin page renders revoke token dialog and DELETE integration', () => {
  const apiTokenHtml = fs.readFileSync(path.resolve('public/admin/api-tokens.html'), 'utf8');
  const apiTokenScript = fs.readFileSync(path.resolve('public/admin/api-tokens.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(apiTokenHtml, /revoke-api-token-panel/);
  assert.match(apiTokenHtml, /revoke-api-token-confirm/);
  assert.match(apiTokenHtml, /API-Token widerrufen/);
  assert.match(apiTokenHtml, /colspan="10"/);

  assert.match(apiTokenScript, /function revokeApiToken/);
  assert.match(apiTokenScript, /adminApi\.delete/);
  assert.match(apiTokenScript, /encodeURIComponent\(tokenId\)/);
  assert.match(apiTokenScript, /data-action="revoke-api-token"/);
  assert.match(apiTokenScript, /function openRevokeDialog/);
  assert.match(apiTokenScript, /function confirmRevokeToken/);
  assert.match(apiTokenScript, /await loadApiTokens\(\)/);
  assert.doesNotMatch(apiTokenScript, /tokenHash/);

  assert.match(styles, /\.danger-card/);
  assert.match(styles, /button\.danger/);
});

test('Dashboard links to Credential transfer page', () => {
  const dashboardHtml = fs.readFileSync(path.resolve('public/admin/dashboard.html'), 'utf8');

  assert.match(dashboardHtml, /credential-transfer\.html/);
  assert.match(dashboardHtml, /data-i18n="nav\.transfer"/);
  assert.match(dashboardHtml, /data-i18n="dashboard\.transferHelp"/);
});

test('Dashboard and Credential Wizard provide direct navigation between both views', () => {
  const dashboardHtml = fs.readFileSync(path.resolve('public/admin/dashboard.html'), 'utf8');
  const wizardHtml = fs.readFileSync(path.resolve('public/admin/index.html'), 'utf8');
  const shellScript = fs.readFileSync(path.resolve('public/admin/admin-shell.js'), 'utf8');

  assert.match(dashboardHtml, /Credential Wizard/);
  assert.match(dashboardHtml, /data-app-path="\/admin\/"/);
  assert.match(wizardHtml, /app-navigation/);
  assert.match(shellScript, /applicationPath\('\/admin\/dashboard\.html'\)/);
  assert.match(shellScript, /applicationPath\('\/admin\/'\)/);
});

test('Credential Wizard keeps management and consumer tokens in memory while provisioning least-privilege grants', () => {
  const wizardHtml = fs.readFileSync(path.resolve('public/admin/index.html'), 'utf8');
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(wizardHtml, /app-navigation/);
  assert.match(wizardHtml, /consumer-grant-panel/);
  assert.match(wizardScript, /managementTokenStore/);
  assert.match(wizardScript, /consumerApi\.request/);
  assert.doesNotMatch(wizardScript, /x-credential-hub-user/);
  assert.match(wizardScript, /\/api\/v1\/management\/api-tokens/);
  assert.match(wizardScript, /\/api\/v1\/management\/consumer-grants/);
  assert.match(wizardScript, /\/api\/v1\/management\/consumer-grants\/diagnose/);
  assert.match(wizardScript, /consumerTokenPlaintext/);
  assert.doesNotMatch(wizardScript, /localStorage\.(setItem|getItem).*token/i);
  assert.match(styles, /\.consumer-grant-panel/);
  assert.match(styles, /\.grant-warning/);
});

test('Credential Wizard synchronizes the exact current grant configuration before Resolve verification', () => {
  const wizardScript = fs.readFileSync(path.resolve('public/admin/wizard.js'), 'utf8');
  const synchronization = fs.readFileSync(path.resolve('public/admin/grant-synchronization.js'), 'utf8');
  const attempt = fs.readFileSync(path.resolve('public/admin/grant-attempt.js'), 'utf8');

  assert.match(wizardScript, /savedGrant: null/);
  assert.doesNotMatch(wizardScript, /grantSaved/);
  assert.match(wizardScript, /from '\.\/grant-synchronization\.js'/);
  assert.match(synchronization, /export function normalizeSecretNames/);
  assert.match(synchronization, /export function sameGrantConfiguration/);
  assert.match(synchronization, /\/api\/v1\/management\/consumer-grants\?\$\{query\.toString\(\)\}/);
  assert.match(synchronization, /method: 'PUT'/);
  assert.match(synchronization, /CONSUMER_GRANT_DUPLICATE/);
  assert.match(wizardScript, /from '\.\/grant-attempt\.js'/);
  assert.match(wizardScript, /const grantAttempt = \+\+state\.integration\.grantAttempt/);
  assert.match(attempt, /if \(!isCurrentAttempt\(\)\) return \{ status: 'stale' \};[\s\S]*commitSavedGrant/);
  assert.match(attempt, /verifyResolve\(\{ consumerToken, configuration: savedGrant \}\)/);
  assert.match(wizardScript, /sameGrantConfiguration\(verification, current\)[\s\S]*sameGrantConfiguration\(state\.integration\.savedGrant, current\)/);
  assert.match(wizardScript, /const consumerToken = enteredToken \|\| state\.consumerTokenPlaintext/);
  assert.match(wizardScript, /commitVerification: \(verifiedConfiguration\)/);
  assert.match(wizardScript, /isCurrentAttempt = \(\) => grantAttempt === state\.integration\.grantAttempt/);
  assert.match(wizardScript, /#grant-consumer-id, \[data-grant-secret\]/);
  assert.match(wizardScript, /wizard\.grant\.changed/);
  assert.match(wizardScript, /wizard\.grant\.resolveFailed/);
  assert.match(wizardScript, /wizard\.grant\.saveFailed/);
});

test('Credential transfer admin page renders export and import shell', () => {
  const transferHtml = fs.readFileSync(path.resolve('public/admin/credential-transfer.html'), 'utf8');
  const transferScript = fs.readFileSync(path.resolve('public/admin/credential-transfer.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');

  assert.match(transferHtml, /Credential Export \/ Import/);
  assert.match(transferHtml, /credential-export-form/);
  assert.match(transferHtml, /credential-import-form/);
  assert.match(transferHtml, /import-source-format/);
  assert.match(transferHtml, /data-i18n="transfer\.csv"/);
  assert.match(transferHtml, /providerKey, externalReference/);
  assert.match(transferHtml, /import-preview-panel/);
  assert.match(transferHtml, /credential-transfer\.js/);

  assert.match(transferScript, /function exportCredentials/);
  assert.match(transferScript, /\/api\/v1\/credentials\/export/);
  assert.match(transferScript, /function previewImport/);
  assert.match(transferScript, /\/api\/v1\/credentials\/import\/preview/);
  assert.match(transferScript, /function importCredentials/);
  assert.match(transferScript, /\/api\/v1\/credentials\/import/);
  assert.match(transferScript, /encryptionPassword/);
  assert.match(transferScript, /sourceFormat/);
  assert.match(transferScript, /updateImportFormatUi/);
  assert.match(transferScript, /downloadTextFile/);

  assert.match(styles, /\.preview-panel/);
  assert.match(styles, /\.credential-selection-card/);
  assert.match(styles, /\.success-alert/);
});

test('Credential transfer UI invalidates a preview whenever import-affecting input changes', () => {
  const transferScript = fs.readFileSync(path.resolve('public/admin/credential-transfer.js'), 'utf8');

  assert.match(transferScript, /importContentInput\?\.addEventListener\('input', \(\) => resetPreview\(\)\)/);
  assert.match(transferScript, /importPasswordInput\?\.addEventListener\('input', \(\) => resetPreview\(\)\)/);
  assert.match(transferScript, /importConflictStrategyInput\?\.addEventListener\('change', \(\) => resetPreview\(\)\)/);
  assert.match(transferScript, /lastPreviewFingerprint = fingerprint/);
  assert.match(transferScript, /lastPreviewFingerprint !== await fingerprintImportPayload\(payload\)/);
  assert.match(transferScript, /lastPreviewFingerprint = null/);
});

test('admin UI serves the Credential transfer shell', async () => {
  const httpServer = createServer();
  const { server, baseUrl } = await listen(httpServer.app);

  try {
    const response = await fetch(`${baseUrl}/admin/credential-transfer.html`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /text\/html/);
    assert.match(body, /Credential Export \/ Import/);
    assert.match(body, /credential-transfer\.js/);
  } finally {
    server.close();
  }
});

test('Admin pages expose a persistent, localized administration context indicator', () => {
  const adminScripts = ['wizard.js', 'dashboard.js', 'credentials.js', 'consumer-grants.js', 'api-tokens.js', 'credential-transfer.js', 'providers.js'];
  for (const file of adminScripts) {
    const script = fs.readFileSync(path.resolve('public/admin', file), 'utf8');
    assert.match(script, /mountAdminShell\(\)/, `${file} must mount the shared admin shell`);
  }

  const shell = fs.readFileSync(path.resolve('public/admin/admin-shell.js'), 'utf8');
  const styles = fs.readFileSync(path.resolve('public/admin/styles.css'), 'utf8');
  const english = fs.readFileSync(path.resolve('public/admin/locales/en.js'), 'utf8');
  const german = fs.readFileSync(path.resolve('public/admin/locales/de.js'), 'utf8');
  const consumerHtml = fs.readFileSync(path.resolve('public/consumer/index.html'), 'utf8');
  const consumerStyles = fs.readFileSync(path.resolve('public/consumer/styles.css'), 'utf8');

  assert.match(shell, /id = 'admin-context-indicator'/);
  assert.match(shell, /admin\.context\.label/);
  assert.match(shell, /admin\.context\.help/);
  assert.match(shell, /renderAdminContext\(\)/);
  assert.match(styles, /\.admin-context-indicator/);
  assert.match(styles, /border: 2px solid #7c2d12/);
  assert.match(english, /'admin\.context\.label': 'ADMIN AREA'/);
  assert.match(german, /'admin\.context\.label': 'ADMIN-BEREICH'/);
  assert.doesNotMatch(consumerHtml, /admin-context-indicator/);
  assert.doesNotMatch(consumerStyles, /admin-context-indicator/);
});

test('Dashboard separates credential and provider breakdowns and details warnings', () => {
  const dashboardHtml = fs.readFileSync(path.resolve('public/admin/dashboard.html'), 'utf8');
  const dashboardScript = fs.readFileSync(path.resolve('public/admin/dashboard.js'), 'utf8');

  assert.match(dashboardHtml, /management-credentials-methods/);
  assert.match(dashboardHtml, /management-provider-credentials/);
  assert.match(dashboardScript, /function renderCountList/);
  assert.match(dashboardScript, /function renderWarnings/);
  assert.match(dashboardScript, /openCredentials/);
});

test('Admin authentication restores the full shell after an existing token is validated', () => {
  const authScript = fs.readFileSync(path.resolve('public/admin/auth.js'), 'utf8');

  assert.match(authScript, /await adminApi\.get\('\/api\/v1\/dashboard'\);\n\s+setAdminAuthenticated\(true\);/);
  assert.match(authScript, /function setAdminAuthenticated\(authenticated\)/);
  assert.match(authScript, /for \(const selector of \['\.layout', '\.app-footer', '#app-navigation'\]\)/);
  assert.match(authScript, /classList\.toggle\('hidden', !authenticated\)/);
  assert.doesNotMatch(authScript, /document\.querySelector\('\.layout'\)\?\.classList\.remove\('hidden'\)/);
  assert.doesNotMatch(authScript, /document\.querySelector\('\.app-footer'\)\?\.classList\.remove\('hidden'\)/);
  assert.doesNotMatch(authScript, /document\.querySelector\('#app-navigation'\)\?\.classList\.remove\('hidden'\)/);
});
