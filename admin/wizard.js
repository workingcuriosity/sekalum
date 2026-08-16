const wizardStates = Object.freeze({
  SELECT_PROVIDER: 'SELECT_PROVIDER',
  CONFIGURE: 'CONFIGURE',
  AUTHORIZE: 'AUTHORIZE',
  WAIT_CALLBACK: 'WAIT_CALLBACK',
  SUCCESS: 'SUCCESS',
  ERROR: 'ERROR'
});

const stepStateMap = Object.freeze({
  1: wizardStates.SELECT_PROVIDER,
  2: wizardStates.SELECT_PROVIDER,
  3: wizardStates.CONFIGURE,
  4: wizardStates.AUTHORIZE,
  5: wizardStates.SUCCESS
});

const wizardStepLabels = Object.freeze({
  1: 'Typ auswählen',
  2: 'Provider auswählen',
  3: 'Credential-Daten erfassen',
  4: 'OAuth autorisieren',
  5: 'Zusammenfassung'
});

const state = {
  step: 1,
  flowState: wizardStates.SELECT_PROVIDER,
  type: null,
  provider: null,
  providers: [],
  meta: null,
  formData: {}
};

const credentialTypes = [
  { key: 'oauth', title: 'OAuth', description: 'Für Google, Twitch, Kick, Discord, X, Facebook, Instagram und Threads.', tags: ['Redirect', 'State', 'PKCE optional'] },
  { key: 'api-key', title: 'API-Key', description: 'Für API-Schlüssel wie OpenAI.', tags: ['Secret', 'Validate', 'Health Check'] },
  { key: 'connection', title: 'Connection', description: 'Für Verbindungen wie FTP und SFTP.', tags: ['Host', 'Port', 'Benutzer'] }
];

const typeCapabilityMap = {
  oauth: ['oauth'],
  'api-key': ['validation'],
  connection: ['connection-validation', 'validation']
};

const providerFieldCatalog = {
  oauth: {
    default: [
      { name: 'displayName', label: 'Anzeigename', required: true, placeholder: 'z. B. Google Hauptkonto', group: 'Basisdaten' },
      { name: 'description', label: 'Beschreibung', required: false, placeholder: 'Optionaler Hinweis für die Verwaltung', group: 'Basisdaten' }
    ]
  },
  'api-key': {
    default: [
      { name: 'displayName', label: 'Anzeigename', required: true, group: 'Basisdaten' },
      { name: 'apiKey', label: 'API-Key', required: true, secret: true, group: 'Secret' }
    ],
    openai: [
      { name: 'displayName', label: 'Anzeigename', required: true, placeholder: 'z. B. OpenAI Produktion', group: 'Basisdaten' },
      { name: 'apiKey', label: 'OpenAI API-Key', required: true, secret: true, group: 'Secret', help: 'Der Schlüssel wird verschlüsselt gespeichert und nicht wieder angezeigt.' },
      { name: 'organization', label: 'Organisation', required: false, group: 'Optionale OpenAI-Felder' },
      { name: 'project', label: 'Projekt', required: false, group: 'Optionale OpenAI-Felder' }
    ]
  },
  connection: {
    default: [
      { name: 'displayName', label: 'Anzeigename', required: true, group: 'Basisdaten' },
      { name: 'host', label: 'Host', required: true, group: 'Verbindung' },
      { name: 'port', label: 'Port', required: false, type: 'number', group: 'Verbindung' },
      { name: 'username', label: 'Benutzername', required: true, group: 'Authentifizierung' },
      { name: 'password', label: 'Passwort', required: false, secret: true, group: 'Authentifizierung' },
      { name: 'privateKey', label: 'Private Key', required: false, secret: true, multiline: true, group: 'Authentifizierung' }
    ],
    ftp: [
      { name: 'displayName', label: 'Anzeigename', required: true, placeholder: 'z. B. FTP Webspace', group: 'Basisdaten' },
      { name: 'host', label: 'FTP-Host', required: true, group: 'Verbindung' },
      { name: 'port', label: 'Port', required: false, type: 'number', placeholder: '21', group: 'Verbindung' },
      { name: 'username', label: 'Benutzername', required: true, group: 'Authentifizierung' },
      { name: 'password', label: 'Passwort', required: true, secret: true, group: 'Authentifizierung' }
    ],
    sftp: [
      { name: 'displayName', label: 'Anzeigename', required: true, placeholder: 'z. B. SFTP Backup-Ziel', group: 'Basisdaten' },
      { name: 'host', label: 'SFTP-Host', required: true, group: 'Verbindung' },
      { name: 'port', label: 'Port', required: false, type: 'number', placeholder: '22', group: 'Verbindung' },
      { name: 'username', label: 'Benutzername', required: true, group: 'Authentifizierung' },
      { name: 'password', label: 'Passwort', required: false, secret: true, group: 'Authentifizierung' },
      { name: 'privateKey', label: 'Private Key', required: false, secret: true, multiline: true, group: 'Authentifizierung', help: 'Für spätere SSH-Key-Unterstützung vorbereitet; das Backend entscheidet, ob der Provider das Secret akzeptiert.' }
    ]
  }
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'content-type': 'application/json', ...(options.headers ?? {}) },
    ...options
  });
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) {
    const message = body?.error?.message ?? body ?? `HTTP ${response.status}`;
    throw new Error(message);
  }
  return body;
}

function showError(message) {
  const el = $('#wizard-error');
  el.textContent = message;
  el.classList.remove('hidden');
}

function clearError() {
  $('#wizard-error').classList.add('hidden');
}

function transitionWizardState(flowState) {
  state.flowState = flowState;
  document.body.dataset.wizardState = flowState;
}

function isOAuthCredential() {
  return state.type === 'oauth';
}

function nextStepForCurrentState() {
  if (state.step === 3 && isOAuthCredential()) return 4;
  if (state.step === 3) return 5;
  if (state.step === 4) return 5;
  return Math.min(5, state.step + 1);
}

function previousStepForCurrentState() {
  if (state.step === 5 && !isOAuthCredential()) return 3;
  return Math.max(1, state.step - 1);
}

function renderWizardProgress() {
  const current = $('#wizard-progress-current');
  const label = $('#wizard-progress-label');
  const bar = $('#wizard-progress-bar');

  if (!current || !label || !bar) {
    return;
  }

  current.textContent = `Schritt ${state.step} von 5`;
  label.textContent = wizardStepLabels[state.step] ?? 'Wizard';
  bar.style.width = `${(state.step / 5) * 100}%`;
  bar.setAttribute('aria-valuenow', String(state.step));
}

function setStep(step) {
  state.step = step;
  renderWizardProgress(); 
 transitionWizardState(stepStateMap[step] ?? wizardStates.ERROR);
  $$('.wizard-step').forEach((el) => el.classList.toggle('hidden', Number(el.dataset.step) !== step));
  $$('[data-step-indicator]').forEach((el) => el.classList.toggle('active', Number(el.dataset.stepIndicator) === step));
  $$('[data-action="back"]').forEach((button) => button.disabled = step === 1);
  $$('[data-action="next"]').forEach((button) => button.classList.toggle('hidden', step === 5));
  clearError();
}

const oauthCallbackResult = readOAuthCallbackResult();
applyOAuthCallbackResult(oauthCallbackResult);


function renderTypeOptions() {
  $('#type-options').innerHTML = credentialTypes.map((type) => `
    <button class="option-card ${state.type === type.key ? 'selected' : ''}" type="button" data-type="${type.key}">
      <h3>${type.title}</h3>
      <p>${type.description}</p>
      <span class="tags">${type.tags.map((tag) => `<span class="tag">${tag}</span>`).join('')}</span>
    </button>
  `).join('');
}

function providerType(provider) {
  const caps = provider.capabilities ?? [];
  if (caps.includes('oauth')) return 'oauth';
  if (provider.key === 'openai' || provider.providerKey === 'openai') return 'api-key';
  if (caps.includes('connection-validation') || ['ftp', 'sftp'].includes(provider.key ?? provider.providerKey)) return 'connection';
  return 'unknown';
}

function matchesSelectedType(provider) {
  if (!state.type) return true;
  if (providerType(provider) === state.type) return true;
  const required = typeCapabilityMap[state.type] ?? [];
  const caps = provider.capabilities ?? [];
  return required.some((capability) => caps.includes(capability));
}

function providerTypeLabel(type) {
  switch (type) {
    case 'oauth':
      return 'OAuth';
    case 'api-key':
      return 'API-Key';
    case 'connection':
      return 'Connection';
    default:
      return 'Unbekannt';
  }
}

function renderProviders() {
  const search = ($('#provider-search')?.value ?? '').trim().toLowerCase();
  const providers = state.providers
    .filter(matchesSelectedType)
    .filter((provider) => `${provider.displayName ?? provider.key} ${provider.description ?? ''}`.toLowerCase().includes(search));

  $('#provider-options').innerHTML = providers.map((provider) => {
    const key = provider.key ?? provider.providerKey;
    const type = providerType(provider);

    return `
      <button class="option-card ${state.provider?.key === key ? 'selected' : ''}" type="button" data-provider="${key}">
        <div class="option-card-header">
          <div>
            <h3>${provider.displayName ?? key}</h3>
            <span class="provider-key">${key}</span>
          </div>
          <span class="provider-type-badge">${providerTypeLabel(type)}</span>
        </div>
        <p>${provider.description ?? 'Kein Beschreibungstext vorhanden.'}</p>
        <span class="tags">${(provider.capabilities ?? []).slice(0, 4).map((cap) => `<span class="tag">${cap}</span>`).join('')}</span>
      </button>
    `;
  }).join('') || `
    <div class="empty-state">
      <h3>Keine passenden Provider gefunden</h3>
      <p>Ändere den Suchbegriff oder wähle einen anderen Credential-Typ.</p>
    </div>
  `;
}


function providerKey(provider = state.provider) {
  return provider?.key ?? provider?.providerKey ?? null;
}

function providerCapabilities(provider = state.provider) {
  return provider?.capabilities ?? [];
}

function buildOAuthLoginUrl(provider = state.provider) {
  const key = providerKey(provider);
  if (!key) return '#';
  return `/oauth/${encodeURIComponent(key)}/login`;
}

function markOAuthRedirectStarted() {
  transitionWizardState(wizardStates.WAIT_CALLBACK);
}

function readOAuthCallbackResult(search = window.location.search) {
  const params = new URLSearchParams(search);

  const status = params.get('oauth');
  if (!status) {
    return null;
  }

  return {
    status,
    provider: params.get('provider'),
    credentialId: params.get('credentialId')
  };
}

function applyOAuthCallbackResult(result) {
  if (!result) {
    return;
  }

  switch (result.status) {
    case 'success':
      transitionWizardState(wizardStates.SUCCESS);
      break;

    case 'error':
      transitionWizardState(wizardStates.ERROR);
      break;

    case 'cancelled':
      transitionWizardState(wizardStates.CONFIGURE);
      break;
  }

  state.oauthResult = result;
}

function getProviderFieldSet(type = state.type, provider = state.provider) {
  const catalog = providerFieldCatalog[type] ?? {};
  const key = providerKey(provider);
  return catalog[key] ?? catalog.default ?? [];
}

function groupFields(fields) {
  return fields.reduce((groups, field) => {
    const group = field.group ?? 'Credential-Daten';
    groups[group] = groups[group] ?? [];
    groups[group].push(field);
    return groups;
  }, {});
}

function autocompleteForField(field) {
  if (field.autocomplete) return field.autocomplete;
  if (field.secret) return 'current-password';
  if (field.name === 'username') return 'username';
  if (field.name === 'displayName') return 'off';
  return 'off';
}

function renderField(field) {
  const required = field.required ? 'required' : '';
  const placeholder = field.placeholder ? `placeholder="${field.placeholder}"` : '';
  const autocomplete = `autocomplete="${autocompleteForField(field)}"`;
  const fieldId = `credential-field-${field.name}`;
  const help = field.help ?? (field.secret ? 'Wird nur an das Backend übertragen und dort verschlüsselt gespeichert.' : '');
  const control = field.multiline
    ? `<textarea id="${fieldId}" name="${field.name}" ${required} ${placeholder} ${autocomplete}></textarea>`
    : `<input id="${fieldId}" name="${field.name}" type="${field.secret ? 'password' : field.type ?? 'text'}" ${required} ${placeholder} ${autocomplete}>`;

  return `
    <div class="field">
      <label for="${fieldId}">
        <span>${field.label}</span>
        ${field.required ? '<span class="required-badge">Pflichtfeld</span>' : ''}
      </label>
      ${control}
      ${help ? `<small class="field-help">${help}</small>` : ''}
    </div>
  `;
}

function renderProviderContext() {
  const provider = state.provider;
  const key = providerKey(provider);
  const caps = providerCapabilities(provider);
  const type = providerType(provider);
  const oauthSecurity = provider?.oauthSecurity ?? provider?.security ?? null;
  const securityTags = oauthSecurity
    ? Object.entries(oauthSecurity).map(([name, value]) => `<span class="tag">${name}: ${value}</span>`).join('')
    : '';

  $('#provider-context').innerHTML = `
    <article class="provider-context-card">
      <h3>${provider?.displayName ?? key}</h3>
      <p>${provider?.description ?? 'Die Eingabemaske wurde aus Provider-Typ, Provider-Key und Capabilities abgeleitet.'}</p>
      <span class="tags">
        <span class="tag">Typ: ${type}</span>
        ${caps.slice(0, 6).map((capability) => `<span class="tag">${capability}</span>`).join('')}
        ${securityTags}
      </span>
    </article>
  `;
}

function renderForm() {
  const providerName = state.provider?.displayName ?? state.provider?.key ?? 'Provider';
  $('#credential-form-title').textContent = `${providerName}: Credential-Daten`;
  renderProviderContext();
  const groupedFields = groupFields(getProviderFieldSet());
  $('#credential-form').innerHTML = Object.entries(groupedFields).map(([group, fields]) => `
    <fieldset class="field-group">
      <legend>${group}</legend>
      ${fields.map(renderField).join('')}
    </fieldset>
  `).join('');
}

function collectFormData() {
  const form = $('#credential-form');
  if (!form.reportValidity()) return false;
  state.formData = Object.fromEntries(new FormData(form).entries());
  return true;
}

function credentialPayload() {
  const providerKey = state.provider?.key ?? state.provider?.providerKey;
  const displayName = state.formData.displayName;
  const base = {
    providerKey,
    externalReference: displayName,
    lifecycleState: 'registered',
    metadata: {
      displayName,
      description: state.formData.description ?? null,
      type: state.type,
      providerName: state.provider?.displayName ?? providerKey
    },
    secrets: []
  };

  if (state.type === 'api-key') {
    base.secrets.push({ name: 'apiKey', value: state.formData.apiKey, type: 'api-key', required: true });
    if (state.formData.organization) base.secrets.push({ name: 'organization', value: state.formData.organization, required: false });
    if (state.formData.project) base.secrets.push({ name: 'project', value: state.formData.project, required: false });
  }

  if (state.type === 'connection') {
    for (const name of ['host', 'port', 'username', 'password', 'privateKey']) {
      if (state.formData[name]) base.secrets.push({ name, value: state.formData[name], required: ['host', 'username'].includes(name) });
    }
  }

  return base;
}

function renderOAuthAuthorizationStep() {
  const provider = state.provider;
  const providerName = provider?.displayName ?? providerKey(provider);
  const oauthSecurity = provider?.oauthSecurity ?? provider?.security ?? {};
  const loginUrl = buildOAuthLoginUrl(provider);
  const securityRows = Object.keys(oauthSecurity).length
    ? Object.entries(oauthSecurity).map(([name, value]) => `<span class="tag">${name}: ${value}</span>`).join('')
    : '<span class="tag">Standard OAuth-Schutz aktiv</span>';

  $('#oauth-authorization').innerHTML = `
    <article class="provider-context-card">
      <h3>${providerName} autorisieren</h3>
      <p>Der Wizard startet den OAuth-Login über den bestehenden Backend-Endpunkt. Die Verbindung wird sicher aufgebaut. Alle erforderlichen Sicherheitsmechanismen werden automatisch angewendet.</p>
      <span class="tags">
        <span class="tag">Status: ${wizardStates.AUTHORIZE}</span>
        <span class="tag">Redirect: ${loginUrl}</span>
        ${securityRows}
      </span>

      <p class="oauth-info">
  Nach dem Klick öffnet sich der Anmeldebildschirm des Providers.
  Bitte dieses Fenster geöffnet lassen, bis die Autorisierung abgeschlossen ist.
</p>

      <div class="oauth-actions">
        <a class="primary" id="oauth-authorize-start" href="${loginUrl}" data-oauth-login-start>OAuth bei ${providerName} starten</a>
      </div>
      <p class="oauth-hint">Nach der Autorisierung verarbeitet der bestehende Callback-Endpunkt den Provider-Rückruf und importiert das Credential.</p>
    </article>
  `;
}

function renderSummary() {
  const providerKey = state.provider?.key ?? state.provider?.providerKey ?? '';
  const providerName = state.provider?.displayName ?? providerKey;
  const authenticationLabel = providerTypeLabel(providerType(state.provider));

  const rows = [
    ['Typ', state.type],
    ['Provider', `${providerName}${providerKey ? ` (${providerKey})` : ''}`],
    ['Authentifizierung', authenticationLabel],
    ['Name', state.formData.displayName ?? ''],
    ['Speicherweg', state.type === 'oauth' ? 'OAuth Redirect' : 'POST /api/v1/credentials']
  ];

  $('#summary').innerHTML = `
    <div class="summary-ready">
      <strong>Bereit zum Anlegen</strong>
      <span>Bitte prüfe die Angaben, bevor das Credential erstellt wird.</span>
    </div>
    ${rows.map(([label, value]) => `<div class="summary-row"><strong>${label}</strong><span>${value ?? ''}</span></div>`).join('')}
  `;

  const oauthStart = $('#oauth-start');
  const createButton = $('#create-credential');
  if (state.type === 'oauth') {
    oauthStart.href = `/oauth/${providerKey}/login`;
    oauthStart.classList.remove('hidden');
    createButton.classList.add('hidden');
  } else {
    oauthStart.classList.add('hidden');
    createButton.classList.remove('hidden');
  }
}

async function createCredential() {
  clearError();
  const result = $('#create-result');
  result.classList.add('hidden');
  try {
    const body = await api('/api/v1/credentials', {
      method: 'POST',
      body: JSON.stringify(credentialPayload())
    });
    result.textContent = JSON.stringify(body, null, 2);
    result.classList.remove('hidden');
  } catch (error) {
    showError(error.message);
  }
}

async function bootstrapWizard() {
  try {
    const [health, providers, meta] = await Promise.all([
      api('/health'),
      api('/api/v1/providers'),
      api('/api/v1/credentials/meta')
    ]);
    $('#api-status').textContent = health.status === 'UP' ? 'API verbunden' : 'API unklar';
    state.providers = providers.data ?? [];
    state.meta = meta.data;
    renderTypeOptions();
    renderProviders();
    setStep(1);
  } catch (error) {
    $('#api-status').textContent = 'API nicht erreichbar';
    $('#api-status').classList.add('down');
    showError(error.message);
  }
}

document.addEventListener('click', (event) => {
  if (event.target.closest('[data-oauth-login-start]')) {
  const link = event.target.closest('[data-oauth-login-start]');

link.classList.add('disabled');
link.textContent = 'Verbindung wird aufgebaut …';

const info = document.querySelector('.oauth-info');
if (info) {
  info.textContent =
    'Die Verbindung wird aufgebaut. Bitte dieses Fenster geöffnet lassen.';
}  
  markOAuthRedirectStarted();
    return;
  }

  const typeButton = event.target.closest('[data-type]');
  if (typeButton) {
    state.type = typeButton.dataset.type;
    state.provider = null;
    renderTypeOptions();
    renderProviders();
    setStep(2);
    return;
  }

  const providerButton = event.target.closest('[data-provider]');
  if (providerButton) {
    const key = providerButton.dataset.provider;
    state.provider = state.providers.find((provider) => (provider.key ?? provider.providerKey) === key);
    renderProviders();
    renderForm();
    setStep(3);
    return;
  }

  if (event.target.matches('[data-action="back"]')) {
    setStep(previousStepForCurrentState());
    return;
  }

  if (event.target.matches('[data-action="next"]')) {
    if (state.step === 1 && !state.type) return showError('Bitte zuerst einen Credential-Typ auswählen.');
    if (state.step === 2 && !state.provider) return showError('Bitte zuerst einen Provider auswählen.');
    if (state.step === 3 && !collectFormData()) return;
    if (state.step === 3 && isOAuthCredential()) renderOAuthAuthorizationStep();
    if ((state.step === 3 && !isOAuthCredential()) || state.step === 4) renderSummary();
    setStep(nextStepForCurrentState());
  }
});

$('#provider-search').addEventListener('input', renderProviders);
$('#create-credential').addEventListener('click', createCredential);

await bootstrapWizard();
