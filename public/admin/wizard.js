// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { applicationPath } from './base-path.js';
import { adminApi, consumerApi, managementTokenStore } from './auth.js';
import { initI18n, onLanguageChange, t, translationOr, userFacingError } from './i18n.js';
import { mountAdminShell } from './admin-shell.js';
import { normalizeSecretNames, normalizedGrantConfiguration, sameGrantConfiguration, synchronizeGrant } from './grant-synchronization.js';
import { runGrantDiagnosisAttempt, runGrantResolveAttempt } from './grant-attempt.js';

initI18n();
await mountAdminShell();

const wizardStates = Object.freeze({
  SELECT_PROVIDER: 'SELECT_PROVIDER',
  CONFIGURE: 'CONFIGURE',
  AUTHORIZE: 'AUTHORIZE',
  WAIT_CALLBACK: 'WAIT_CALLBACK',
  CREDENTIAL_READY: 'CREDENTIAL_READY',
  GRANT_CONFIGURE: 'GRANT_CONFIGURE',
  INTEGRATION_COMPLETE: 'INTEGRATION_COMPLETE',
  ERROR: 'ERROR'
});

const wizardStepLabels = Object.freeze({
  1: 'wizard.step.selectAuth',
  2: 'wizard.step.selectProvider',
  3: 'wizard.step.captureCredentials',
  4: 'wizard.step.authorizeOAuth',
  5: 'wizard.step.review'
});

const state = {
  step: 1,
  flowState: wizardStates.SELECT_PROVIDER,
  authType: null,
  provider: null,
  credentialMethod: null,
  providers: [],
  meta: null,
  formData: {},
  hasUnsavedChanges: false,
  oauthWindow: null,
  oauthPending: false,
  oauthResult: null,
  oauthAttemptDetails: null,
  creationResult: null,
  connectionTest: null,
  connectionTestPending: false,
  consumerTokens: [],
  selectedConsumerId: null,
  consumerGrant: null,
  consumerTokenPlaintext: null,
  selectedSecretNames: [],
  integration: { credentialReady: false, savedGrant: null, verification: null, grantAttempt: 0 }
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

async function api(path, options = {}) {
  return adminApi.request(path, options);
}

function credentialIdFromOutcome(outcome = state.creationResult?.credential ?? state.oauthResult) {
  return outcome?.id ?? outcome?.credentialId ?? outcome?.credential?.id ?? null;
}

function credentialSecretNames(credential = state.creationResult?.credential) {
  const inventory = credential?.secretInventory ?? credential?.secrets ?? credential?.secretNames;
  const names = Array.isArray(inventory)
    ? inventory.map((secret) => typeof secret === 'string' ? secret : secret.name).filter(Boolean)
    : [];
  return [...new Set(names.length > 0 ? names : getProviderFieldSet().filter((field) => field.secret).map((field) => field.key))];
}

function consumerTokenRows(body) {
  const data = body?.data ?? body;
  return Array.isArray(data) ? data : (data?.items ?? data?.tokens ?? []);
}

async function loadConsumerTokens() {
  const body = await api('/api/v1/management/api-tokens');
  state.consumerTokens = consumerTokenRows(body).filter((token) => token.status === undefined || token.status === 'active');
  return state.consumerTokens;
}

function consumerTokenId(token) {
  return token?.id ?? token?.tokenId;
}

function consumerTokenLabel(token) {
  return token?.name ?? token?.displayName ?? consumerTokenId(token);
}

function grantTarget() {
  const credential = state.creationResult?.credential ?? state.oauthResult;
  return {
    credentialId: credentialIdFromOutcome(credential),
    providerKey: credential?.providerKey ?? providerKey(),
    secretNames: state.selectedSecretNames
  };
}

function currentGrantConfiguration() {
  const target = grantTarget();
  return normalizedGrantConfiguration({
    consumerId: state.selectedConsumerId,
    credentialId: target.credentialId,
    providerKey: target.providerKey,
    secretNames: state.selectedSecretNames
  });
}

function setSavedGrant(grant) {
  state.integration.savedGrant = normalizedGrantConfiguration(grant);
}

function invalidateGrantVerification(message = null) {
  state.integration.grantAttempt += 1;
  state.integration.verification = null;
  if (message) state.consumerGrant = { success: false, message };
}

function prepareCredentialIntegration(credentialId) {
  state.integration.grantAttempt += 1;
  if (state.integration.savedGrant?.credentialId && state.integration.savedGrant.credentialId !== credentialId) {
    state.integration.savedGrant = null;
    state.integration.verification = null;
    state.selectedConsumerId = null;
    state.selectedSecretNames = [];
  }
  state.integration.credentialReady = true;
}

function credentialReady() {
  return state.integration.credentialReady && Boolean(grantTarget().credentialId);
}

function integrationComplete() {
  const current = currentGrantConfiguration();
  const verification = state.integration.verification;
  return verification?.kind === 'resolve'
    && verification.success === true
    && sameGrantConfiguration(verification, current)
    && sameGrantConfiguration(state.integration.savedGrant, current);
}

function showError(message) {
  const element = $('#wizard-error');
  element.textContent = message && typeof message === 'object' ? userFacingError(message) : message;
  element.classList.remove('hidden');
}

function clearError() {
  $('#wizard-error').classList.add('hidden');
}

function providerKey(provider = state.provider) {
  return provider?.key ?? provider?.providerKey ?? null;
}

function providerAuthType(provider = state.provider) {
  return provider?.authType ?? 'custom';
}

function providerAuthGroup(provider = state.provider) {
  return providerAuthType(provider).startsWith('oauth2') ? 'oauth2' : providerAuthType(provider);
}

function providerCapabilities(provider = state.provider) {
  return provider?.capabilities ?? [];
}

function providerTechnicalTags(provider = state.provider) {
  return [
    ...providerCapabilities(provider),
    ...(provider?.defaultScopes ?? []).map((scope) => `scope: ${scope}`)
  ];
}

function oauthRegistrationDetails(provider = state.provider, attempt = state.oauthAttemptDetails) {
  if (!isOAuthProvider(provider)) return '';
  const technical = provider?.oauthTechnical ?? {};
  const callbackPath = attempt?.callbackPath
    ?? technical.callbackPath
    ?? applicationPath(`/oauth/${encodeURIComponent(providerKey(provider))}/callback`);
  const redirectUri = attempt?.redirectUri
    ?? technical.redirectUri
    ?? `${window.location.origin}${callbackPath}`;
  const authorizationUrl = attempt?.authorizationUrl ?? technical.authorizationEndpoint;
  const scopes = attempt?.scopes ?? state.formData.scopes ?? provider?.defaultScopes ?? [];
  const rows = [
    [t('wizard.oauth.redirectUri'), redirectUri],
    [attempt?.authorizationUrl ? t('wizard.oauth.authorizationUrl') : t('wizard.oauth.authorizationEndpoint'), authorizationUrl],
    [t('wizard.oauth.callbackPath'), callbackPath],
    [t('common.scopes'), scopes.length > 0 ? scopes.join(' ') : t('wizard.oauth.noScopes')]
  ].filter(([, value]) => value);
  return `<dl class="oauth-registration-details">${rows.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd><code>${escapeHtml(value)}</code></dd></div>`).join('')}</dl>`;
}

function providerDescription(provider = state.provider) {
  return translationOr(`provider.${providerKey(provider)}.description`, provider?.description ?? t('wizard.provider.noDescription'));
}

function selectedCredentialMethod() {
  return state.credentialMethod;
}

function isOAuthProvider(provider = state.provider) {
  if (!providerCapabilities(provider).includes('oauth')) return false;
  const method = selectedCredentialMethod();
  // Method-aware providers declare the OAuth input as part of the selected
  // method. This keeps the wizard independent of provider or method names.
  return !method || (method.credentialFields ?? []).some((field) => field.type === 'oauth-scope');
}

function supportsConnectionTest(provider = state.provider) {
  return providerCapabilities(provider).includes('validation');
}

function authTypeLabel(authType) {
  const key = `auth.${authType ?? 'custom'}`;
  return translationOr(key, humanize(authType ?? 'custom'));
}

function humanize(value) {
  const text = String(value ?? '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[-_]+/g, ' ').trim();
  return text ? `${text.charAt(0).toUpperCase()}${text.slice(1)}` : '';
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function transitionWizardState(flowState) {
  state.flowState = flowState;
  document.body.dataset.wizardState = flowState;
}

function nextStepForCurrentState() {
  if (state.step === 3 && isOAuthProvider()) return 4;
  if (state.step === 3 || state.step === 4) return 5;
  return Math.min(5, state.step + 1);
}

function previousStepForCurrentState() {
  if (state.step === 5 && !isOAuthProvider()) return 3;
  return Math.max(1, state.step - 1);
}

function renderWizardProgress() {
  $('#wizard-progress-current').textContent = t('wizard.stepOf', { step: state.step, total: 5 });
  $('#wizard-progress-label').textContent = t(wizardStepLabels[state.step] ?? 'wizard.title');
  const bar = $('#wizard-progress-bar');
  bar.style.width = `${(state.step / 5) * 100}%`;
  bar.setAttribute('aria-valuenow', String(state.step));
}

function setStep(step) {
  state.step = step;
  renderWizardProgress();
  transitionWizardState(step === 3 ? wizardStates.CONFIGURE : step === 4 ? wizardStates.AUTHORIZE : wizardStates.SELECT_PROVIDER);
  $$('.wizard-step').forEach((element) => element.classList.toggle('hidden', Number(element.dataset.step) !== step));
  $$('[data-step-indicator]').forEach((element) => element.classList.toggle('active', Number(element.dataset.stepIndicator) === step));
  $$('[data-action="back"]').forEach((button) => { button.disabled = step === 1; });
  $$('[data-action="next"]').forEach((button) => button.classList.toggle('hidden', step === 5 || (step === 4 && isOAuthProvider())));
  clearError();
}

function availableAuthTypes() {
  return [...new Set(state.providers.map((provider) => providerAuthGroup(provider)))].sort();
}

function renderAuthOptions() {
  $('#type-options').innerHTML = availableAuthTypes().map((authType) => {
    const providers = state.providers.filter((provider) => providerAuthGroup(provider) === authType);
    const count = providers.length;
    const preview = providers.slice(0, 4).map((provider) => provider.displayName ?? providerKey(provider)).join(' · ');
    return `
      <article class="auth-type-row ${state.authType === authType ? 'selected' : ''}">
        <div><h3>${escapeHtml(authTypeLabel(authType))}</h3><p>${t('wizard.provider.availableCount', { count })}</p><span>${escapeHtml(preview)}</span></div>
        <button class="primary" type="button" data-auth-type="${authType}" aria-pressed="${state.authType === authType}">${t('wizard.auth.select')}</button>
      </article>
  `;
  }).join('') || `<div class="empty-state"><h3>${t('wizard.provider.unavailable')}</h3><p>${t('wizard.provider.unavailableHelp')}</p></div>`;
}

function renderProviders() {
  const search = ($('#provider-search')?.value ?? '').trim().toLowerCase();
  const providers = state.providers
    .filter((provider) => providerAuthGroup(provider) === state.authType)
    .filter((provider) => `${provider.displayName ?? providerKey(provider)} ${providerKey(provider)} ${providerDescription(provider)} ${authTypeLabel(providerAuthType(provider))}`.toLowerCase().includes(search));

  $('#provider-options').innerHTML = providers.map((provider) => {
    const key = providerKey(provider);
    return `
      <article class="provider-row ${providerKey(state.provider) === key ? 'selected' : ''}">
        <div class="option-card-header">
          <div class="provider-title"><span class="provider-mark" aria-hidden="true">${escapeHtml((provider.displayName ?? key).slice(0, 1).toUpperCase())}</span><div><h3>${escapeHtml(provider.displayName ?? key)}</h3><span class="provider-key">${escapeHtml(key)}</span></div></div>
          <span class="provider-type-badge">${escapeHtml(authTypeLabel(providerAuthType(provider)))}</span>
        </div>
        <p>${escapeHtml(providerDescription(provider))}</p>
        <details class="technical-details"><summary>${t('wizard.provider.technicalDetails')}</summary><span class="tags">${providerTechnicalTags(provider).map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}</span>${oauthRegistrationDetails(provider, null)}</details>
        <button class="primary provider-select" type="button" data-provider="${key}" aria-pressed="${providerKey(state.provider) === key}">${t('wizard.provider.select')}</button>
      </article>
    `;
  }).join('') || `<div class="empty-state"><h3>${t('wizard.provider.none')}</h3><p>${t('wizard.provider.noneHelp')}</p></div>`;
}

function getProviderFieldSet(provider = state.provider) {
  const fields = selectedCredentialMethod()?.credentialFields ?? provider?.credentialFields ?? [];
  return (Array.isArray(fields) ? fields : [])
    .filter((field) => field.visible !== false && field.userConfigurable !== false && !field.systemManaged);
}

function credentialMethods(provider = state.provider) {
  return Array.isArray(provider?.credentialMethods) ? provider.credentialMethods : [];
}

function methodPresentation(method) {
  const binding = (state.provider?.providerMethodBindings ?? []).find((candidate) => candidate.methodKey === method.key);
  return {
    displayName: binding?.displayName ?? method.displayName ?? method.key,
    description: binding?.description ?? method.description ?? ''
  };
}

function renderCredentialMethodSelection() {
  const target = $('#credential-method-selection');
  const methods = credentialMethods();
  target.replaceChildren();
  if (methods.length === 0 || selectedCredentialMethod()) return;

  target.innerHTML = `<div class="provider-context-card"><h3>${escapeHtml(t('wizard.method.heading'))}</h3><p>${escapeHtml(t('wizard.method.help'))}</p><div class="card-grid">${methods.map((method) => {
    const presentation = methodPresentation(method);
    return `<article class="auth-type-row"><div><h3>${escapeHtml(presentation.displayName)}</h3><p>${escapeHtml(presentation.description)}</p></div><button class="primary" type="button" data-credential-method="${escapeHtml(method.key)}">${escapeHtml(t('wizard.method.select'))}</button></article>`;
  }).join('')}</div></div>`;
}

function groupFields(fields) {
  return fields.reduce((groups, field) => {
    const group = field.section ?? 'accountCredentials';
    groups[group] = groups[group] ?? [];
    groups[group].push(field);
    return groups;
  }, {});
}

function fieldInputType(field) {
  const inputType = field.inputType ?? field.type;
  if (inputType === 'integer') return 'number';
  if (inputType === 'api-key') return 'password';
  if (inputType === 'oauth-scope') return 'text';
  return inputType ?? 'text';
}

function fieldValue(field) {
  const value = state.formData[field.key] ?? field.defaultValue ?? '';
  return Array.isArray(value) ? value.join(' ') : value;
}

function autocompleteForField(field) {
  if (field.secret) return 'current-password';
  if (field.key === 'username') return 'username';
  return 'off';
}

function renderField(field) {
  const required = field.required ? 'required' : '';
  const placeholder = field.placeholder ? `placeholder="${field.placeholder}"` : '';
  const id = `credential-field-${field.key}`;
  const value = fieldValue(field);
  const autocomplete = `autocomplete="${autocompleteForField(field)}"`;
  const label = translationOr(`field.${field.key}.label`, field.label ?? humanize(field.key));
  const help = translationOr(`field.${field.key}.help`, field.description ?? (field.secret ? t('wizard.secretHelp') : ''));
  let control;

  if (field.type === 'textarea') {
    control = `<textarea id="${id}" name="${field.key}" ${required} ${placeholder} ${autocomplete}>${value}</textarea>`;
  } else if (field.type === 'select' && Array.isArray(field.options)) {
    control = `<select id="${id}" name="${field.key}" ${required} ${autocomplete}>${field.options.map((option) => {
      const optionValue = option.value ?? option.key ?? option;
      const optionLabel = option.label ?? optionValue;
      return `<option value="${optionValue}" ${String(optionValue) === String(value) ? 'selected' : ''}>${optionLabel}</option>`;
    }).join('')}</select>`;
  } else if (field.type === 'boolean') {
    control = `<input id="${id}" name="${field.key}" type="checkbox" ${value ? 'checked' : ''} ${autocomplete}>`;
  } else {
    const scopeHint = field.type === 'oauth-scope' ? 'placeholder="scope-one scope-two"' : placeholder;
    control = `<input id="${id}" name="${field.key}" type="${fieldInputType(field)}" value="${value}" ${required} ${scopeHint} ${autocomplete}>`;
  }

  return `<div class="field" data-field-key="${escapeHtml(field.key)}"><label for="${id}"><span>${escapeHtml(label)}</span>${field.required ? `<span class="required-badge">${t('wizard.requiredField')}</span>` : ''}</label>${control}${help ? `<small class="field-help">${escapeHtml(help)}</small>` : ''}</div>`;
}

function renderProviderContext() {
  const provider = state.provider;
  const security = provider?.oauthSecurity;
  const securityTags = security
    ? Object.entries(security).map(([name, value]) => `<span class="tag">${name}: ${value}</span>`).join('')
    : '';
  $('#provider-context').innerHTML = `
    <article class="provider-context-card">
      <h3>${provider?.displayName ?? providerKey(provider)}</h3>
      <p>${escapeHtml(providerDescription(provider))}</p>
      <span class="provider-type-badge">${authTypeLabel(providerAuthType(provider))}</span>
      ${selectedCredentialMethod() ? `<span class="provider-type-badge">${escapeHtml(methodPresentation(selectedCredentialMethod()).displayName)}</span>` : ''}
      <details class="technical-details"><summary>${t('wizard.provider.technicalDetails')}</summary><span class="tags">${providerCapabilities(provider).map((capability) => `<span class="tag">${capability}</span>`).join('')}${securityTags}</span>${oauthRegistrationDetails(provider)}</details>
    </article>`;
}

function renderForm() {
  const method = selectedCredentialMethod();
  $('#credential-form-title').textContent = `${state.provider?.displayName ?? providerKey()}${method ? ` · ${methodPresentation(method).displayName}` : ''}: ${t('wizard.data.heading')}`;
  renderProviderContext();
  renderCredentialMethodSelection();
  if (credentialMethods().length > 0 && !method) {
    $('#credential-form').replaceChildren();
    $('#connection-test-panel').replaceChildren();
    return;
  }
  const fields = getProviderFieldSet();
  $('#credential-form').innerHTML = Object.entries(groupFields(fields)).map(([section, groupFields]) => `
    <fieldset class="field-group"><legend>${translationOr(`field.section.${section}`, humanize(section))}</legend>${groupFields.map(renderField).join('')}</fieldset>
  `).join('') || `<div class="empty-state"><h3>${t('wizard.data.none')}</h3><p>${t('wizard.data.noneHelp')}</p></div>`;
  $('#credential-form').addEventListener('input', () => {
    state.hasUnsavedChanges = true;
    if (state.connectionTest) {
      state.connectionTest = null;
      renderConnectionTestPanel();
    }
  });
  renderConnectionTestPanel();
}

function renderConnectionTestPanel() {
  const panel = $('#connection-test-panel');
  if (!supportsConnectionTest()) {
    panel.replaceChildren();
    return;
  }

  const result = state.connectionTest;
  const status = result
    ? `<p class="connection-test-result ${result.success ? 'success' : 'failure'}" role="status">${escapeHtml(result.success ? t('wizard.connectionTest.success') : userFacingError(result.error))}</p>`
    : `<p class="connection-test-help">${t('wizard.connectionTest.help')}</p>`;
  panel.innerHTML = `<h3>${t('wizard.connectionTest.heading')}</h3>${status}<button class="secondary" type="button" data-action="test-connection" data-testid="credential-wizard-test-connection" ${state.connectionTestPending ? 'disabled' : ''}>${state.connectionTestPending ? t('wizard.connectionTest.testing') : t('wizard.connectionTest.start')}</button>`;
}

function collectFormData() {
  if (credentialMethods().length > 0 && !selectedCredentialMethod()) {
    showError(t('wizard.method.required'));
    return false;
  }
  const form = $('#credential-form');
  if (!form.reportValidity()) return false;
  const values = Object.fromEntries(new FormData(form).entries());
  for (const field of getProviderFieldSet()) {
    if (field.type === 'boolean') values[field.key] = form.elements[field.key].checked;
    if (field.type === 'oauth-scope') values[field.key] = String(values[field.key] ?? '').split(/[\s,]+/).filter(Boolean);
  }
  state.formData = values;
  state.hasUnsavedChanges = false;
  return true;
}

function providerConfigurationPayload() {
  return Object.fromEntries(getProviderFieldSet()
    .filter((field) => field.section === 'providerConfiguration')
    .map((field) => [field.key, state.formData[field.key]])
    .filter(([, value]) => value !== undefined && value !== null && value !== ''));
}

function credentialPayload() {
  const metadata = { displayName: state.formData.displayName ?? providerKey(), description: state.formData.description ?? null, type: providerAuthType(), providerName: state.provider?.displayName ?? providerKey(), custom: {} };
  const secrets = [];
  for (const field of getProviderFieldSet()) {
    const value = state.formData[field.key];
    if (value === undefined || value === null || value === '') continue;
    if (field.key === 'displayName' || field.key === 'description') continue;
    if (field.key === 'scopes') {
      metadata.scopes = value;
      continue;
    }
    if (field.secret) secrets.push({ name: field.key, value, type: field.type, required: field.required });
    else metadata.custom[field.key] = value;
  }
  return {
    providerKey: providerKey(),
    ...(selectedCredentialMethod() ? { credentialMethodKey: selectedCredentialMethod().key } : {}),
    externalReference: state.formData.displayName ?? providerKey(),
    lifecycleState: 'registered',
    metadata,
    secrets
  };
}

async function testConnection() {
  if (state.connectionTestPending || !collectFormData()) return;
  state.connectionTestPending = true;
  state.connectionTest = null;
  renderConnectionTestPanel();
  try {
    const body = await api('/api/v1/credentials/test-connection', {
      method: 'POST',
      body: JSON.stringify(credentialPayload())
    });
    state.connectionTest = { success: true, result: body.data };
  } catch (error) {
    state.connectionTest = { success: false, error };
  } finally {
    state.connectionTestPending = false;
    renderConnectionTestPanel();
  }
}

function markOAuthRedirectStarted() {
  transitionWizardState(wizardStates.WAIT_CALLBACK);
}

function resetOAuthAttempt() {
  if (state.oauthWindow && !state.oauthWindow.closed) state.oauthWindow.close();
  state.oauthWindow = null;
  state.oauthPending = false;
  state.oauthResult = null;
  state.oauthAttemptDetails = null;
}

function missingProviderConfigurationFields() {
  return getProviderFieldSet()
    .filter((field) => field.section === 'providerConfiguration' && field.required)
    .filter((field) => {
      const value = state.formData[field.key];
      return value === undefined || value === null || String(value).trim() === '';
    });
}

function markMissingFields(fields) {
  for (const field of fields) {
    const container = document.querySelector(`[data-field-key="${CSS.escape(field.key)}"]`);
    const input = document.querySelector(`#credential-field-${CSS.escape(field.key)}`);
    container?.classList.add('invalid');
    input?.setAttribute('aria-invalid', 'true');
  }
}

async function startOAuth() {
  if (state.oauthPending) return;
  const missing = missingProviderConfigurationFields();
  if (missing.length > 0) {
    setStep(3);
    renderForm();
    markMissingFields(missing);
    showError({ code: 'PROVIDER_CONFIGURATION_MISSING' });
    return;
  }

  const popup = window.open('about:blank', 'credential-hub-oauth', 'popup,width=720,height=760');
  if (!popup) {
    showError({ code: 'OAUTH_POPUP_BLOCKED' });
    return;
  }

  state.oauthWindow = popup;
  state.oauthPending = true;
  markOAuthRedirectStarted();
  renderOAuthAuthorizationStep();

  try {
    const response = await api(`/api/v1/providers/${encodeURIComponent(providerKey())}/oauth/start`, {
      method: 'POST',
      body: JSON.stringify({
        providerConfiguration: providerConfigurationPayload(),
        scopes: state.formData.scopes ?? state.provider?.defaultScopes ?? []
      })
    });
    const authorizationUrl = new URL(response.data.authorizationUrl);
    if (authorizationUrl.protocol !== 'https:') throw new Error('Unsafe OAuth authorization URL');
    state.oauthAttemptDetails = {
      authorizationUrl: authorizationUrl.toString(),
      redirectUri: response.data.redirectUri,
      callbackPath: response.data.callbackPath,
      scopes: response.data.scopes ?? []
    };
    renderOAuthAuthorizationStep();
    popup.location.replace(authorizationUrl.toString());
  } catch (error) {
    popup.close();
    state.oauthWindow = null;
    state.oauthPending = false;
    transitionWizardState(wizardStates.ERROR);
    renderOAuthAuthorizationStep();
    showError(error);
  }
}

function readOAuthCallbackResult(search = window.location.search) {
  const params = new URLSearchParams(search);
  const status = params.get('oauth');
  return status ? { status, provider: params.get('provider'), credentialId: params.get('credentialId') } : null;
}

function applyOAuthCallbackResult(result) {
  if (!result) return;
  state.oauthResult = result;
  switch (result.status) {
    case 'success':
      prepareCredentialIntegration(credentialIdFromOutcome(result));
      transitionWizardState(wizardStates.CREDENTIAL_READY);
      break;
    case 'cancelled':
      transitionWizardState(wizardStates.CONFIGURE);
      break;
    default:
      transitionWizardState(wizardStates.ERROR);
      break;
  }
}

function renderOAuthAuthorizationStep() {
  const provider = state.provider;
  $('#oauth-authorization').innerHTML = `<article class="provider-context-card"><h3>${t('wizard.authorize', { provider: provider?.displayName ?? providerKey() })}</h3><p>${t('wizard.oauth.securityProfile')}</p><details class="technical-details" open><summary>${t('wizard.provider.technicalDetails')}</summary>${oauthRegistrationDetails(provider)}</details><div class="oauth-actions"><button class="primary" id="oauth-authorize-start" type="button" data-oauth-login-start ${state.oauthPending ? 'disabled' : ''}>${state.oauthPending ? t('wizard.connecting') : t('wizard.oauth.start')}</button></div><p class="oauth-info">${t('wizard.oauth.wait')}</p></article>`;
}

function renderSummary() {
  const oauth = isOAuthProvider();
  $('#summary').innerHTML = `<div class="summary-ready"><strong>${t('wizard.ready')}</strong><span>${t('wizard.readyHelp')}</span></div><div class="summary-row"><strong>${t('wizard.step.selectAuth')}</strong><span>${authTypeLabel(providerAuthType())}</span></div><div class="summary-row"><strong>${t('common.provider')}</strong><span>${state.provider?.displayName ?? providerKey()}</span></div><div class="summary-row"><strong>${t('common.name')}</strong><span>${state.formData.displayName ?? ''}</span></div>`;
  const oauthStart = $('#oauth-start');
  const createButton = $('#create-credential');
  oauthStart.classList.add('hidden');
  createButton.classList.toggle('hidden', oauth);
}

function renderOAuthOutcome(result) {
  const provider = state.provider?.displayName ?? result.provider ?? 'Provider';
  const isSuccess = result.status === 'success';
  const isCancelled = result.status === 'cancelled';
  const title = isSuccess ? t('wizard.integration.credentialReady') : isCancelled ? t('wizard.cancelled') : t('wizard.failed');
  const description = isSuccess
    ? t('wizard.integration.credentialReadyHelp', { provider })
    : isCancelled
      ? t('wizard.cancelledHelp', { provider })
      : t('wizard.failedHelp', { provider });
  const credential = result.credentialId ? `<div class="summary-row"><strong>Credential</strong><span>${escapeHtml(result.credentialId)}</span></div>` : '';
  $('#summary').innerHTML = `<div class="summary-ready"><strong>${title}</strong><span>${description}</span></div>${credential}${isSuccess ? `<p class="grant-warning">${t('wizard.integration.grantRequired')}</p>` : ''}`;
  $('#oauth-start').classList.add('hidden');
  $('#create-credential').classList.add('hidden');
  if (isSuccess && credentialIdFromOutcome(result)) showConsumerGrantPanel();
}

async function createCredential() {
  clearError();
  const result = $('#create-result');
  result.classList.add('hidden');
  const createButton = $('#create-credential');
  createButton.disabled = true;
  createButton.textContent = t('wizard.creating');
  try {
    const body = await api('/api/v1/credentials', { method: 'POST', body: JSON.stringify(credentialPayload()) });
    state.creationResult = { success: true, credential: body.data };
    prepareCredentialIntegration(credentialIdFromOutcome());
    transitionWizardState(wizardStates.CREDENTIAL_READY);
    renderCreationOutcome();
  } catch (error) {
    state.creationResult = { success: false, code: error.code ?? 'CREDENTIAL_CREATE_FAILED' };
    transitionWizardState(wizardStates.ERROR);
    renderCreationOutcome();
  } finally {
    createButton.disabled = false;
    createButton.textContent = t('wizard.create');
  }
}

function renderCreationOutcome() {
  const outcome = state.creationResult;
  if (!outcome) return;
  $('#create-credential').classList.add('hidden');
  $('#oauth-start').classList.add('hidden');

  if (outcome.success) {
    $('#summary').innerHTML = `
      <div class="summary-ready"><strong>${t('wizard.integration.credentialReady')}</strong><span>${t('wizard.integration.credentialReadyHelp', { provider: state.provider?.displayName ?? providerKey() })}</span></div>
      <p class="grant-warning">${t('wizard.integration.grantRequired')}</p>`;
    showConsumerGrantPanel();
    return;
  }

  $('#summary').innerHTML = `
    <div class="creation-error"><strong>${t('wizard.createFailed')}</strong><span>${userFacingError({ code: outcome.code })}</span><code>${escapeHtml(outcome.code)}</code></div>
    <div class="actions"><button class="secondary" type="button" data-action="edit-credential">${t('wizard.backToEdit')}</button></div>`;
}

function renderConsumerGrantPanel({ preserveEnteredToken = null } = {}) {
  const panel = $('#consumer-grant-panel');
  const target = grantTarget();
  const secretNames = credentialSecretNames();
  if (!target.credentialId) {
    panel.classList.add('hidden');
    return;
  }
  if (!integrationComplete()) transitionWizardState(wizardStates.GRANT_CONFIGURE);
  const consumers = state.consumerTokens.map((token) => `<option value="${escapeHtml(consumerTokenId(token))}" ${consumerTokenId(token) === state.selectedConsumerId ? 'selected' : ''}>${escapeHtml(consumerTokenLabel(token))}</option>`).join('');
  const selection = secretNames.map((name) => `<label class="checkbox-row"><input type="checkbox" data-grant-secret value="${escapeHtml(name)}" ${state.selectedSecretNames.includes(name) ? 'checked' : ''}> ${escapeHtml(name)}</label>`).join('') || `<p>${t('wizard.grant.noSecrets')}</p>`;
  const plaintext = state.consumerTokenPlaintext ? `<div class="grant-token-once"><strong>${t('wizard.grant.tokenOnce')}</strong><code>${escapeHtml(state.consumerTokenPlaintext)}</code><p>${t('wizard.grant.tokenOnceHelp')}</p></div>` : '';
  const grantResult = state.consumerGrant ? `<p class="connection-test-result ${state.consumerGrant.success ? 'success' : 'failure'}">${escapeHtml(state.consumerGrant.message)}</p>` : '';
  const nextSteps = integrationComplete()
    ? `<details class="technical-details"><summary>${t('wizard.integration.nextSteps')}</summary><p>${t('wizard.integration.nextStepsHelp')}</p><pre>curl --fail --silent --show-error \\
  -H "Authorization: Bearer &lt;consumer-api-token&gt;" \\
  -H "Content-Type: application/json" \\
  -X POST "https://hub.example/api/v1/consumer/credentials/&lt;credential-key&gt;/resolve" \\
  --data '{"secretNames":["&lt;allowed-secret-name&gt;"]}'</pre></details>`
    : '';
  panel.classList.remove('hidden');
  const completionActions = integrationComplete() ? `<div class="actions"><a class="primary" href="${applicationPath('/consumer/')}" data-testid="consumer-handoff-open">${t('wizard.integration.openConsumer')}</a><a class="secondary" href="${applicationPath('/admin/dashboard.html')}">${t('nav.dashboard')}</a><a class="secondary" href="${applicationPath('/admin/')}">${t('wizard.createAnother')}</a></div><p>${t('wizard.integration.openConsumerHelp')}</p>` : '';
  panel.innerHTML = `<h3>${t('wizard.grant.heading')}</h3><p>${t('wizard.grant.help')}</p><div class="grant-warning">${t('wizard.grant.warning')}</div>${plaintext}<div class="summary-row"><strong>${t('wizard.grant.credential')}</strong><span>${escapeHtml(target.credentialId)}</span></div><label>${t('wizard.grant.consumer')}<select id="grant-consumer-id"><option value="">${t('wizard.grant.chooseConsumer')}</option>${consumers}</select></label><label>${t('wizard.grant.consumerOwner')}<input id="grant-consumer-user-id" value="" autocomplete="username" required></label><label>${t('wizard.integration.consumerToken')}<input id="grant-consumer-token" type="password" autocomplete="off" spellcheck="false" placeholder="${escapeHtml(t('wizard.integration.consumerTokenHelp'))}"></label><div class="grant-secrets"><strong>${t('wizard.grant.secrets')}</strong>${selection}</div><div class="actions"><button class="secondary" type="button" data-action="create-consumer-token">${t('wizard.grant.createConsumer')}</button><button class="primary" type="button" data-action="create-consumer-grant" ${secretNames.length === 0 ? 'disabled' : ''}>${t('wizard.grant.create')}</button><button class="secondary" type="button" data-action="diagnose-consumer-grant" ${secretNames.length === 0 ? 'disabled' : ''}>${t('wizard.grant.diagnose')}</button></div>${grantResult}${nextSteps}${completionActions}`;
  if (preserveEnteredToken) $('#grant-consumer-token').value = preserveEnteredToken;
}

async function showConsumerGrantPanel() {
  try {
    await loadConsumerTokens();
  } catch (error) {
    state.consumerGrant = { success: false, message: userFacingError(error) };
  }
  renderConsumerGrantPanel();
}

function selectedGrantSecrets() {
  return $$('[data-grant-secret]:checked').map((input) => input.value);
}

async function createConsumerToken() {
  const grantAttempt = ++state.integration.grantAttempt;
  const isCurrentAttempt = () => grantAttempt === state.integration.grantAttempt;
  try {
    const userId = $('#grant-consumer-user-id')?.value?.trim();
    if (!userId) throw { code: 'CONSUMER_OWNER_REQUIRED' };
    const body = await api('/api/v1/management/api-tokens', { method: 'POST', body: JSON.stringify({ name: `Consumer for ${state.formData.displayName ?? providerKey()}`, userId, scopes: ['credentials:consume'] }) });
    const created = body?.data ?? body;
    const token = created.apiToken ?? created;
    if (!isCurrentAttempt()) return;
    state.consumerTokenPlaintext = created.token ?? created.plaintextToken ?? created.value ?? null;
    state.consumerTokens = [...state.consumerTokens, token];
    state.selectedConsumerId = consumerTokenId(token);
    state.integration.verification = null;
    state.consumerGrant = { success: false, message: t('wizard.grant.consumerCreated') };
  } catch (error) {
    if (!isCurrentAttempt()) return;
    state.consumerGrant = { success: false, message: userFacingError(error) };
  }
  renderConsumerGrantPanel();
}

async function verifyRealResolve({ consumerToken, configuration }) {
  if (!consumerToken) throw { code: 'CONSUMER_TOKEN_REQUIRED' };
  const credentialKey = configuration.credentialId;
  const { body, response } = await consumerApi.request(`/api/v1/consumer/credentials/${encodeURIComponent(credentialKey)}/resolve`, consumerToken, {
    method: 'POST',
    body: JSON.stringify({ secretNames: configuration.secretNames })
  });
  if (body?.success !== true || body?.data?.credentialKey !== credentialKey || response.headers.get('cache-control') !== 'no-store') {
    const error = new Error('Consumer resolve verification failed');
    error.code = body?.error?.code ?? 'RESOLVE_NOT_AVAILABLE';
    throw error;
  }
  return normalizedGrantConfiguration(configuration);
}

async function submitConsumerGrant({ diagnose = false } = {}) {
  const consumerId = $('#grant-consumer-id')?.value;
  const target = grantTarget();
  state.selectedSecretNames = normalizeSecretNames(selectedGrantSecrets());
  state.selectedConsumerId = consumerId;
  const configuration = currentGrantConfiguration();
  const grantAttempt = ++state.integration.grantAttempt;
  const isCurrentAttempt = () => grantAttempt === state.integration.grantAttempt;
  if (!configuration.consumerId || configuration.secretNames.length === 0) {
    invalidateGrantVerification();
    state.consumerGrant = { success: false, message: t('wizard.grant.required') };
    renderConsumerGrantPanel();
    return;
  }
  try {
    if (diagnose) {
      const outcome = await runGrantDiagnosisAttempt({
        isCurrentAttempt,
        diagnoseGrant: () => api('/api/v1/management/consumer-grants/diagnose', { method: 'POST', body: JSON.stringify(configuration) })
      });
      if (outcome.status === 'stale') return;
      if (outcome.status === 'error') throw outcome.error;
      const code = outcome.diagnostic?.data?.code;
      state.consumerGrant = code === 'RESOLVE_SUCCESS'
        ? { success: true, message: t('wizard.grant.diagnoseSuccess') }
        : { success: false, message: userFacingError({ code }) };
    } else {
      const enteredToken = $('#grant-consumer-token')?.value?.trim();
      const consumerToken = enteredToken || state.consumerTokenPlaintext;
      const outcome = await runGrantResolveAttempt({
        configuration,
        consumerToken,
        isCurrentAttempt,
        synchronizeGrant: (snapshot) => synchronizeGrant({ api, savedGrant: state.integration.savedGrant, configuration: snapshot }),
        verifyResolve: verifyRealResolve,
        commitSavedGrant: setSavedGrant,
        commitVerification: (verifiedConfiguration) => { state.integration.verification = { kind: 'resolve', success: true, ...verifiedConfiguration }; },
        consumeToken: () => { if (consumerToken === state.consumerTokenPlaintext) state.consumerTokenPlaintext = null; }
      });
      if (outcome.status === 'stale') return;
      if (outcome.status === 'error') throw Object.assign(outcome.error, { grantPhase: outcome.phase });
      transitionWizardState(wizardStates.INTEGRATION_COMPLETE);
      state.consumerGrant = { success: true, message: t('wizard.integration.complete') };
    }
  } catch (error) {
    if (!isCurrentAttempt()) return;
    state.integration.verification = null;
    state.consumerGrant = { success: false, message: error.grantPhase === 'resolve' ? t('wizard.grant.resolveFailed') : t('wizard.grant.saveFailed') };
  }
  renderConsumerGrantPanel();
}

async function bootstrapWizard() {
  const outcome = readOAuthCallbackResult();
  if (outcome?.status === 'success' && !managementTokenStore.getToken()) {
    state.oauthResult = outcome;
    prepareCredentialIntegration(credentialIdFromOutcome(outcome));
    state.provider = { key: outcome.provider, displayName: outcome.provider };
    state.authType = providerAuthGroup(state.provider);
    setStep(5);
    transitionWizardState(wizardStates.CREDENTIAL_READY);
    $('#api-status').textContent = t('wizard.integration.managementTokenRequired');
    $('#api-status').classList.add('down');
    renderOAuthOutcome(outcome);
    return;
  }
  try {
    const [health, providers, meta] = await Promise.all([api('/health'), api('/api/v1/providers'), api('/api/v1/credentials/meta')]);
    $('#api-status').textContent = health.status === 'UP' ? t('wizard.apiConnected') : t('wizard.apiUnclear');
    state.providers = providers.data ?? [];
    state.meta = meta.data;
    renderAuthOptions();
    renderProviders();
    if (!outcome) {
      setStep(1);
      return;
    }
    state.provider = state.providers.find((provider) => providerKey(provider) === outcome.provider) ?? null;
    state.authType = providerAuthGroup(state.provider);
    state.credentialMethod = null;
    setStep(5);
    applyOAuthCallbackResult(outcome);
    renderOAuthOutcome(outcome);
  } catch (error) {
    $('#api-status').textContent = t('wizard.apiUnavailable');
    $('#api-status').classList.add('down');
    showError(t('errors.apiUnavailable'));
  }
}

document.addEventListener('change', (event) => {
  if (!event.target.matches('#grant-consumer-id, [data-grant-secret]')) return;
  const enteredToken = $('#grant-consumer-token')?.value ?? null;
  state.selectedConsumerId = $('#grant-consumer-id')?.value ?? null;
  state.selectedSecretNames = normalizeSecretNames(selectedGrantSecrets());
  invalidateGrantVerification(event.target.matches('#grant-consumer-id') ? t('wizard.grant.consumerChanged') : t('wizard.grant.changed'));
  renderConsumerGrantPanel({ preserveEnteredToken: enteredToken });
});

document.addEventListener('input', (event) => {
  if (!event.target.matches('#grant-consumer-token')) return;
  const hadVerification = Boolean(state.integration.verification);
  const enteredToken = event.target.value;
  state.integration.grantAttempt += 1;
  state.integration.verification = null;
  if (hadVerification) renderConsumerGrantPanel({ preserveEnteredToken: enteredToken });
});

document.addEventListener('click', (event) => {
  if (event.target.closest('[data-oauth-login-start]')) {
    startOAuth();
    return;
  }
  const authButton = event.target.closest('[data-auth-type]');
  if (authButton) {
    state.authType = authButton.dataset.authType;
    state.provider = null;
    state.credentialMethod = null;
    state.formData = {};
    state.oauthAttemptDetails = null;
    renderAuthOptions();
    renderProviders();
    setStep(2);
    return;
  }
  const providerButton = event.target.closest('[data-provider]');
  if (providerButton) {
    if (state.hasUnsavedChanges && !window.confirm(t('wizard.unsaved'))) return;
    state.provider = state.providers.find((provider) => providerKey(provider) === providerButton.dataset.provider);
    state.credentialMethod = null;
    state.formData = {};
    state.oauthAttemptDetails = null;
    state.hasUnsavedChanges = false;
    renderProviders();
    renderForm();
    setStep(3);
    return;
  }
  const methodButton = event.target.closest('[data-credential-method]');
  if (methodButton) {
    state.credentialMethod = credentialMethods().find((method) => method.key === methodButton.dataset.credentialMethod) ?? null;
    state.formData = {};
    state.hasUnsavedChanges = false;
    renderForm();
    return;
  }
  if (event.target.matches('[data-action="edit-credential"]')) {
    invalidateGrantVerification();
    state.creationResult = null;
    $('#create-credential').classList.remove('hidden');
    renderForm();
    setStep(3);
    return;
  }
  if (event.target.matches('[data-action="test-connection"]')) return testConnection();
  if (event.target.matches('[data-action="create-consumer-token"]')) return createConsumerToken();
  if (event.target.matches('[data-action="create-consumer-grant"]')) return submitConsumerGrant();
  if (event.target.matches('[data-action="diagnose-consumer-grant"]')) return submitConsumerGrant({ diagnose: true });
  if (event.target.matches('[data-action="back"]')) {
    if (state.step === 4) resetOAuthAttempt();
    return setStep(previousStepForCurrentState());
  }
  if (event.target.matches('[data-action="next"]')) {
    if (state.step === 1 && !state.authType) return showError(t('wizard.selectAuthError'));
    if (state.step === 2 && !state.provider) return showError(t('wizard.selectProviderError'));
    if (state.step === 3 && !collectFormData()) return;
    if (state.step === 3 && isOAuthProvider()) renderOAuthAuthorizationStep();
    if (state.step === 3 && !isOAuthProvider()) renderSummary();
    setStep(nextStepForCurrentState());
  }
});

window.addEventListener('message', (event) => {
  if (event.origin !== window.location.origin) return;
  if (state.oauthWindow && event.source !== state.oauthWindow) return;
  const result = event.data;
  if (result?.type !== 'credential-hub:oauth-result' || result.version !== 1) return;
  if (result.provider !== providerKey()) return;

  state.oauthPending = false;
  state.oauthResult = result;
  state.oauthWindow = null;
  if (result.status === 'success') {
    prepareCredentialIntegration(credentialIdFromOutcome(result));
    setStep(5);
    transitionWizardState(wizardStates.CREDENTIAL_READY);
    renderOAuthOutcome(result);
    return;
  }

  transitionWizardState(result.status === 'cancelled' ? wizardStates.CONFIGURE : wizardStates.ERROR);
  setStep(4);
  renderOAuthAuthorizationStep();
  showError(result);
});

window.addEventListener('beforeunload', (event) => {
  if (!state.hasUnsavedChanges) return;
  event.preventDefault();
  event.returnValue = '';
});

$('#provider-search').addEventListener('input', renderProviders);
$('#create-credential').addEventListener('click', createCredential);

onLanguageChange(() => {
  renderWizardProgress();
  renderAuthOptions();
  renderProviders();
  if (state.provider && state.step >= 3) renderForm();
  if (state.step === 4) renderOAuthAuthorizationStep();
  if (state.step === 5) {
    if (state.creationResult) renderCreationOutcome();
    else if (state.oauthResult) renderOAuthOutcome(state.oauthResult);
    else renderSummary();
  }
});

await bootstrapWizard();
