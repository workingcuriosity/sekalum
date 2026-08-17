// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { ConsumerApiClient } from '../shared/consumer-api.js';

const ERROR_MESSAGES = new Map([
  [401, 'Connection failed. Check the Consumer API token and try again.'],
  [403, 'Connection failed. This token is not authorized for Consumer Discovery.'],
  [500, 'Credential Discovery is temporarily unavailable. Try again.']
]);

function publicCredential(entry) {
  if (!entry || typeof entry !== 'object' || typeof entry.credentialKey !== 'string') return null;
  return {
    credentialKey: entry.credentialKey,
    metadata: entry.metadata && typeof entry.metadata === 'object' ? entry.metadata : {},
    fields: Array.isArray(entry.fields) ? entry.fields : []
  };
}

function publicCredentials(body) {
  const credentials = body?.data?.credentials;
  return Array.isArray(credentials) ? credentials.map(publicCredential).filter(Boolean) : [];
}

function secretNamesForCredential(credential) {
  return publicSecretFields(credential).map(({ name }) => name);
}

function publicSecretFields(credential) {
  const seen = new Set();
  return (credential?.fields ?? []).filter((field) => {
    if (!field || typeof field !== 'object' || typeof field.name !== 'string' || field.name.trim() === '' || field.secret !== true || field.visible !== true || seen.has(field.name)) return false;
    seen.add(field.name);
    return true;
  });
}

function errorMessage(error) {
  if (ERROR_MESSAGES.has(error?.status)) return ERROR_MESSAGES.get(error.status);
  if (error?.code === 'API_TOKEN_AUTH_FAILED') return ERROR_MESSAGES.get(401);
  if (error?.code === 'CONSUMER_SCOPE_MISSING') return ERROR_MESSAGES.get(403);
  return error?.status ? 'Credential Discovery could not be completed. Try again.' : 'Network error. Check the connection and try again.';
}

function resolveErrorMessage(error) {
  if (error?.status === 400) return 'Resolve request could not be completed. Check the selected secret fields and try again.';
  if (error?.status === 401) return 'Resolve failed. Check the Consumer API token and try again.';
  if (error?.status === 403) return 'Resolve failed. This token is not authorized for the selected credential fields.';
  if (error?.status) return 'Resolve request could not be completed. Try again.';
  return 'Network error. Check the connection and try again.';
}

function maskedSecret(value) {
  return '•'.repeat(Math.max(8, Math.min(32, value.length)));
}

function validatedResolveData(body, credentialKey, requestedSecretNames) {
  const data = body?.data;
  if (!data || typeof data !== 'object' || data.credentialKey !== credentialKey || data.lifecycleState !== 'active' || typeof data.providerKey !== 'string' || !data.secrets || typeof data.secrets !== 'object' || Array.isArray(data.secrets)) {
    throw Object.assign(new Error('Invalid Resolve response'), { code: 'RESOLVE_RESPONSE_INVALID' });
  }

  const secretNames = Object.keys(data.secrets);
  if (secretNames.length !== requestedSecretNames.length || secretNames.some((name) => !requestedSecretNames.includes(name)) || requestedSecretNames.some((name) => typeof data.secrets[name] !== 'string')) {
    throw Object.assign(new Error('Invalid Resolve response'), { code: 'RESOLVE_RESPONSE_INVALID' });
  }

  return data;
}

function text(documentRef, value) {
  const node = documentRef.createElement('span');
  node.textContent = value;
  return node;
}

function renderCredentials(documentRef, list, results, selectedCredentialKey, onSelect) {
  results.replaceChildren();
  if (list.length === 0) {
    const empty = documentRef.createElement('p');
    empty.className = 'consumer-empty';
    empty.textContent = 'Connection successful. No credentials are currently available.';
    results.append(empty);
    return;
  }

  for (const credential of list) {
    const article = documentRef.createElement('article');
    article.className = 'consumer-credential';
    const heading = documentRef.createElement('h3');
    heading.append(text(documentRef, credential.metadata.displayName ?? credential.credentialKey));
    article.append(heading);
    const key = documentRef.createElement('p');
    key.className = 'consumer-credential-key';
    key.append(text(documentRef, `Credential key: ${credential.credentialKey}`));
    article.append(key);

    const selectionLabel = documentRef.createElement('label');
    selectionLabel.className = 'consumer-credential-selection';
    const selection = documentRef.createElement('input');
    selection.type = 'radio';
    selection.name = 'credential-selection';
    selection.value = credential.credentialKey;
    selection.checked = credential.credentialKey === selectedCredentialKey;
    selection.addEventListener('change', () => onSelect(credential.credentialKey));
    selectionLabel.append(selection, text(documentRef, ' Select credential'));
    article.append(selectionLabel);

    const fields = credential.fields.filter((field) => field && typeof field === 'object' && typeof field.name === 'string');
    if (fields.length > 0) {
      const fieldList = documentRef.createElement('ul');
      fieldList.className = 'consumer-field-list';
      for (const field of fields) {
        const item = documentRef.createElement('li');
        const label = field.label ?? field.name;
        const required = field.required ? 'required' : 'optional';
        item.append(text(documentRef, `${label} (${field.inputType ?? 'text'}, ${required})`));
        fieldList.append(item);
      }
      article.append(fieldList);
    }
    results.append(article);
  }
}

function renderSecretSelection(documentRef, credential, selection, selectedNames, onToggle, onResolve, resolveRequestInFlight) {
  selection.replaceChildren();
  selection.hidden = !credential;
  if (!credential) return;

  const heading = documentRef.createElement('h3');
  heading.textContent = 'Secret fields available for Resolve';
  selection.append(heading);

  const fields = publicSecretFields(credential);
  if (fields.length === 0) {
    const empty = documentRef.createElement('p');
    empty.className = 'consumer-empty';
    empty.textContent = 'No resolvable secret fields are available for this credential.';
    selection.append(empty);
    return;
  }

  const fieldList = documentRef.createElement('div');
  fieldList.className = 'consumer-secret-selection-list';
  for (const field of fields) {
    const label = documentRef.createElement('label');
    label.className = 'consumer-secret-selection-item';
    const checkbox = documentRef.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.name = 'secret-selection';
    checkbox.value = field.name;
    checkbox.checked = selectedNames.includes(field.name);
    checkbox.addEventListener('change', () => onToggle(field.name, checkbox.checked));
    const fieldLabel = field.required ? `${field.label ?? field.name} (required)` : (field.label ?? field.name);
    label.append(checkbox, text(documentRef, ` ${fieldLabel}`));
    fieldList.append(label);
  }
  selection.append(fieldList);

  const resolveButton = documentRef.createElement('button');
  resolveButton.type = 'button';
  // data-testid="consumer-resolve-submit" (runtime-generated control)
  resolveButton.setAttribute('data-testid', 'consumer-resolve-submit');
  resolveButton.disabled = selectedNames.length === 0 || resolveRequestInFlight;
  resolveButton.textContent = resolveRequestInFlight ? 'Resolving…' : 'Resolve selected secrets';
  resolveButton.addEventListener('click', onResolve);
  selection.append(resolveButton);
}

export function createConsumerController({ documentRef = globalThis.document, apiClient = new ConsumerApiClient() } = {}) {
  if (!documentRef) return null;
  const state = {
    authenticationState: 'initial',
    discoveryState: 'initial',
    consumerToken: '',
    requestInFlight: false,
    selectedCredentialKey: null,
    discoveredCredentials: [],
    resolveState: 'initial',
    resolvedCredential: null,
    resolveRequestInFlight: false,
    requestedSecretNames: []
  };
  const form = documentRef.querySelector('#consumer-token-form');
  const tokenInput = documentRef.querySelector('#consumer-token');
  const status = documentRef.querySelector('#consumer-status');
  const results = documentRef.querySelector('#consumer-discovery-results');
  const secretSelection = documentRef.querySelector('#consumer-secret-selection');
  const resolveResults = documentRef.querySelector('#consumer-resolve-results');
  const resolveResultList = documentRef.querySelector('#consumer-resolve-result-list');
  const submit = form?.querySelector('button[type="submit"]');
  let resolveGeneration = 0;
  const revealTimers = new Map();

  const setStatus = (message) => { if (status) status.textContent = message; };
  const setLoading = (loading) => {
    state.requestInFlight = loading;
    if (submit) submit.disabled = loading;
    if (form) form.setAttribute('aria-busy', String(loading));
  };

  function clearRevealTimers() {
    for (const timer of revealTimers.values()) clearTimeout(timer);
    revealTimers.clear();
  }

  function clearResolveResults() {
    clearRevealTimers();
    if (resolveResultList) resolveResultList.replaceChildren();
    if (resolveResults) resolveResults.hidden = true;
  }

  function renderResolveResults(data, requestedSecretNames) {
    clearResolveResults();
    if (!resolveResults || !resolveResultList) return;
    resolveResults.hidden = false;
    resolveResultList.className = 'consumer-resolve-result-list';

    for (const name of requestedSecretNames) {
      const value = data.secrets[name];
      const article = documentRef.createElement('article');
      article.className = 'consumer-resolve-result';
      const label = documentRef.createElement('strong');
      label.textContent = name;
      const valueNode = documentRef.createElement('span');
      valueNode.className = 'consumer-resolve-result-value';
      valueNode.textContent = maskedSecret(value);
      const reveal = documentRef.createElement('button');
      reveal.type = 'button';
      reveal.textContent = 'Reveal';
      reveal.addEventListener('click', () => {
        const existingTimer = revealTimers.get(name);
        if (existingTimer) clearTimeout(existingTimer);
        if (reveal.textContent === 'Hide') {
          valueNode.textContent = maskedSecret(value);
          reveal.textContent = 'Reveal';
          revealTimers.delete(name);
          return;
        }
        valueNode.textContent = value;
        reveal.textContent = 'Hide';
        revealTimers.set(name, setTimeout(() => {
          valueNode.textContent = maskedSecret(value);
          reveal.textContent = 'Reveal';
          revealTimers.delete(name);
        }, 5000));
      });
      article.append(label, valueNode, reveal);
      resolveResultList.append(article);
    }
  }

  function resetResolveState() {
    resolveGeneration += 1;
    clearResolveResults();
    state.resolveState = 'initial';
    state.resolvedCredential = null;
    state.resolveRequestInFlight = false;
    state.requestedSecretNames = [];
  }

  function clearSecretSelection() {
    if (!secretSelection) return;
    secretSelection.replaceChildren();
    secretSelection.hidden = true;
  }

  function reset() {
    resetResolveState();
    state.selectedCredentialKey = null;
    state.discoveredCredentials = [];
    if (results) results.replaceChildren();
    clearSecretSelection();
  }

  function renderSelectedSecretFields() {
    if (!secretSelection) return;
    const credential = state.discoveredCredentials.find((entry) => entry.credentialKey === state.selectedCredentialKey);
    renderSecretSelection(documentRef, credential, secretSelection, state.requestedSecretNames, (name, checked) => {
      const allowedNames = secretNamesForCredential(credential);
      if (!allowedNames.includes(name)) return;
      state.requestedSecretNames = checked
        ? [...new Set([...state.requestedSecretNames, name])]
        : state.requestedSecretNames.filter((requestedName) => requestedName !== name);
      state.requestedSecretNames = allowedNames.filter((allowedName) => state.requestedSecretNames.includes(allowedName));
      renderSelectedSecretFields();
    }, resolve, state.resolveRequestInFlight);
  }

  function selectCredential(credentialKey) {
    if (state.selectedCredentialKey === credentialKey) return;
    resetResolveState();
    state.selectedCredentialKey = credentialKey;
    renderSelectedSecretFields();
  }

  async function resolve() {
    if (state.resolveRequestInFlight || !state.selectedCredentialKey || state.requestedSecretNames.length === 0) return;

    const generation = resolveGeneration;
    const credentialKey = state.selectedCredentialKey;
    const secretNames = [...state.requestedSecretNames];
    state.resolveState = 'loading';
    state.resolveRequestInFlight = true;
    renderSelectedSecretFields();
    setStatus('Resolving selected secrets…');

    try {
      const { body } = await apiClient.request(
        `/api/v1/consumer/credentials/${encodeURIComponent(credentialKey)}/resolve`,
        state.consumerToken,
        { method: 'POST', body: JSON.stringify({ secretNames }) }
      );
      if (generation !== resolveGeneration) return;
      state.resolvedCredential = validatedResolveData(body, credentialKey, secretNames);
      state.resolveState = 'success';
      renderResolveResults(state.resolvedCredential, secretNames);
      setStatus('Resolve completed successfully.');
    } catch (error) {
      if (generation !== resolveGeneration) return;
      state.resolvedCredential = null;
      state.resolveState = 'error';
      clearResolveResults();
      setStatus(resolveErrorMessage(error));
    } finally {
      if (generation !== resolveGeneration) return;
      state.resolveRequestInFlight = false;
      renderSelectedSecretFields();
    }
  }

  async function discover(event) {
    event?.preventDefault();
    if (state.requestInFlight) return;
    state.consumerToken = tokenInput?.value?.trim() ?? '';
    if (!state.consumerToken) {
      reset();
      state.authenticationState = 'missing';
      state.discoveryState = 'initial';
      setStatus('Enter a Consumer API token to continue.');
      return;
    }

    state.authenticationState = 'testing';
    state.discoveryState = 'loading';
    resetResolveState();
    if (results) results.replaceChildren();
    clearSecretSelection();
    setLoading(true);
    setStatus('Testing connection and discovering credentials…');
    try {
      const { body } = await apiClient.request('/api/v1/consumer/credentials', state.consumerToken, { method: 'GET' });
      const list = publicCredentials(body);
      state.discoveredCredentials = list;
      if (!list.some(({ credentialKey }) => credentialKey === state.selectedCredentialKey)) {
        state.selectedCredentialKey = null;
      }
      state.authenticationState = 'authenticated';
      state.discoveryState = list.length > 0 ? 'success' : 'empty';
      if (results) renderCredentials(documentRef, list, results, state.selectedCredentialKey, selectCredential);
      renderSelectedSecretFields();
      setStatus(list.length > 0 ? 'Connection successful.' : 'Connection successful. No credentials are currently available.');
    } catch (error) {
      reset();
      state.authenticationState = error?.status === 401 || error?.status === 403 ? 'failed' : 'unknown';
      state.discoveryState = 'error';
      setStatus(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }

  form?.addEventListener('submit', discover);
  return { state, discover, resolve, reset };
}

createConsumerController();
