import { adminApi } from './auth.js';
import { getLanguage, initI18n, onLanguageChange, t, translationOr } from './i18n.js';
import { mountAdminShell } from './admin-shell.js';

initI18n();
await mountAdminShell();

const statusBadge = document.getElementById('credentials-status');
const tableBody = document.getElementById('credentials-table-body');
const errorBox = document.getElementById('credentials-error');
const successBox = document.getElementById('credentials-success');
const refreshButton = document.getElementById('refresh-credentials');
const editPanel = document.getElementById('credential-edit-panel');
const editForm = document.getElementById('credential-edit-form');
const editFields = document.getElementById('credential-edit-fields');
const editMeta = document.getElementById('credential-edit-meta');
const editError = document.getElementById('credential-edit-error');
const editSubmit = document.getElementById('credential-edit-submit');
const detailPanel = document.getElementById('credential-detail-panel');
const detailMeta = document.getElementById('credential-detail-meta');
const detailFields = document.getElementById('credential-detail-fields');
const detailError = document.getElementById('credential-detail-error');
const deletePanel = document.getElementById('credential-delete-panel');
const deleteMessage = document.getElementById('credential-delete-message');
const deleteError = document.getElementById('credential-delete-error');
const deleteConfirm = document.getElementById('credential-delete-confirm');
const deleteCancel = document.getElementById('credential-delete-cancel');
const revokePanel = document.getElementById('credential-revoke-panel');
const revokeMessage = document.getElementById('credential-revoke-message');
const revokeError = document.getElementById('credential-revoke-error');
const revokeConfirm = document.getElementById('credential-revoke-confirm');
const revokeCancel = document.getElementById('credential-revoke-cancel');

let credentials = [];
let providerCapabilities = new Map();
let editState = null;
let deleteState = null;
let revokeState = null;
let lastTrigger = null;

refreshButton.addEventListener('click', () => loadCredentials());
tableBody.addEventListener('click', (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  lastTrigger = button;
  const credential = credentials.find((entry) => entry.credentialId === button.dataset.credentialId);
  if (!credential) return;
  if (button.dataset.action === 'view') openDetail(credential);
  if (button.dataset.action === 'edit') openEdit(credential);
  if (button.dataset.action === 'validate') validateCredential(credential, button);
  if (button.dataset.action === 'delete') openDelete(credential);
  if (button.dataset.action === 'revoke') openRevoke(credential);
});
document.getElementById('credential-edit-close').addEventListener('click', closeEdit);
document.getElementById('credential-edit-cancel').addEventListener('click', closeEdit);
document.getElementById('credential-detail-close').addEventListener('click', closeDetail);
document.getElementById('credential-delete-close').addEventListener('click', closeDelete);
document.getElementById('credential-revoke-close').addEventListener('click', closeRevoke);
deleteCancel.addEventListener('click', closeDelete);
editForm.addEventListener('submit', submitEdit);
deleteConfirm.addEventListener('click', confirmDelete);
revokeCancel.addEventListener('click', closeRevoke);
revokeConfirm.addEventListener('click', confirmRevoke);
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (!detailPanel.classList.contains('hidden')) closeDetail();
  if (!editSubmit.disabled) closeEdit();
  if (!deleteConfirm.disabled) closeDelete();
  if (!revokeConfirm.disabled) closeRevoke();
});
onLanguageChange(() => renderCredentials(credentials));
loadCredentials().then(() => {
  const requestedCredentialId = new URLSearchParams(window.location.search).get('credentialId');
  if (!requestedCredentialId) return;
  const listed = credentials.find((entry) => entry.credentialId === requestedCredentialId);
  openDetail(listed ?? { credentialId: requestedCredentialId });
});

async function loadCredentials({ preserveMessages = false } = {}) {
  setStatus(t('credentials.loading'));
  if (!preserveMessages) hideMessages();
  try {
    const [body, providers] = await Promise.all([
      request('/api/v1/credentials?pageSize=500'),
      request('/api/v1/providers')
    ]);
    if (!Array.isArray(body.data)) throw new Error('MALFORMED_RESPONSE');
    providerCapabilities = new Map((providers.data ?? []).map((provider) => [provider.key ?? provider.providerKey, provider.capabilities ?? []]));
    credentials = body.data;
    renderCredentials(credentials);
    setStatus(t('credentials.ready', { count: credentials.length }));
    statusBadge.classList.remove('down');
    return true;
  } catch (error) {
    setStatus(t('credentials.unavailable'));
    statusBadge.classList.add('down');
    showError(errorBox, credentialError(error, 'load'));
    return false;
  }
}

function renderCredentials(items) {
  tableBody.replaceChildren();
  if (items.length === 0) {
    const cell = document.createElement('td');
    cell.colSpan = 6;
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    const title = document.createElement('h3'); title.textContent = t('credentials.none');
    const help = document.createElement('p'); help.textContent = t('credentials.noneHelp');
    empty.append(title, help); cell.append(empty);
    const row = document.createElement('tr'); row.append(cell); tableBody.append(row);
    return;
  }
  for (const credential of items) {
    const row = document.createElement('tr');
    row.append(textCell(displayName(credential), credential.credentialId));
    row.append(textCell(credential.providerName ?? credential.providerKey ?? t('common.unknown')));
    row.append(textCell(credentialMethodLabel(credential)));
    const status = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = `status-pill status-${String(credential.status ?? credential.lifecycleState ?? 'unknown').toLowerCase()}`;
    pill.textContent = credential.status ?? credential.lifecycleState ?? t('common.unknown');
    status.append(pill); row.append(status);
    row.append(textCell(formatDate(credential.updatedAt ?? credential.createdAt)));
    const actions = document.createElement('td');
    if (canValidate(credential)) actions.append(actionButton('validate', credential, t('credentials.validate'), 'secondary'));
    actions.append(actionButton('view', credential, t('credentials.details'), 'secondary'), actionButton('edit', credential, t('credentials.edit'), 'secondary'));
    if ((credential.supportedActions ?? []).includes('revoke') && credential.status !== 'revoked') {
      actions.append(actionButton('revoke', credential, t('credentials.revoke'), 'danger'));
    }
    actions.append(actionButton('delete', credential, t('credentials.delete'), 'danger'));
    row.append(actions); tableBody.append(row);
  }
}

function canValidate(credential) {
  return (providerCapabilities.get(credential.providerKey) ?? []).includes('validation');
}

function textCell(value, detail = null) {
  const cell = document.createElement('td');
  const primary = document.createElement('strong'); primary.textContent = value; cell.append(primary);
  if (detail) { const secondary = document.createElement('small'); secondary.textContent = detail; cell.append(secondary); }
  return cell;
}

function actionButton(action, credential, label, className) {
  const button = document.createElement('button');
  button.type = 'button'; button.className = `${className} small`;
  button.dataset.action = action; button.dataset.credentialId = credential.credentialId;
  button.textContent = label;
  return button;
}

function displayName(credential) { return credential.display?.name ?? credential.metadata?.displayName ?? credential.externalReference ?? credential.credentialId; }
function credentialMethodLabel(credential) { return credential.credentialMethod?.displayName ?? credential.credentialMethodKey ?? credential.credentialType ?? t('common.unknown'); }
function formatDate(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? t('common.unknown') : date.toLocaleString(getLanguage()); }

async function openEdit(credential) {
  hideMessages(); hideError(editError); editPanel.classList.remove('hidden'); editFields.replaceChildren();
  try {
    const [detailResponse, providerResponse] = await Promise.all([
      request(`/api/v1/credentials/${encodeURIComponent(credential.credentialId)}`),
      request(`/api/v1/providers/${encodeURIComponent(credential.providerKey)}`)
    ]);
    const method = (providerResponse.data?.credentialMethods ?? []).find((candidate) => candidate.key === detailResponse.data.credentialMethodKey) ?? null;
    editState = {
      credential: detailResponse.data,
      method,
      fields: editableFields(method?.credentialFields ?? providerResponse.data?.credentialFields)
    };
    editMeta.replaceChildren(
      metaLine(t('credentials.provider'), detailResponse.data.provider?.displayName ?? credential.providerKey),
      ...(method ? [metaLine(t('credentials.method'), method.displayName ?? method.key)] : []),
      metaLine(t('credentials.credentialId'), credential.credentialId)
    );
    renderEditFields(editState);
    editForm.classList.remove('hidden');
    document.getElementById('credential-edit-cancel').focus();
  } catch (error) {
    editForm.classList.add('hidden'); showError(editError, credentialError(error, 'load'));
  }
}

async function openDetail(credential) {
  hideMessages(); hideError(detailError); detailPanel.classList.remove('hidden'); detailMeta.replaceChildren(); detailFields.replaceChildren();
  try {
    const response = await request(`/api/v1/credentials/${encodeURIComponent(credential.credentialId)}`);
    const detail = response.data;
    detailMeta.replaceChildren(
      metaLine(t('credentials.credentialId'), detail.credentialId),
      metaLine(t('credentials.provider'), detail.provider?.displayName ?? detail.providerName ?? detail.providerKey),
      metaLine(t('common.status'), detail.status ?? detail.lifecycleState ?? t('common.unknown'))
    );
    const values = [
      [t('common.name'), detail.metadata?.displayName ?? detail.displayName ?? detail.externalReference],
      [t('credentials.description'), detail.metadata?.description ?? ''],
      [t('credentials.updated'), formatDate(detail.updatedAt ?? detail.createdAt)]
    ].filter(([, value]) => value != null && value !== '');
    for (const [label, value] of values) {
      const term = document.createElement('dt'); term.textContent = label;
      const description = document.createElement('dd'); description.className = 'credential-detail-field'; description.textContent = value;
      detailFields.append(term, description);
    }
    document.getElementById('credential-detail-close').focus();
  } catch (error) {
    showError(detailError, credentialError(error, 'load'));
  }
}

function editableFields(fields) {
  return (fields ?? []).filter((field) => field.visible !== false && field.userConfigurable !== false && !field.systemManaged && !field.readonly && field.section !== 'providerConfiguration');
}
function metaLine(label, value) { const line = document.createElement('span'); line.textContent = `${label}: ${value}`; return line; }

function renderEditFields(state) {
  editFields.replaceChildren();
  for (const field of state.fields) {
    const wrapper = document.createElement('div'); wrapper.className = 'field';
    const id = `credential-edit-${field.key}`;
    const label = document.createElement('label'); label.htmlFor = id; label.textContent = fieldLabel(field);
    const required = isEditFieldRequired(field, state.credential);
    if (required) {
      const badge = document.createElement('span'); badge.className = 'required-badge'; badge.textContent = t('common.required');
      label.append(badge);
    }
    const input = field.type === 'textarea' || field.type === 'oauth-scope' ? document.createElement('textarea') : document.createElement('input');
    input.id = id; input.name = field.key; input.dataset.credentialField = field.key; input.dataset.secret = String(Boolean(field.secret));
    if (input.tagName === 'INPUT') input.type = inputType(field); else input.rows = field.type === 'oauth-scope' ? 2 : 3;
    if (required) { input.required = true; input.setAttribute('aria-required', 'true'); }
    const help = document.createElement('small'); help.id = `${id}-help`;
    input.setAttribute('aria-describedby', help.id);
    input.addEventListener('input', () => clearFieldError(wrapper, input));
    if (field.secret) {
      input.autocomplete = 'new-password';
      const present = state.credential.secretInventory?.some((secret) => secret.name === field.key && secret.hasValue);
      help.className = 'secret-replacement-help'; help.textContent = present ? t('credentials.secretPresent') : t('credentials.secretReplace');
      wrapper.append(label, input, help);
    } else {
      input.value = editableValue(state.credential, field);
      help.textContent = fieldDescription(field);
      wrapper.append(label, input, help);
    }
    editFields.append(wrapper);
  }
}

function isEditFieldRequired(field, credential) {
  if (!field.required) return false;
  if (!field.secret) return true;
  return !(credential.secretInventory ?? []).some((secret) => secret.name === field.key && secret.hasValue);
}

function validateEditFields() {
  let firstInvalid = null;
  let invalidCount = 0;
  for (const field of editState.fields) {
    const input = editForm.elements.namedItem(field.key);
    const wrapper = input?.closest('.field');
    if (!input || !wrapper) continue;
    clearFieldError(wrapper, input);
    if (!input.required || String(input.value ?? '').trim()) continue;
    invalidCount += 1;
    const error = document.createElement('small');
    error.className = 'field-error';
    error.textContent = t('credentials.fieldRequired');
    error.id = `${input.id}-error`;
    input.setAttribute('aria-describedby', `${input.id}-help ${error.id}`);
    wrapper.classList.add('invalid');
    wrapper.append(error);
    if (!firstInvalid) firstInvalid = input;
  }
  if (firstInvalid) firstInvalid.focus();
  return invalidCount === 0;
}

function clearFieldError(wrapper, input) {
  wrapper.classList.remove('invalid');
  const error = wrapper.querySelector('.field-error');
  if (error) error.remove();
  const help = document.getElementById(`${input.id}-help`);
  if (help) input.setAttribute('aria-describedby', help.id);
}

function inputType(field) { return ['password', 'api-key'].includes(field.type) ? 'password' : field.type === 'integer' ? 'number' : 'text'; }
function fieldLabel(field) { return translationOr(`field.${field.key}.label`, field.label ?? field.key); }
function fieldDescription(field) { return translationOr(`field.${field.key}.help`, field.description ?? ''); }
function editableValue(credential, field) {
  const metadata = credential.metadata ?? {};
  const value = field.key === 'displayName' ? metadata.displayName : field.key === 'description' ? metadata.description : field.key === 'scopes' ? metadata.scopes : metadata.custom?.[field.key];
  return Array.isArray(value) ? value.join(' ') : value ?? '';
}

async function submitEdit(event) {
  event.preventDefault(); hideError(editError);
  if (!validateEditFields()) { showError(editError, t('credentials.requiredFields')); return; }
  const updates = buildUpdates();
  if (!updates) { showError(editError, t('credentials.noChanges')); return; }
  setEditSubmitting(true);
  try {
    await request(`/api/v1/credentials/${encodeURIComponent(editState.credential.credentialId)}`, { method: 'PUT', body: JSON.stringify(updates) });
    closeEdit();
    if (await loadCredentials({ preserveMessages: true })) showSuccess(t('credentials.updateSuccess'));
  } catch (error) {
    showError(editError, credentialError(error, 'update'));
  } finally { setEditSubmitting(false); }
}

async function validateCredential(credential, button) {
  hideMessages();
  button.disabled = true;
  button.textContent = t('credentials.validating');
  try {
    await request(`/api/v1/credentials/${encodeURIComponent(credential.credentialId)}/validate`, { method: 'POST' });
    if (await loadCredentials({ preserveMessages: true })) showSuccess(t('credentials.validateSuccess'));
  } catch (error) {
    showError(errorBox, error?.code === 'NOT_FOUND' ? t('credentials.notFound') : t('credentials.validateFailed'));
  } finally {
    button.disabled = false;
    button.textContent = t('credentials.validate');
  }
}

function buildUpdates() {
  const metadata = {}; const custom = {}; const secrets = [];
  for (const field of editState.fields) {
    const input = editForm.elements.namedItem(field.key); const raw = String(input?.value ?? '');
    if (field.secret) { if (raw.trim()) secrets.push({ name: field.key, value: raw, type: field.type }); continue; }
    const next = field.key === 'scopes' ? raw.split(/[\s,]+/).filter(Boolean) : raw;
    const current = editableValue(editState.credential, field);
    const previous = field.key === 'scopes' ? String(current).split(/[\s,]+/).filter(Boolean) : current;
    if (JSON.stringify(next) === JSON.stringify(previous)) continue;
    if (['displayName', 'description', 'scopes'].includes(field.key)) metadata[field.key] = next; else custom[field.key] = next;
  }
  if (Object.keys(custom).length) metadata.custom = custom;
  if (!Object.keys(metadata).length && !secrets.length) return null;
  return { ...(Object.keys(metadata).length ? { metadata } : {}), ...(secrets.length ? { secrets } : {}) };
}

function openDelete(credential) {
  hideMessages(); hideError(deleteError); deleteState = credential;
  deleteMessage.textContent = t('credentials.deleteMessage', { name: displayName(credential), provider: credential.providerName ?? credential.providerKey ?? t('common.unknown') });
  deletePanel.classList.remove('hidden'); deleteCancel.focus();
}
function openRevoke(credential) {
  hideMessages(); hideError(revokeError); revokeState = credential;
  revokeMessage.textContent = t('credentials.revokeMessage', { name: displayName(credential), provider: credential.providerName ?? credential.providerKey ?? t('common.unknown') });
  revokePanel.classList.remove('hidden'); revokeCancel.focus();
}
async function confirmRevoke() {
  if (!revokeState) return;
  hideError(revokeError); setRevokeSubmitting(true);
  try {
    await request(`/api/v1/credentials/${encodeURIComponent(revokeState.credentialId)}/revoke`, { method: 'POST' });
    closeRevoke();
    if (await loadCredentials({ preserveMessages: true })) showSuccess(t('credentials.revokeSuccess'));
  } catch (error) {
    showError(revokeError, credentialError(error, 'revoke'));
  } finally { setRevokeSubmitting(false); }
}
async function confirmDelete() {
  if (!deleteState) return;
  hideError(deleteError); setDeleteSubmitting(true);
  try {
    await request(`/api/v1/credentials/${encodeURIComponent(deleteState.credentialId)}`, { method: 'DELETE' });
    closeDelete();
    if (await loadCredentials({ preserveMessages: true })) showSuccess(t('credentials.deleteSuccess'));
  } catch (error) {
    showError(deleteError, credentialError(error, 'delete'));
  } finally { setDeleteSubmitting(false); }
}
function closeEdit() { editPanel.classList.add('hidden'); editState = null; lastTrigger?.focus(); }
function closeDetail() { detailPanel.classList.add('hidden'); detailMeta.replaceChildren(); detailFields.replaceChildren(); lastTrigger?.focus(); }
function closeDelete() { deletePanel.classList.add('hidden'); deleteState = null; lastTrigger?.focus(); }
function closeRevoke() { revokePanel.classList.add('hidden'); revokeState = null; lastTrigger?.focus(); }
function setEditSubmitting(value) { editSubmit.disabled = value; editSubmit.textContent = value ? t('credentials.saving') : t('credentials.save'); }
function setDeleteSubmitting(value) { deleteConfirm.disabled = value; deleteCancel.disabled = value; deleteConfirm.textContent = value ? t('credentials.deleting') : t('credentials.confirmDelete'); }
function setRevokeSubmitting(value) { revokeConfirm.disabled = value; revokeCancel.disabled = value; revokeConfirm.textContent = value ? t('credentials.revoking') : t('credentials.confirmRevoke'); }

async function request(path, options = {}) {
  return adminApi.request(path, options);
}
function credentialError(error, operation) { if (error?.code === 'NOT_FOUND') return t('credentials.notFound'); return operation === 'delete' ? t('credentials.deleteFailed') : operation === 'revoke' ? t('credentials.revokeFailed') : operation === 'update' ? t('credentials.updateFailed') : t('credentials.loadFailed'); }
function setStatus(value) { statusBadge.textContent = value; }
function hideMessages() { errorBox.classList.add('hidden'); successBox.classList.add('hidden'); }
function hideError(element) { element.classList.add('hidden'); }
function showError(element, message) { element.textContent = message; element.classList.remove('hidden'); }
function showSuccess(message) { successBox.textContent = message; successBox.classList.remove('hidden'); }
