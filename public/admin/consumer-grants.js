import { adminApi, managementTokenStore } from './auth.js';
import { buildConsumerProfileSuggestion, listConsumerProfileTemplates } from './consumer-profiles.js';
import { getLanguage, initI18n, onLanguageChange, t } from './i18n.js';
import { mountAdminShell } from './admin-shell.js';

initI18n();
await mountAdminShell();

const statusBadge = document.getElementById('consumer-grants-status');
const tableBody = document.getElementById('consumer-grants-table-body');
const filterForm = document.getElementById('consumer-grants-filter-form');
const errorBox = document.getElementById('consumer-grants-error');
const successBox = document.getElementById('consumer-grants-success');
const editPanel = document.getElementById('consumer-grant-edit-panel');
const editForm = document.getElementById('consumer-grant-edit-form');
const editSummary = document.getElementById('consumer-grant-edit-summary');
const editError = document.getElementById('consumer-grant-edit-error');
const editSubmit = document.getElementById('consumer-grant-edit-submit');
const editConsumer = document.getElementById('consumer-grant-edit-consumer');
const editCredential = document.getElementById('consumer-grant-edit-credential');
const editProvider = document.getElementById('consumer-grant-edit-provider');
const refreshButton = document.getElementById('refresh-consumer-grants');
const refreshStatus = document.getElementById('consumer-grants-refresh-status');
const grantsTable = document.querySelector('.data-table');
const createPanel = document.getElementById('consumer-grant-create-panel');
const createForm = document.getElementById('consumer-grant-create-form');
const createError = document.getElementById('consumer-grant-create-error');
const createCredential = document.getElementById('consumer-grant-create-credential');
const createProvider = document.getElementById('consumer-grant-create-provider');
const createSecrets = document.getElementById('consumer-grant-create-secrets');
const createPreview = document.querySelector('#consumer-grant-create-preview .grant-preview-content');
const editPreview = document.querySelector('#consumer-grant-edit-preview .grant-preview-content');
const createReferenceCheck = document.getElementById('consumer-grant-create-reference-check');
const editReferenceCheck = document.getElementById('consumer-grant-edit-reference-check');
const createProfile = document.getElementById('consumer-grant-create-profile');
const profileDescription = document.getElementById('consumer-grant-profile-description');
const profileSuggestion = document.getElementById('consumer-grant-profile-suggestion');
const scopeConsumer = document.getElementById('consumer-access-scope-consumer');
const scopeResult = document.getElementById('consumer-access-scope-result');

let grants = [];
let consumers = new Map();
let credentials = new Map();
let editGrant = null;
let lastTrigger = null;

document.getElementById('refresh-consumer-grants').addEventListener('click', () => loadGrants());
document.getElementById('clear-consumer-grants-filter').addEventListener('click', () => { filterForm.reset(); loadGrants(); });
filterForm.addEventListener('submit', (event) => { event.preventDefault(); loadGrants(); });
tableBody.addEventListener('click', (event) => {
  const remove = event.target.closest('button[data-remove-grant-id]');
  if (remove) { void removeGrant(remove.dataset.removeGrantId); return; }
  const button = event.target.closest('button[data-grant-id]');
  if (!button) return;
  const grant = grants.find((item) => item.grantId === button.dataset.grantId);
  if (grant) { lastTrigger = button; openEdit(grant); }
});
document.getElementById('consumer-grant-edit-close').addEventListener('click', closeEdit);
document.getElementById('consumer-grant-edit-cancel').addEventListener('click', closeEdit);
editForm.addEventListener('submit', submitEdit);
document.getElementById('consumer-grant-create-open').addEventListener('click', openCreate);
document.getElementById('consumer-grant-create-close').addEventListener('click', closeCreate);
document.getElementById('consumer-grant-create-cancel').addEventListener('click', closeCreate);
createCredential.addEventListener('change', renderCreateSecrets);
createForm.elements.consumerId.addEventListener('input', renderCreatePreview);
createCredential.addEventListener('change', renderCreatePreview);
createProfile.addEventListener('change', renderProfileSuggestion);
document.getElementById('consumer-grant-apply-profile').addEventListener('click', applyProfileSuggestions);
document.getElementById('consumer-access-scope-load').addEventListener('click', loadAccessScope);
createSecrets.addEventListener('change', renderCreatePreview);
createForm.addEventListener('submit', submitCreate);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && !editSubmit.disabled) closeEdit(); });
onLanguageChange(() => { renderGrants(grants); renderCreatePreview(); renderProfileSuggestion(); if (editGrant) updateEditSummary(); });
void loadGrants();

async function loadGrants({ preserveMessages = false } = {}) {
  if (!managementTokenStore.getToken()) {
    setStatus(t('consumerGrants.tokenNeeded'));
    renderTokenRequired();
    return false;
  }
  if (!preserveMessages) hideMessages();
  setStatus(t('consumerGrants.loading'));
  setLoading(true);
  try {
    const [response, tokenResult, credentialResult] = await Promise.all([
      request(`/api/v1/management/consumer-grants${filterQuery()}`),
      request('/api/v1/management/api-tokens').catch(() => null),
      request('/api/v1/credentials?pageSize=500').catch(() => null)
    ]);
    if (!Array.isArray(response.data)) throw new Error('MALFORMED_RESPONSE');
    grants = response.data;
    consumers = new Map((tokenResult?.data ?? []).map((token) => [token.id, token]));
    credentials = new Map((credentialResult?.data ?? []).map((credential) => [credential.credentialId, credential]));
    renderGrants(grants);
    renderCreateOptions();
    const requestedGrantId = new URLSearchParams(window.location.search).get('grantId');
    if (requestedGrantId) await fetchGrantDetail(requestedGrantId);
    setStatus(t('consumerGrants.ready', { count: grants.length }));
    setRefreshStatus();
    statusBadge.classList.remove('down');
    return true;
  } catch (error) {
    grants = [];
    renderGrants(grants);
    setStatus(t('consumerGrants.unavailable'));
    statusBadge.classList.add('down');
    showError(errorBox, grantError(error, 'load'));
    return false;
  } finally {
    setLoading(false);
  }
}

async function fetchGrantDetail(grantId) {
  try {
    const response = await request(`/api/v1/management/consumer-grants/${encodeURIComponent(grantId)}`);
    if (response?.data) return response.data;
    throw Object.assign(new Error('NOT_FOUND'), { code: 'NOT_FOUND' });
  } catch (error) {
    showError(errorBox, grantError(error, 'load'));
    throw error;
  }
}

function filterQuery() {
  const params = new URLSearchParams();
  for (const key of ['consumerId', 'credentialId', 'providerKey']) {
    const value = String(filterForm.elements.namedItem(key)?.value ?? '').trim();
    if (value) params.set(key, value);
  }
  const query = params.toString();
  return query ? `?${query}` : '';
}

function renderTokenRequired() {
  tableBody.replaceChildren();
  const cell = document.createElement('td'); cell.colSpan = 7;
  const empty = document.createElement('div'); empty.className = 'empty-state';
  const title = document.createElement('h3'); title.textContent = t('consumerGrants.tokenNeeded');
  const help = document.createElement('p'); help.textContent = t('consumerGrants.tokenNeededHelp');
  empty.append(title, help); cell.append(empty);
  const row = document.createElement('tr'); row.append(cell); tableBody.append(row);
}

function renderGrants(items) {
  tableBody.replaceChildren();
  if (!managementTokenStore.getToken()) return renderTokenRequired();
  if (items.length === 0) {
    const cell = document.createElement('td'); cell.colSpan = 7;
    const empty = document.createElement('div'); empty.className = 'empty-state';
    const hasFilter = Boolean(filterQuery());
    const title = document.createElement('h3'); title.textContent = t(hasFilter ? 'consumerGrants.noneFiltered' : 'consumerGrants.none');
    const help = document.createElement('p'); help.textContent = t(hasFilter ? 'consumerGrants.noneFilteredHelp' : 'consumerGrants.noneHelp');
    empty.append(title, help); cell.append(empty);
    const row = document.createElement('tr'); row.append(cell); tableBody.append(row);
    return;
  }
  for (const grant of items) {
    const row = document.createElement('tr');
    row.append(detailCell(consumerLabel(grant.consumerId), technicalDetail(grant.consumerId)));
    row.append(detailCell(credentialLabel(grant.credentialId), technicalDetail(grant.credentialId)));
    row.append(detailCell(providerLabel(grant.providerKey)));
    row.append(secretNamesCell(grant.secretNames));
    const state = grantState(grant);
    row.append(detailCell(state.label, state.reason));
    row.append(detailCell(formatDate(grant.updatedAt)));
    const actions = document.createElement('td');
    const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'secondary small'; edit.dataset.grantId = grant.grantId; edit.textContent = t('consumerGrants.edit');
    const scope = document.createElement('button'); scope.type = 'button'; scope.className = 'secondary small'; scope.dataset.scopeConsumer = grant.consumerId; scope.textContent = t('consumerGrants.viewScope');
    scope.addEventListener('click', () => { scopeConsumer.value = grant.consumerId; void loadAccessScope(); });
    if (state.orphaned) {
      const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'danger small'; remove.dataset.removeGrantId = grant.grantId; remove.textContent = t('consumerGrants.removeGrant');
      actions.append(remove);
    } else actions.append(edit, scope);
    row.append(actions); tableBody.append(row);
  }
}

async function loadAccessScope() {
  const consumerId = String(scopeConsumer.value ?? '').trim();
  if (!consumerId) return;
  scopeResult.textContent = t('consumerGrants.scopeLoading');
  try {
    const response = await request(`/api/v1/management/consumer-grants/access-scope?consumerId=${encodeURIComponent(consumerId)}`);
    const scope = response.data;
    scopeResult.replaceChildren();
    const summary = document.createElement('p');
    summary.textContent = `${t('consumerGrants.scopeSummary')}: ${scope.summary.credentialCount} ${t('consumerGrants.scopeCredentials')}, ${scope.summary.providerCount} ${t('consumerGrants.scopeProviders')}, ${scope.summary.secretFieldAssignmentCount} ${t('consumerGrants.scopeFields')}, ${scope.summary.activeGrantCount} ${t('consumerGrants.scopeGrants')}`;
    scopeResult.append(summary);
    for (const credential of scope.credentials ?? []) {
      const item = document.createElement('p');
      item.textContent = `${credential.displayName} (${credential.providerKey}) — ${(credential.permittedSecretFields ?? []).join(', ')}`;
      scopeResult.append(item);
    }
  } catch (error) { scopeResult.textContent = grantError(error, 'load'); }
}

function detailCell(value, detail = null) {
  const cell = document.createElement('td');
  const primary = document.createElement('strong'); primary.textContent = value || t('common.unknown'); cell.append(primary);
  if (detail) { const secondary = document.createElement('small'); secondary.textContent = detail; cell.append(secondary); }
  return cell;
}

function technicalDetail(value) { return value ? `${t('consumerGrants.technicalId')}: ${value}` : null; }
function consumerTokenId(token) { return token?.id ?? token?.userId ?? token?.consumerId ?? ''; }
function consumerLabel(id) {
  const consumer = consumers.get(id);
  return consumer?.name || consumer?.displayName || consumer?.label || id || t('common.unknown');
}
function credentialLabel(id) {
  const credential = credentials.get(id);
  return credential?.display?.name || credential?.displayName || credential?.metadata?.displayName || credential?.externalReference || id || t('common.unknown');
}
function providerLabel(providerKey) {
  return providerKey || t('common.unknown');
}

function grantState(grant) {
  const credential = credentials.get(grant.credentialId);
  if (!consumers.has(grant.consumerId)) return { label: t('consumerGrants.orphanConsumer'), reason: t('consumerGrants.noAuthority'), orphaned: true };
  if (!credential) return { label: t('consumerGrants.orphanCredential'), reason: t('consumerGrants.noAuthority'), orphaned: true };
  if (grant.credentialGeneration && grant.credentialGeneration !== credential.credentialGeneration) return { label: t('consumerGrants.staleBinding'), reason: t('consumerGrants.noAuthority'), orphaned: true };
  if (credential.lifecycleState === 'revoked' || credential.lifecycleState === 'deleted') return { label: t('consumerGrants.inactiveCredential'), reason: t('consumerGrants.noAuthority'), orphaned: true };
  return { label: t('consumerGrants.active'), reason: null, orphaned: false };
}

async function removeGrant(grantId) {
  if (!window.confirm(t('consumerGrants.removeGrantConfirm'))) return;
  try {
    await request(`/api/v1/management/consumer-grants/${encodeURIComponent(grantId)}`, { method: 'DELETE' });
    if (await loadGrants({ preserveMessages: true })) showSuccess(t('consumerGrants.removeGrantSuccess'));
  } catch (error) { showError(errorBox, grantError(error, 'delete')); }
}

function secretNamesCell(names) {
  const cell = document.createElement('td');
  const list = document.createElement('div'); list.className = 'tags';
  for (const name of names ?? []) { const tag = document.createElement('span'); tag.className = 'tag'; tag.textContent = name; list.append(tag); }
  cell.append(list); return cell;
}

function renderCreateOptions() {
  const entries = [...credentials.values()];
  createCredential.replaceChildren();
  for (const credential of entries) {
    const option = document.createElement('option');
    option.value = credential.credentialId;
    option.textContent = credentialLabel(credential.credentialId);
    createCredential.append(option);
  }
  if (entries.length) createCredential.value = entries[0].credentialId;
  renderProfileOptions();
  renderCreateSecrets();
}

function renderProfileOptions() {
  createProfile.replaceChildren();
  for (const profile of listConsumerProfileTemplates()) {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = profile.label;
    createProfile.append(option);
  }
  createProfile.value = 'none';
  renderProfileSuggestion();
}

function renderProfileSuggestion() {
  const credential = credentials.get(createCredential.value);
  const suggestion = buildConsumerProfileSuggestion(createProfile.value || 'none', credential);
  profileDescription.textContent = `${t('consumerGrants.profileClassification')}: ${suggestion.classification}. ${suggestion.description}`;
  profileSuggestion.replaceChildren();
  const settings = document.createElement('p');
  settings.textContent = `${t('consumerGrants.profileScope')}: ${suggestion.recommendedScopes.join(', ')}. ${t('consumerGrants.profileFields')}: ${suggestion.suggestedSecretFields.join(', ') || t('consumerGrants.previewNone')}.`;
  const hint = document.createElement('p');
  hint.textContent = suggestion.documentationHint;
  profileSuggestion.append(settings, hint);
}

function applyProfileSuggestions() {
  const credential = credentials.get(createCredential.value);
  const suggestion = buildConsumerProfileSuggestion(createProfile.value || 'none', credential);
  if (suggestion.suggestedConsumerId) createForm.elements.consumerId.value = suggestion.suggestedConsumerId;
  renderCreateSecrets({ selectedNames: suggestion.suggestedSecretFields });
  renderProfileSuggestion();
}

function renderCreateSecrets({ selectedNames = [] } = {}) {
  const credential = credentials.get(createCredential.value);
  createProvider.textContent = credential ? `${t('common.provider')}: ${providerLabel(credential.providerKey)}` : '';
  createSecrets.replaceChildren();
  for (const name of credential?.secretNames ?? credential?.secretInventory?.map((field) => field.name) ?? []) {
    const label = document.createElement('label'); label.className = 'checkbox-row';
    const input = document.createElement('input'); input.type = 'checkbox'; input.name = 'secretNames'; input.value = name; input.dataset.grantSecret = name;
    input.checked = selectedNames.includes(name);
    label.append(input, document.createTextNode(` ${name}`)); createSecrets.append(label);
  }
  renderProfileSuggestion();
  renderCreatePreview();
}

function openCreate() {
  hideMessages(); hideError(createError); renderCreateOptions(); renderCreatePreview(); createPanel.classList.remove('hidden');
  createForm.elements.consumerId.focus();
}

function closeCreate() { createPanel.classList.add('hidden'); hideError(createError); }

async function submitCreate(event) {
  event.preventDefault(); hideError(createError);
  const credential = credentials.get(createForm.elements.credentialId.value);
  const secretNames = [...createForm.querySelectorAll('input[name="secretNames"]:checked')].map((input) => input.value);
  if (!credential || !secretNames.length) { showError(createError, t('consumerGrants.secretsRequired')); return; }
  const submit = document.getElementById('consumer-grant-create-submit'); submit.disabled = true;
  try {
    await request('/api/v1/management/consumer-grants', { method: 'POST', body: JSON.stringify({
      consumerId: createForm.elements.consumerId.value.trim(), consumerName: 'UI test consumer', credentialId: credential.credentialId,
      providerKey: credential.providerKey, secretNames
    }) });
    closeCreate();
    if (await loadGrants({ preserveMessages: true })) showSuccess(t('consumerGrants.createSuccess'));
  } catch (error) { showError(createError, grantError(error, 'create')); }
  finally { submit.disabled = false; }
}

function openEdit(grant) {
  hideMessages(); hideError(editError); editGrant = grant;
  editConsumer.textContent = `${consumerLabel(grant.consumerId)} (${technicalDetail(grant.consumerId)})`;
  editCredential.textContent = `${credentialLabel(grant.credentialId)} (${technicalDetail(grant.credentialId)})`;
  editProvider.textContent = providerLabel(grant.providerKey);
  editForm.elements.secretNames.value = (grant.secretNames ?? []).join('\n');
  editSummary.replaceChildren(
    summaryLine(t('consumerGrants.grantId'), grant.grantId),
    summaryLine(t('consumerGrants.consumer'), `${consumerLabel(grant.consumerId)} (${technicalDetail(grant.consumerId)})`),
    summaryLine(t('consumerGrants.credential'), `${credentialLabel(grant.credentialId)} (${technicalDetail(grant.credentialId)})`),
    summaryLine(t('common.provider'), providerLabel(grant.providerKey)),
    summaryLine(t('consumerGrants.permissionSummary'), permissionSummary(grant.consumerId, grant.credentialId)),
    summaryLine(t('consumerGrants.secrets'), (grant.secretNames ?? []).join(', '))
  );
  void renderAuthoritativePreview(editPreview, {
    consumerId: grant.consumerId,
    credentialId: grant.credentialId,
    providerKey: grant.providerKey,
    secretNames: grant.secretNames ?? [],
    grantId: grant.grantId
  });
  editPanel.classList.remove('hidden');
  editForm.elements.secretNames.focus();
}

function permissionSummary(consumerId, credentialId) {
  return t('consumerGrants.permissionSummaryText', {
    consumer: consumerLabel(consumerId),
    credential: credentialLabel(credentialId)
  });
}

function updateEditSummary() {
  if (!editGrant) return;
  editSummary.replaceChildren(
    summaryLine(t('consumerGrants.grantId'), editGrant.grantId),
    summaryLine(t('consumerGrants.permissionSummary'), permissionSummary(editGrant.consumerId, editGrant.credentialId)),
    summaryLine(t('common.provider'), editProvider.textContent),
    summaryLine(t('consumerGrants.secrets'), String(editForm.elements.secretNames.value ?? '').split(/[\n,]/).map((name) => name.trim()).filter(Boolean).join(', '))
  );
  void renderAuthoritativePreview(editPreview, {
    consumerId: editGrant.consumerId,
    credentialId: editGrant.credentialId,
    providerKey: editGrant.providerKey,
    secretNames: parseSecretNames(editForm.elements.secretNames.value),
    grantId: editGrant.grantId
  });
}

function renderCreatePreview() {
  const selected = [...createForm.querySelectorAll('input[name="secretNames"]:checked')].map((input) => input.value);
  void renderAuthoritativePreview(createPreview, {
    consumerId: createForm.elements.consumerId.value,
    credentialId: createForm.elements.credentialId.value,
    providerKey: credentials.get(createForm.elements.credentialId.value)?.providerKey,
    secretNames: selected
  });
}

function previewState(credentialId, selectedNames) {
  const credential = credentials.get(credentialId);
  const allNames = credential?.secretNames ?? credential?.secretInventory?.map((field) => field.name) ?? [];
  const selected = [...new Set(selectedNames)];
  return { allNames, selected, credential, hasInventory: allNames.length > 0 };
}

function renderPreview(container, { allNames, selected, credential, hasInventory }) {
  if (!container) return;
  container.replaceChildren();
  const summary = document.createElement('div'); summary.className = 'grant-preview-summary';
  const excluded = hasInventory
    ? allNames.filter((name) => !selected.includes(name)).join(', ') || t('consumerGrants.previewNone')
    : t('consumerGrants.previewExcludedUnavailable');
  const items = [
    [true, t('consumerGrants.previewCredential'), credential ? `${credentialLabel(credential.credentialId)} / ${providerLabel(credential.providerKey)}` : t('common.none')],
    [true, t('consumerGrants.previewDiscovery'), t('consumerGrants.previewDiscoveryValue')],
    [selected.length > 0, t('consumerGrants.previewResolve'), selected.length ? selected.join(', ') : t('consumerGrants.previewNone')],
    [true, t('consumerGrants.previewRuntimePublic'), t('consumerGrants.previewRuntimePublicValue')],
    [false, t('consumerGrants.previewExcluded'), excluded],
    [false, t('consumerGrants.previewProtected'), t('consumerGrants.previewProtectedValue')]
  ];
  for (const [allowed, label, value] of items) {
    const line = document.createElement('p'); line.className = allowed ? 'grant-preview-allowed' : 'grant-preview-excluded';
    const marker = document.createElement('strong'); marker.textContent = allowed ? '✓' : '✗';
    line.append(marker, document.createTextNode(` ${label}: ${value}`)); summary.append(line);
  }
  container.append(summary);
  const notice = document.createElement('p'); notice.className = selected.length ? 'grant-preview-note' : 'grant-warning';
  notice.textContent = t(selected.length ? 'consumerGrants.previewSelectionWarning' : 'consumerGrants.previewEmptyWarning');
  container.append(notice);
}

async function renderAuthoritativePreview(container, input) {
  if (!container) return;
  const referenceContainer = input.grantId ? editReferenceCheck : createReferenceCheck;
  const consumerId = String(input.consumerId ?? '').trim();
  if (!consumerId || !input.credentialId || !input.providerKey) {
    container.textContent = t('consumerGrants.scopePreviewUnavailable');
    renderReferenceCheck(referenceContainer, { decision: 'NEEDS_RECHECK', reason: t('consumerGrants.referenceCheckIncomplete') });
    return;
  }
  container.textContent = t('consumerGrants.scopeLoading');
  renderReferenceCheck(referenceContainer, { decision: 'CHECKING' });
  try {
    const response = await request('/api/v1/management/consumer-grants/preview', { method: 'POST', body: JSON.stringify(input) });
    const { current, proposed, delta, binding, referenceCheck } = response.data;
    renderReferenceCheck(referenceContainer, binding ?? referenceCheck);
    container.replaceChildren();
    const summary = document.createElement('p');
    summary.textContent = `${t('consumerGrants.scopeSummary')}: ${current.summary.credentialCount} → ${proposed.summary.credentialCount} ${t('consumerGrants.scopeCredentials')}; ${current.summary.secretFieldAssignmentCount} → ${proposed.summary.secretFieldAssignmentCount} ${t('consumerGrants.scopeFields')}; ${t(`consumerGrants.scopeDelta.${delta.status}`)}.`;
    container.append(summary);
    if (delta.added.length || delta.removed.length) {
      const detail = document.createElement('p');
      detail.textContent = `${t('consumerGrants.scopeAdded')}: ${delta.added.join(', ') || t('consumerGrants.previewNone')}; ${t('consumerGrants.scopeRemoved')}: ${delta.removed.join(', ') || t('consumerGrants.previewNone')}`;
      container.append(detail);
    }
  } catch (error) {
    container.textContent = t('consumerGrants.scopePreviewUnavailable');
    renderReferenceCheck(referenceContainer, error?.binding ?? { decision: 'BLOCKED', reason: t('consumerGrants.referenceCheckBlocked') });
  }
}

function renderReferenceCheck(container, result = {}) {
  if (!container) return;
  container.replaceChildren();
  const state = result.decision ?? 'NEEDS_RECHECK';
  const heading = document.createElement('strong');
  heading.textContent = t(`consumerGrants.referenceCheck.${state}`);
  container.append(heading);
  if (result.reason) {
    const reason = document.createElement('p'); reason.textContent = result.reason; container.append(reason);
  }
  if (result.reasonCode) {
    const code = document.createElement('p'); code.className = 'technical-detail';
    code.textContent = `${t('consumerGrants.referenceCheckReason')}: ${result.reasonCode}`; container.append(code);
  }
  if (result.remediationHint) {
    const hint = document.createElement('p'); hint.textContent = result.remediationHint; container.append(hint);
  }
}

function parseSecretNames(value) {
  return String(value ?? '').split(/[\n,]/).map((name) => name.trim()).filter(Boolean);
}

function summaryLine(label, value) { const line = document.createElement('span'); line.textContent = `${label}: ${value || t('common.none')}`; return line; }

async function submitEdit(event) {
  event.preventDefault();
  if (!editGrant) return;
  hideError(editError);
  const secretNames = parseSecretNames(editForm.elements.secretNames.value);
  if (!secretNames.length) { showError(editError, t('consumerGrants.secretsRequired')); return; }
  setSubmitting(true);
  try {
    await request(`/api/v1/management/consumer-grants/${encodeURIComponent(editGrant.grantId)}`, {
      method: 'PUT',
      body: JSON.stringify({
        consumerId: editGrant.consumerId,
        credentialId: editGrant.credentialId,
        secretNames
      })
    });
    closeEdit();
    if (await loadGrants({ preserveMessages: true })) showSuccess(t('consumerGrants.updateSuccess'));
  } catch (error) {
    showError(editError, grantError(error, 'update'));
  } finally { setSubmitting(false); }
}

editForm.elements.secretNames.addEventListener('input', updateEditSummary);

function closeEdit() { editPanel.classList.add('hidden'); editGrant = null; lastTrigger?.focus(); }
function formatDate(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? t('common.unknown') : date.toLocaleString(getLanguage()); }
function setSubmitting(value) { editSubmit.disabled = value; editSubmit.textContent = value ? t('consumerGrants.saving') : t('consumerGrants.save'); }
function setLoading(value) {
  refreshButton.disabled = value;
  filterForm.querySelectorAll('button').forEach((button) => { button.disabled = value; });
  grantsTable.setAttribute('aria-busy', String(value));
  if (value) renderLoading();
}
function renderLoading() {
  tableBody.replaceChildren();
  const cell = document.createElement('td'); cell.colSpan = 7;
  const empty = document.createElement('div'); empty.className = 'empty-state loading-state';
  const title = document.createElement('h3'); title.textContent = t('consumerGrants.loading');
  const help = document.createElement('p'); help.textContent = t('consumerGrants.loadingHelp');
  empty.append(title, help); cell.append(empty);
  const row = document.createElement('tr'); row.append(cell); tableBody.append(row);
}
function setRefreshStatus() { refreshStatus.textContent = t('consumerGrants.lastUpdated', { time: new Date().toLocaleTimeString(getLanguage()) }); }
function setStatus(value) { statusBadge.textContent = value; }
function hideMessages() { errorBox.classList.add('hidden'); successBox.classList.add('hidden'); }
function hideError(element) { element.classList.add('hidden'); }
function showError(element, message) { element.textContent = message; element.classList.remove('hidden'); }
function showSuccess(message) { successBox.textContent = message; successBox.classList.remove('hidden'); }
function grantError(error, operation) {
  if (error?.code === 'UNAUTHORIZED' || error?.code === 'FORBIDDEN') return t('consumerGrants.notAuthorized');
  if (error?.code === 'NOT_FOUND') return t('consumerGrants.notFound');
  if (operation === 'create') return t('consumerGrants.createFailed');
  return operation === 'update' ? t('consumerGrants.updateFailed') : t('consumerGrants.loadFailed');
}

async function request(path, options = {}) {
  return adminApi.request(path, options);
}
