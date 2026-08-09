import { applicationPath } from './base-path.js';
import { ConsumerApiClient } from '../shared/consumer-api.js';
import { onLanguageChange, t } from './i18n.js';

export { ConsumerApiClient } from '../shared/consumer-api.js';

const STORAGE_KEY = 'credential-hub.management-token';
const LEGACY_USER_HEADER = 'x-credential-hub-user';
const defaultFetch = (...args) => globalThis.fetch(...args);

function normalizeToken(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizedHeaders(source = {}) {
  const headers = {};
  const add = (name, value) => { headers[String(name).toLowerCase()] = String(value); };
  if (source && typeof source.forEach === 'function') {
    source.forEach((value, name) => add(name, value));
  } else {
    for (const name in source) {
      if (Object.prototype.hasOwnProperty.call(source, name)) add(name, source[name]);
    }
  }
  return headers;
}

function sessionStorageOrNull() {
  try {
    return globalThis.sessionStorage ?? null;
  } catch {
    return null;
  }
}

function apiError(body, status) {
  const error = new Error(body?.error?.message ?? body?.message ?? (typeof body === 'string' ? body : `HTTP ${status}`));
  error.code = body?.error?.code ?? body?.code;
  error.messageKey = body?.error?.messageKey ?? body?.messageKey;
  error.redirectUri = body?.error?.details?.redirectUri;
  error.status = status;
  return error;
}

export class ManagementTokenStore {
  constructor({ storage = sessionStorageOrNull(), key = STORAGE_KEY } = {}) {
    this.storage = storage;
    this.key = key;
    this.memoryToken = '';
  }

  getToken() {
    try {
      return normalizeToken(this.storage?.getItem(this.key)) || this.memoryToken;
    } catch {
      return this.memoryToken;
    }
  }

  setToken(value) {
    const token = normalizeToken(value);
    if (!token) throw new Error('Ein Management-Token ist erforderlich.');
    this.memoryToken = token;
    try {
      this.storage?.setItem(this.key, token);
    } catch {
      // The current page continues to work when browser storage is unavailable.
    }
  }

  clearToken() {
    this.memoryToken = '';
    try {
      this.storage?.removeItem(this.key);
    } catch {
      // The in-memory fallback has already been cleared.
    }
  }
}

export class AdminApiClient {
  constructor({ tokenStore = new ManagementTokenStore(), fetchImpl = defaultFetch } = {}) {
    this.tokenStore = tokenStore;
    this.fetchImpl = fetchImpl;
  }

  async request(path, options = {}) {
    const { headers: suppliedHeaders = {}, ...requestOptions } = options;
    const headers = normalizedHeaders(suppliedHeaders);
    if (headers.authorization || headers[LEGACY_USER_HEADER]) {
      throw new Error('Admin-Requests dürfen keine eigene Authentifizierung setzen.');
    }
    const usesBasicAuthentication = Object.keys(headers).some((name) => /^Basic\s/i.test(headers[name]));
    if (usesBasicAuthentication) {
      throw new Error('Basic Authentication wird von der Admin-API nicht unterstützt.');
    }

    const token = this.tokenStore.getToken();
    if (!token) throw new Error('Kein Management-Token gespeichert.');

    headers.accept = 'application/json';
    headers.authorization = `Bearer ${token}`;
    if (requestOptions.body != null && !headers['content-type']) headers['content-type'] = 'application/json';

    const response = await this.fetchImpl(applicationPath(path), { ...requestOptions, headers });
    const contentType = response.headers.get('content-type') ?? '';
    const body = contentType.includes('application/json') ? await response.json() : await response.text();
    if (!response.ok || body?.success === false) throw apiError(body, response.status);
    return body;
  }

  get(path, options) { return this.request(path, { ...options, method: 'GET' }); }
  post(path, body, options) { return this.request(path, { ...options, method: 'POST', body: JSON.stringify(body) }); }
  put(path, body, options) { return this.request(path, { ...options, method: 'PUT', body: JSON.stringify(body) }); }
  delete(path, options) { return this.request(path, { ...options, method: 'DELETE' }); }
}

export const managementTokenStore = new ManagementTokenStore();
export const adminApi = new AdminApiClient({ tokenStore: managementTokenStore });
export const consumerApi = new ConsumerApiClient();

export async function authenticateAdmin() {
  const existingToken = managementTokenStore.getToken();
  let loginError = null;
  if (existingToken) {
    try {
      await adminApi.get('/api/v1/dashboard');
      setAdminAuthenticated(true);
      return true;
    } catch (error) {
      managementTokenStore.clearToken();
      loginError = error;
      renderAdminLogin(loginError);
    }
  } else {
    renderAdminLogin();
  }
  return new Promise((resolve) => {
    const bindLoginForm = () => {
      const page = document.getElementById('admin-login-page');
      if (!page) return;
      const form = page.querySelector('form');
      const input = form.elements['management-token'];
      const errorBox = page.querySelector('[data-login-error]');
      const submit = form.querySelector('button[type="submit"]');
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        errorBox.textContent = '';
        errorBox.classList.add('hidden');
        try {
          managementTokenStore.setToken(input.value);
          submit.disabled = true;
          await adminApi.get('/api/v1/dashboard');
          page.remove();
          setAdminAuthenticated(true);
          resolve(true);
        } catch (error) {
          managementTokenStore.clearToken();
          loginError = error;
          errorBox.textContent = error?.status === 403 ? t('admin.authentication.forbidden') : t('admin.authentication.invalid');
          errorBox.classList.remove('hidden');
          submit.disabled = false;
          input.focus();
        }
      });
      input.focus();
    };

    onLanguageChange(() => {
      if (!document.getElementById('admin-login-page')) return;
      renderAdminLogin(loginError);
      bindLoginForm();
    });
    bindLoginForm();
  });
}

function renderAdminLogin(error = null) {
  setAdminAuthenticated(false);
  document.querySelector('.layout')?.classList.add('hidden');
  document.querySelector('.app-footer')?.classList.add('hidden');
  document.querySelector('#app-navigation')?.classList.add('hidden');
  let page = document.getElementById('admin-login-page');
  if (!page) {
    page = document.createElement('main');
    page.id = 'admin-login-page';
    page.className = 'admin-login-page';
    document.body.insertBefore(page, document.querySelector('.layout'));
  }
  page.innerHTML = `<section class="panel admin-login-panel" aria-labelledby="admin-login-title"><p class="eyebrow">${t('admin.authentication.eyebrow')}</p><h2 id="admin-login-title">${t('admin.authentication.title')}</h2><p>${t('admin.authentication.help')}</p><form class="admin-login-form" data-testid="admin-login-form"><label for="admin-login-token">${t('admin.authentication.label')}</label><input id="admin-login-token" name="management-token" type="password" autocomplete="off" spellcheck="false" required><button class="primary" type="submit" data-testid="admin-login-submit">${t('admin.authentication.submit')}</button><p class="admin-login-error${error ? '' : ' hidden'}" data-login-error role="alert">${error ? (error.status === 403 ? t('admin.authentication.forbidden') : t('admin.authentication.invalid')) : ''}</p></form><p class="admin-login-note">${t('admin.authentication.note')}</p></section>`;
}

function setAdminAuthenticated(authenticated) {
  document.body.classList.toggle('admin-authenticated', authenticated);
  for (const selector of ['.layout', '.app-footer', '#app-navigation']) {
    document.querySelector(selector)?.classList.toggle('hidden', !authenticated);
  }
}

export function mountManagementTokenControl() {
  const target = document.querySelector('.app-header');
  if (!target || document.getElementById('management-token-control')) return;

  const form = document.createElement('form');
  form.id = 'management-token-control';
  form.className = 'management-token-control';
  form.setAttribute('aria-describedby', 'management-token-help management-token-status');
  form.innerHTML = '<div class="management-token-heading"><strong data-token-label></strong><span class="management-token-purpose" data-token-purpose></span></div><div class="management-token-entry"><label for="management-token" data-token-input-label></label><input id="management-token" name="management-token" type="password" autocomplete="off" spellcheck="false"><button class="secondary" type="submit" data-token-use></button><button class="secondary" type="button" data-action="clear-token" data-token-clear></button></div><p id="management-token-help" class="management-token-help" data-token-help></p><p id="management-token-status" class="management-token-status" data-token-status role="status" aria-live="polite"></p>';
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    try {
      managementTokenStore.setToken(form.elements['management-token'].value);
      renderManagementTokenControl(form);
      globalThis.location?.reload();
    } catch (error) {
      form.querySelector('[data-token-error]')?.remove();
      const message = document.createElement('span');
      message.dataset.tokenError = 'true';
      message.className = 'status';
      message.textContent = error.message;
      form.append(message);
    }
  });
  form.querySelector('[data-action="clear-token"]').addEventListener('click', () => {
    managementTokenStore.clearToken();
    renderManagementTokenControl(form);
    globalThis.location?.reload();
  });
  target.append(form);
  renderManagementTokenControl(form);
  onLanguageChange(() => renderManagementTokenControl(form));
}

function renderManagementTokenControl(form) {
  const hasToken = Boolean(managementTokenStore.getToken());
  form.querySelector('[data-token-label]').textContent = t('admin.managementToken.title');
  form.querySelector('[data-token-purpose]').textContent = t('admin.managementToken.purpose');
  form.querySelector('[data-token-input-label]').textContent = t('admin.managementToken.label');
  form.querySelector('[data-token-input-label]').setAttribute('for', 'management-token');
  form.querySelector('[data-token-use]').textContent = t('admin.managementToken.use');
  form.querySelector('[data-token-clear]').textContent = t('admin.managementToken.clear');
  form.querySelector('[data-token-help]').textContent = t('admin.managementToken.help');
  const status = form.querySelector('[data-token-status]');
  status.textContent = t(hasToken ? 'admin.managementToken.ready' : 'admin.managementToken.required');
  status.classList.toggle('is-ready', hasToken);
  status.classList.toggle('is-required', !hasToken);
}
