// Copyright (C) 2026 cyphre-san productions
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { adminApi } from './auth.js';
import { applicationPath } from './base-path.js';
import { getLanguage, initI18n, onLanguageChange, t, userFacingError } from './i18n.js';
import { mountAdminShell } from './admin-shell.js';

initI18n();
await mountAdminShell();

const status = document.getElementById('dashboard-status');
const managementError = document.getElementById('management-error');
let latestDashboard = null;

await loadDashboard();

async function loadDashboard() {
  try {
    const [body, providerDetails] = await Promise.all([
      adminApi.get('/api/v1/dashboard'),
      loadOAuthProviderDetails()
    ]);
    if (body.success !== true) {
      const error = new Error('Dashboard request failed');
      error.code = body.error?.code;
      throw error;
    }

    latestDashboard = { ...body.data, providerDetails };
    renderDashboard(latestDashboard);
    status.textContent = t('dashboard.ready');
    status.classList.remove('down');
    managementError.classList.add('hidden');
  } catch (error) {
    status.textContent = t('dashboard.unavailable');
    status.classList.add('down');
    managementError.textContent = userFacingError(error);
    managementError.classList.remove('hidden');
  }
}

async function loadOAuthProviderDetails() {
  try {
    const body = await adminApi.get('/api/v1/providers');
    return body.success === true ? body.data ?? [] : [];
  } catch {
    return [];
  }
}

function renderDashboard(data) {
  const credentials = data.credentials ?? {};
  const providers = data.providers ?? {};
  const scheduler = data.scheduler ?? {};

  setText('dashboard-credentials', number(credentials.total));
  setText('dashboard-providers', number(providers.total));
  setText('dashboard-expired', number(credentials.expiredCount));
  setText('dashboard-expiring', number(credentials.expiringSoonCount));

  setText('management-system-status', statusLabel(data.lifecycle?.health));
  setText('management-generated-at', data.generatedAt
    ? t('dashboard.updatedAt', { value: formatDateTime(data.generatedAt) })
    : t('dashboard.updatedUnknown'));
  setText('management-credentials-total', number(credentials.total));
  renderCountList('management-credentials-state', credentials.byLifecycleState, t('dashboard.noLifecycle'));
  renderCountList('management-credentials-methods', credentials.byCredentialMethod, t('dashboard.noCredentialMethods'));
  setText('management-providers-total', number(providers.total));
  renderCountList('management-provider-credentials', {
    withCredentials: providers.withCredentials,
    withoutCredentials: providers.withoutCredentials
  }, t('dashboard.noProviderAssignments'));
  renderCountList('management-provider-capabilities', providers.byCapability, t('dashboard.noCapabilities'));
  setText('management-scheduler-state', schedulerStateLabel(scheduler));
  setText('management-scheduler-details', scheduler.available === false
    ? t('dashboard.noScheduler')
    : t('dashboard.schedulerDetails', {
        jobs: number(scheduler.jobCount),
        runs: number(scheduler.runCount),
        errors: number(scheduler.failureCount)
      }));

  renderIntegrationHealth(data.integrationHealth ?? {});

  renderWarnings(data.warnings ?? {});
  renderScheduler(scheduler);
  renderOAuthDetails(data.providerDetails ?? []);
}

function renderIntegrationHealth(health) {
  const counts = health.counts ?? {};
  for (const key of ['healthy', 'warning', 'error', 'unknown']) {
    setText(`integration-health-${key}`, number(counts[key]));
  }

  const target = document.getElementById('integration-health-list');
  target.replaceChildren();
  const items = Array.isArray(health.items) ? health.items : [];
  if (items.length === 0) {
    target.textContent = t('dashboard.integrationHealthUnavailable');
    return;
  }

  for (const integration of items) {
    const card = document.createElement('article');
    card.className = `integration-health-card status-${integration.status ?? 'unknown'}`;
    const heading = document.createElement('div');
    heading.className = 'integration-health-heading';
    const title = document.createElement('h3');
    title.textContent = integration.displayName ?? integration.credentialId ?? t('dashboard.unknown');
    const overall = document.createElement('span');
    overall.className = 'status-pill';
    overall.textContent = healthLabel(integration.status);
    heading.append(title, overall);
    card.append(heading);

    const provider = document.createElement('p');
    provider.className = 'integration-health-provider';
    provider.textContent = `${t('dashboard.provider')}: ${integration.providerKey ?? t('dashboard.unknown')}`;
    card.append(provider);

    const list = document.createElement('dl');
    for (const key of ['credential', 'grant', 'oauth', 'token', 'refresh', 'resolve']) {
      const entry = integration[key];
      if (!entry) continue;
      const row = document.createElement('div');
      const term = document.createElement('dt');
      term.textContent = t(`dashboard.integration.${key}`);
      const value = document.createElement('dd');
      value.className = `status-text status-${entry.status ?? 'unknown'}`;
      value.textContent = healthLabel(entry.status);
      if (key === 'grant' && Number.isFinite(Number(entry.count))) {
        value.textContent += ` (${entry.count})`;
      }
      row.append(term, value);
      list.append(row);
    }
    card.append(list);
    target.append(card);
  }
}

function healthLabel(value) {
  return t(`dashboard.health.${value ?? 'unknown'}`);
}

function renderOAuthDetails(providers) {
  const target = document.getElementById('dashboard-oauth-details');
  const oauthProviders = providers.filter((provider) => provider.oauthTechnical);
  target.replaceChildren();

  if (oauthProviders.length === 0) {
    target.textContent = t('dashboard.noOAuthDetails');
    return;
  }

  for (const provider of oauthProviders) {
    const details = document.createElement('details');
    details.className = 'technical-details provider-context-card';
    const summary = document.createElement('summary');
    summary.textContent = provider.displayName ?? provider.key;
    details.append(summary);

    const values = [
      [t('wizard.oauth.redirectUri'), provider.oauthTechnical.redirectUri],
      [t('wizard.oauth.authorizationEndpoint'), provider.oauthTechnical.authorizationEndpoint],
      [t('wizard.oauth.callbackPath'), provider.oauthTechnical.callbackPath],
      [t('common.scopes'), (provider.defaultScopes ?? []).join(' ') || t('wizard.oauth.noScopes')]
    ];
    const list = document.createElement('dl');
    list.className = 'oauth-registration-details';
    for (const [label, value] of values) {
      const row = document.createElement('div');
      const term = document.createElement('dt');
      const description = document.createElement('dd');
      const code = document.createElement('code');
      term.textContent = label;
      code.textContent = value ?? '-';
      description.append(code);
      row.append(term, description);
      list.append(row);
    }
    details.append(list);
    target.append(details);
  }
}

function renderWarnings(warnings) {
  const entries = [
    ['dashboard.warningExpired', warnings.expiredCredentials],
    ['dashboard.warningExpiring', warnings.expiringSoonCredentials],
    ['dashboard.warningUnknownProvider', warnings.unknownProviderCredentials]
  ].filter(([, values]) => Array.isArray(values) && values.length > 0);
  const target = document.getElementById('dashboard-warnings');
  target.replaceChildren();
  if (entries.length === 0) {
    const empty = document.createElement('p');
    empty.textContent = t('dashboard.noWarnings');
    target.append(empty);
    return;
  }

  const list = document.createElement('ul');
  for (const [key, values] of entries) {
    const group = document.createElement('li');
    const summary = document.createElement('strong');
    summary.textContent = t(key, { count: values.length });
    group.append(summary);
    const affected = document.createElement('ul');
    for (const value of values) {
      const item = document.createElement('li');
      const credentialId = typeof value === 'object' ? value.credentialId : value;
      const name = typeof value === 'object' && value.displayName ? value.displayName : credentialId;
      item.append(document.createTextNode(`${name} `));
      const link = document.createElement('a');
      link.href = applicationPath('/admin/credentials.html');
      link.textContent = t('dashboard.openCredentials');
      item.append(link);
      affected.append(item);
    }
    group.append(affected);
    list.append(group);
  }
  target.append(list);
}

function renderScheduler(scheduler) {
  const target = document.getElementById('dashboard-scheduler');
  if (scheduler.available === false) {
    target.innerHTML = `<p>${t('dashboard.noScheduler')}</p>`;
    return;
  }
  target.innerHTML = `<p><strong>${schedulerStateLabel(scheduler)}</strong></p><p>${t('dashboard.schedulerDetails', {
    jobs: number(scheduler.jobCount),
    runs: number(scheduler.runCount),
    errors: number(scheduler.failureCount)
  })}</p>`;
}

function renderCountList(id, counts, emptyText) {
  const target = document.getElementById(id);
  target.replaceChildren();
  const entries = Object.entries(counts ?? {});
  if (entries.length === 0) {
    target.textContent = emptyText;
    return;
  }
  const list = document.createElement('ul');
  for (const [key, count] of entries
    .sort(([left], [right]) => left.localeCompare(right, getLanguage()))
  ) {
    const item = document.createElement('li');
    item.textContent = `${countLabel(key)}: ${count}`;
    list.append(item);
  }
  target.append(list);
}

function countLabel(value) {
  const labels = {
    active: t('dashboard.countActive'),
    registered: t('dashboard.countRegistered'),
    expired: t('dashboard.countExpired'),
    'api-key': t('dashboard.countApiKey'),
    oauth: t('dashboard.countOauth2'),
    oauth2: t('dashboard.countOauth2'),
    webhook: t('dashboard.countWebhook'),
    refresh: t('dashboard.countRefresh'),
    'health-check': t('dashboard.countHealthCheck'),
    validation: t('dashboard.countValidation'),
    revoke: t('dashboard.countRevoke'),
    withCredentials: t('dashboard.countWithCredentials'),
    withoutCredentials: t('dashboard.countWithoutCredentials')
  };
  return labels[value] ?? value;
}

function schedulerStateLabel(scheduler) {
  if (scheduler.available === false) return t('dashboard.notAvailable');
  if (scheduler.running) return t('dashboard.schedulerRunning');
  if (scheduler.started) return t('dashboard.schedulerStarted');
  return t('dashboard.schedulerStopped');
}

function statusLabel(value) {
  return t(`dashboard.status.${value ?? 'unknown'}`);
}

function number(value) {
  return Number.isFinite(Number(value)) ? String(Number(value)) : '0';
}

function formatDateTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(getLanguage());
}

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

onLanguageChange(() => {
  if (latestDashboard) {
    renderDashboard(latestDashboard);
    status.textContent = t('dashboard.ready');
  }
});
