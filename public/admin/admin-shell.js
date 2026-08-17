import { applicationPath } from './base-path.js';
import { authenticateAdmin, mountManagementTokenControl } from './auth.js';
import { onLanguageChange, t } from './i18n.js';
import { PROJECT_LINKS } from './project-links.js';

const EXTERNAL_LINK_ATTRIBUTES = 'target="_blank" rel="noopener noreferrer"';

export async function mountAdminShell() {
  renderAdminContext();
  resolveApplicationLinks();
  renderNavigation();
  renderFooter();
  onLanguageChange(() => {
    renderAdminContext();
    renderNavigation();
    renderFooter();
  });
  await authenticateAdmin();
  mountManagementTokenControl();
}

function renderAdminContext() {
  const header = document.querySelector('.app-header');
  if (!header) return;

  const brand = header.querySelector(':scope > div');
  if (!brand) return;

  let context = header.querySelector('#admin-context-indicator');
  if (!context) {
    context = document.createElement('div');
    context.id = 'admin-context-indicator';
    context.className = 'admin-context-indicator';
    context.setAttribute('role', 'status');
    brand.append(context);
  }

  context.innerHTML = `<span class="admin-context-label">${t('admin.context.label')}</span><span class="admin-context-help">${t('admin.context.help')}</span>`;
}

function resolveApplicationLinks() {
  document.querySelectorAll('[data-app-path]').forEach((link) => {
    link.setAttribute('href', applicationPath(link.dataset.appPath));
  });
}

function renderNavigation() {
  const navigation = document.querySelector('#app-navigation');
  if (!navigation) return;
  navigation.setAttribute('aria-label', t('nav.primary'));
  navigation.innerHTML = `
    <a href="${applicationPath('/admin/dashboard.html')}">${t('nav.dashboard')}</a>
    <a href="${applicationPath('/admin/')}">${t('nav.wizard')}</a>
    <a href="${applicationPath('/admin/providers.html')}">${t('nav.providers')}</a>
    <a href="${applicationPath('/admin/credentials.html')}" data-testid="admin-nav-credentials">${t('nav.credentials')}</a>
    <a href="${applicationPath('/admin/consumer-grants.html')}">${t('nav.consumerGrants')}</a>
    <a href="${applicationPath('/admin/api-tokens.html')}">${t('nav.apiTokens')}</a>
    <a href="${applicationPath('/admin/credential-transfer.html')}">${t('nav.transfer')}</a>`;
}

function renderFooter() {
  const footer = document.querySelector('#app-footer');
  if (!footer) return;
  footer.innerHTML = `
    <div><strong>${t('support.openSource')}</strong><span>AGPL-3.0-only</span></div>
    <div><strong>Sekalum</strong><span>Maintained by Working Curiosity</span></div>
    <div><strong>${t('support.title')}</strong><a href="mailto:luiscyphre404@gmail.com">luiscyphre404@gmail.com</a><a href="https://discord.gg/exTu3Dy2UW" ${EXTERNAL_LINK_ATTRIBUTES}>Discord ↗</a></div>
    <div><a href="${applicationPath(PROJECT_LINKS.license)}">LICENSE</a><a href="${applicationPath(PROJECT_LINKS.notice)}">NOTICE</a><a href="${applicationPath(PROJECT_LINKS.thirdPartySoftware)}">${t('support.thirdParty')}</a></div>
    <p>${t('support.securityNotice')} <a href="${applicationPath(PROJECT_LINKS.security)}">SECURITY.md</a></p>`;
}
