// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import en from './locales/en.js';
import de from './locales/de.js';

export const LANGUAGE_STORAGE_KEY = 'credentialHub.language';
export const SUPPORTED_LANGUAGES = Object.freeze(['en', 'de']);

const catalogs = Object.freeze({ en, de });
const listeners = new Set();
const missingTranslationWarnings = new Set();
let currentLanguage = 'en';

const legacyTextKeys = Object.freeze({
  'Zum Dashboard': 'nav.dashboard',
  'Zurück zum Dashboard': 'nav.backToDashboard',
  'Weiter': 'wizard.next',
  'Zurück': 'wizard.back',
  'Credential anlegen': 'wizard.create',
  'OAuth starten': 'wizard.oauth.start',
  'Dashboard wird geladen…': 'dashboard.loading',
  'API wird geprüft…': 'wizard.apiChecking',
  'Credentials aktualisieren': 'transfer.refresh',
  'Aktualisieren': 'common.refresh',
  'Schließen': 'common.close',
  'Abbrechen': 'common.cancel',
  'API-Token erstellen': 'apiTokens.create',
  'Credential Wizard': 'wizard.title',
  'Wizard-Schritte': 'wizard.steps',
  'Wizard-Fortschritt': 'wizard.progress',
  'Authentifizierung': 'wizard.step.selectAuth',
  '1. Authentifizierung': 'wizard.step1',
  '2. Provider': 'wizard.step2',
  '3. Daten': 'wizard.step3',
  '4. Autorisierung': 'wizard.step4',
  '5. Prüfung': 'wizard.step5',
  'Daten': 'wizard.step.captureCredentials',
  'Autorisierung': 'wizard.step.authorizeOAuth',
  'Prüfung': 'wizard.step.review',
  'Authentifizierungsart auswählen': 'wizard.auth.heading',
  'Provider auswählen': 'wizard.provider.heading',
  'Credential-Daten': 'wizard.data.heading',
  'OAuth-Autorisierung vorbereiten': 'wizard.oauth.heading',
  'Zusammenfassung': 'wizard.review.heading',
  'Systemübersicht': 'dashboard.overview',
  'Management': 'dashboard.management',
  'Credentials': 'dashboard.credentials',
  'Provider': 'dashboard.providers',
  'Abgelaufen': 'dashboard.expired',
  'Laufen bald ab': 'dashboard.expiring',
  'Security & Access': 'dashboard.securityAccess',
  'Scheduler': 'dashboard.scheduler',
  'Systemstatus': 'dashboard.systemStatus',
  'Warnungen': 'dashboard.warnings',
  'API-Token-Übersicht': 'apiTokens.overview',
  'API Tokens': 'apiTokens.title',
  'Credentials exportieren': 'transfer.exportHeading',
  'Credentials importieren': 'transfer.importHeading',
  'Import-Vorschau': 'transfer.previewHeading',
  'Sicheres Transferformat': 'transfer.secureFormat',
  'Import mit Vorschau': 'transfer.importPreview',
  'Importformat': 'transfer.importFormat',
  'Importdatei': 'transfer.file',
  'Dateiinhalt': 'transfer.content',
  'Konfliktstrategie': 'transfer.conflictStrategy',
  'Vorschau prüfen': 'transfer.checkPreview',
  'Import ausführen': 'transfer.runImport',
  'Auswahl': 'transfer.selection',
  'Exportdatei erzeugen': 'transfer.createExport',
  'Alle Credentials exportieren': 'transfer.exportAll',
  'Export-Passwort': 'transfer.password',
  'Import-Passwort': 'transfer.importPassword',
  'Credentials für Export auswählen': 'transfer.selectForExport',
  'Neu anlegen': 'dashboard.newCredential',
  'Verwalten': 'dashboard.manage',
  'Transfer': 'dashboard.transfer',
  'Erstellt': 'apiTokens.created',
  'Ablauf': 'apiTokens.expires',
  'Ablaufdatum': 'apiTokens.expiryDate',
  'Letzte Nutzung': 'apiTokens.lastUsed',
  'Aktionen': 'common.actions',
  'Name': 'common.name',
  'Status': 'common.status',
  'Provider': 'common.provider',
  'Typ': 'common.type',
  'Pflicht': 'common.required'
  , 'Benutzer-ID': 'apiTokens.userId'
  , 'Prefix': 'apiTokens.prefix'
  , 'Scopes': 'common.scopes'
  , 'Credentials werden geladen…': 'transfer.credentialsLoading'
  , 'Typ auswählen': 'wizard.step.selectAuth'
  , 'Schritt 1': 'wizard.stepLabel1'
  , 'Schritt 2': 'wizard.stepLabel2'
  , 'Schritt 3': 'wizard.stepLabel3'
  , 'Schritt 4': 'wizard.stepLabel4'
  , 'Schritt 5': 'wizard.stepLabel5'
  , 'Die verfügbaren Authentifizierungsarten werden aus den registrierten Providerdefinitionen geladen.': 'wizard.auth.help'
  , 'Die Providerliste kommt direkt aus dem eingefrorenen Backend-Vertrag.': 'wizard.provider.help'
  , 'Noch keine Daten geladen.': 'dashboard.noData'
  , 'Lebenszyklus noch nicht geladen.': 'dashboard.lifecyclePending'
  , 'Capabilities noch nicht geladen.': 'dashboard.capabilitiesPending'
  , 'Scheduler noch nicht geladen.': 'dashboard.schedulerPending'
  , 'Ein neues Credential mit einem registrierten Provider anlegen.': 'dashboard.newCredentialHelp'
  , 'Technische Zugriffe anzeigen und absichern.': 'dashboard.apiTokensHelp'
  , 'Verschlüsselte Exportdateien erzeugen und importieren.': 'dashboard.transferHelp'
  , 'API Tokens werden geladen…': 'apiTokens.loading'
  , 'Diese Übersicht zeigt technische REST-API-Zugriffe. Token-Klartexte und Token-Hashes werden hier nicht angezeigt.': 'apiTokens.overviewHelp'
  , 'Neuer REST-Zugriff': 'apiTokens.newAccess'
  , 'Interner Anzeigename für diesen technischen Zugriff.': 'apiTokens.nameHelp'
  , 'Der Token authentifiziert diese Benutzer-ID; RBAC entscheidet weiterhin über Berechtigungen.': 'apiTokens.userIdHelp'
  , 'Optional. Ohne Ablaufdatum bleibt der Token aktiv, bis er widerrufen wird.': 'apiTokens.expiryHelp'
  , 'Optional. Ein Scope pro Zeile oder kommasepariert.': 'apiTokens.scopesHelp'
  , 'Einmalige Anzeige': 'apiTokens.oneTime'
  , 'API-Token wurde erstellt': 'apiTokens.createdTitle'
  , 'Kopiere den Token jetzt und speichere ihn sicher. Er wird nach dem Schließen nicht erneut angezeigt.': 'apiTokens.createdHelp'
  , 'Token-Klartext': 'apiTokens.plaintext'
  , 'Token kopieren': 'apiTokens.copy'
  , 'Verstanden': 'apiTokens.understood'
  , 'Zugriff widerrufen': 'apiTokens.revokeAccess'
  , 'API-Token widerrufen': 'apiTokens.revokeTitle'
  , 'Dieser API-Token wird sofort für REST-Zugriffe gesperrt.': 'apiTokens.revokeNotice'
  , 'Der Token-Klartext kann danach nicht wiederhergestellt werden. Bestehende Clients müssen einen neuen Token erhalten.': 'apiTokens.revokeHelp'
  , 'Erzeuge eine verschlüsselte Sekalum-Exportdatei. Die Datei kann später über die Import-Vorschau geprüft und eingelesen werden.': 'transfer.exportHelp'
  , 'Dieses Passwort wird zum Entschlüsseln beim Import benötigt.': 'transfer.passwordHelp'
  , 'Füge eine Sekalum-Exportdatei oder eine CSV-Migrationsdatei ein. Vor dem Schreiben wird immer zuerst eine Vorschau angezeigt.': 'transfer.importHelp'
  , 'Sekalum-Exportdatei': 'transfer.transferFile'
  , 'CSV-Migrationsimport': 'transfer.csv'
  , 'Alternativ kann der Dateiinhalt unten eingefügt werden.': 'transfer.fileHelp'
  , 'Pflicht bei verschlüsselten Dateien': 'transfer.importPasswordRequired'
  , 'Konflikte überspringen': 'transfer.skip'
  , 'Bestehende überschreiben': 'transfer.overwrite'
  , 'Importierte umbenennen': 'transfer.rename'
  , 'CSV-Pflichtfelder: providerKey, externalReference und mindestens eine Secret-Spalte, z. B. apiKey oder secret.clientSecret.': 'transfer.csvFieldsHelp'
  , 'Aktion': 'transfer.action'
  , 'Konflikt': 'transfer.conflict'
});

export function normalizeLanguage(value) {
  return SUPPORTED_LANGUAGES.includes(value) ? value : null;
}

export function resolveLanguage({ storedLanguage = null, browserLanguage = '' } = {}) {
  if (storedLanguage !== null && storedLanguage !== undefined) {
    return normalizeLanguage(storedLanguage) ?? 'en';
  }
  return String(browserLanguage).toLowerCase().startsWith('de') ? 'de' : 'en';
}

export function getLanguage() {
  return currentLanguage;
}

export function t(key, params = {}, language = currentLanguage) {
  const template = catalogs[language]?.[key] ?? catalogs.en[key] ?? catalogs.en['errors.unexpected'];
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, name) => String(params[name] ?? `{${name}}`));
}

export function translationOr(key, fallback, params = {}, language = currentLanguage) {
  const template = catalogs[language]?.[key] ?? catalogs.en[key];
  if (template === undefined) {
    if (!missingTranslationWarnings.has(key)) {
      missingTranslationWarnings.add(key);
      console.warn(`Missing translation: ${key}`);
    }
    return String(fallback ?? key);
  }
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, name) => String(params[name] ?? `{${name}}`));
}

export function userFacingError(error) {
  const code = error?.code;
  const known = code ? `errors.${code}` : null;
  return known && catalogs.en[known] ? t(known, error) : t('errors.unexpected');
}

export function setLanguage(language, storage = globalThis.localStorage) {
  currentLanguage = normalizeLanguage(language) ?? 'en';
  storage?.setItem?.(LANGUAGE_STORAGE_KEY, currentLanguage);
  applyDocumentLanguage();
  listeners.forEach((listener) => listener(currentLanguage));
  return currentLanguage;
}

export function onLanguageChange(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function initI18n({ storage = globalThis.localStorage, browserLanguage = globalThis.navigator?.language } = {}) {
  const storedLanguage = storage?.getItem?.(LANGUAGE_STORAGE_KEY);
  currentLanguage = resolveLanguage({ storedLanguage, browserLanguage });
  applyDocumentLanguage();
  return currentLanguage;
}

function applyDocumentLanguage() {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = currentLanguage;
  document.title = pageTitle();
  document.querySelectorAll('[data-i18n]').forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((element) => {
    element.setAttribute('placeholder', t(element.dataset.i18nPlaceholder));
  });
  document.querySelectorAll('[data-i18n-aria-label]').forEach((element) => {
    element.setAttribute('aria-label', t(element.dataset.i18nAriaLabel));
  });
  translateLegacyStaticText();
  mountLanguageSwitch();
}

function pageTitle() {
  const path = globalThis.location?.pathname ?? '';
  if (path.endsWith('/dashboard.html')) return t('page.dashboardTitle');
  if (path.endsWith('/api-tokens.html')) return t('page.apiTokensTitle');
  if (path.endsWith('/credentials.html')) return t('page.credentialsTitle');
  if (path.endsWith('/credential-transfer.html')) return t('page.transferTitle');
  if (path.endsWith('/providers.html')) return t('page.providersTitle');
  return t('page.wizardTitle');
}

function translateLegacyStaticText() {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const node of nodes) {
    const source = node.textContent.trim();
    const key = legacyTextKeys[source];
    if (key) {
      if (node.parentElement?.childNodes.length === 1) {
        node.parentElement.setAttribute('data-i18n', key);
      }
      node.textContent = node.textContent.replace(source, t(key));
    }
  }
}

function mountLanguageSwitch() {
  const header = document.querySelector('.app-header');
  if (!header) return;
  const existing = document.getElementById('language-switch');
  if (existing) {
    existing.setAttribute('aria-label', t('language.label'));
    existing.querySelectorAll('[data-language]').forEach((button) => {
      button.setAttribute('aria-pressed', String(button.dataset.language === currentLanguage));
    });
    return;
  }
  const switcher = document.createElement('div');
  switcher.id = 'language-switch';
  switcher.className = 'language-switch';
  switcher.setAttribute('role', 'group');
  switcher.setAttribute('aria-label', t('language.label'));
  for (const language of SUPPORTED_LANGUAGES) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'language-switch-button';
    button.dataset.language = language;
    button.textContent = t(`language.${language}`);
    button.setAttribute('aria-pressed', String(language === currentLanguage));
    button.addEventListener('click', () => setLanguage(language));
    switcher.append(button);
  }
  header.append(switcher);
}
