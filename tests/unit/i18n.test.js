import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { LANGUAGE_STORAGE_KEY, normalizeLanguage, resolveLanguage, t, translationOr, userFacingError } from '../../public/admin/i18n.js';
import en from '../../public/admin/locales/en.js';
import de from '../../public/admin/locales/de.js';

test('resolves English by default and German only for German browser languages', () => {
  assert.equal(resolveLanguage(), 'en');
  assert.equal(resolveLanguage({ browserLanguage: 'de-DE' }), 'de');
  assert.equal(resolveLanguage({ browserLanguage: 'de-AT' }), 'de');
  assert.equal(resolveLanguage({ browserLanguage: 'en-US' }), 'en');
  assert.equal(resolveLanguage({ storedLanguage: 'invalid', browserLanguage: 'de-DE' }), 'en');
  assert.equal(resolveLanguage({ storedLanguage: '', browserLanguage: 'de-DE' }), 'en');
});

test('dynamic UI translations use readable metadata fallbacks instead of error messages', () => {
  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (message) => warnings.push(message);
  assert.equal(translationOr('missing.field.label', 'Custom field', {}, 'de'), 'Custom field');
  console.warn = originalWarn;
  assert.deepEqual(warnings, ['Missing translation: missing.field.label']);
  assert.equal(translationOr('field.apiKey.label', 'apiKey', {}, 'en'), 'API key');
  assert.equal(translationOr('field.apiKey.label', 'apiKey', {}, 'de'), 'API-Schluessel');
  assert.equal(translationOr('field.host.label', 'host', {}, 'de'), 'Host');
});

test('uses a valid stored preference over the browser language', () => {
  assert.equal(resolveLanguage({ storedLanguage: 'de', browserLanguage: 'en-US' }), 'de');
  assert.equal(resolveLanguage({ storedLanguage: 'en', browserLanguage: 'de-DE' }), 'en');
  assert.equal(normalizeLanguage('invalid'), null);
  assert.equal(LANGUAGE_STORAGE_KEY, 'credentialHub.language');
});

test('keeps English as the complete fallback catalog', () => {
  for (const key of Object.keys(en)) {
    assert.ok(de[key], `German catalog is missing ${key}`);
  }
  assert.equal(t('wizard.stepOf', { step: 1, total: 5 }, 'en'), 'Step 1 of 5');
  assert.equal(t('wizard.stepOf', { step: 1, total: 5 }, 'de'), 'Schritt 1 von 5');
  assert.equal(t('missing.key', {}, 'de'), 'Something went wrong. Try again. If the problem continues, check the service status or contact an administrator.');
});

test('renders the actual redirect URI in a localized mismatch error', () => {
  const redirectUri = 'https://hub.example.test/oauth/google/callback';
  assert.match(userFacingError({ code: 'OAUTH_REDIRECT_URI_MISMATCH', redirectUri }), /https:\/\/hub\.example\.test\/oauth\/google\/callback/);
});

test('provides actionable localized guidance for the admin error states', () => {
  assert.match(t('errors.apiUnavailable', {}, 'en'), /running.*refresh the page/i);
  assert.match(t('errors.apiUnavailable', {}, 'de'), /Dienst nicht erreichen.*laden Sie die Seite neu/i);
  assert.match(t('wizard.selectAuthError', {}, 'en'), /available methods.*refresh the page/i);
  assert.match(t('wizard.selectAuthError', {}, 'de'), /verfuegbare Methode.*Provider-Konfiguration/i);
  assert.match(t('errors.unexpected', {}, 'en'), /Try again.*service status/i);
  assert.match(t('errors.unexpected', {}, 'de'), /erneut.*Dienststatus/i);
});

test('keeps the Custom Provider admin page fully localized in both catalogs', () => {
  const html = fs.readFileSync(path.resolve('public/admin/providers.html'), 'utf8');
  const script = fs.readFileSync(path.resolve('public/admin/providers.js'), 'utf8');
  const requiredKeys = [
    'providers.title', 'providers.detailsTitle', 'providers.methodsTitle',
    'providers.fieldsTitle', 'providers.reviewTitle', 'providers.invalidMethods',
    'providers.invalidFields', 'providers.created', 'providers.noMethods',
    'providers.noFields'
  ];

  for (const key of requiredKeys) {
    assert.equal(typeof en[key], 'string', `English catalog is missing ${key}`);
    assert.equal(typeof de[key], 'string', `German catalog is missing ${key}`);
  }

  assert.match(html, /data-i18n="providers\.title"/);
  assert.match(html, /data-i18n="providers\.detailsTitle"/);
  assert.match(html, /data-i18n-placeholder="providers\.idPlaceholder"/);
  assert.match(script, /onLanguageChange\(\(\) =>/);
  assert.doesNotMatch(script, /<legend>Method \$\{/);
  assert.doesNotMatch(script, /Add at least one valid credential method\./);
});
