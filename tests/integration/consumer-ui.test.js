import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { createConsumerController } from '../../public/consumer/consumer.js';

class Element {
  constructor() { this.children = []; this.listeners = {}; this.attributes = {}; this.dataset = {}; this.textContent = ''; this.value = ''; this.disabled = false; this.checked = false; this.hidden = false; this.type = ''; this.name = ''; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  append(...nodes) { this.children.push(...nodes); this.textContent += nodes.map((node) => node.textContent ?? '').join(''); }
  replaceChildren(...nodes) { this.children = nodes; this.textContent = nodes.map((node) => node.textContent ?? '').join(''); }
  setAttribute(name, value) { this.attributes[name] = value; }
  querySelector(selector) { return selector === 'button[type="submit"]' ? this.button : null; }
}

function documentFixture() {
  const form = new Element();
  form.button = new Element();
  const input = new Element();
  const status = new Element();
  const results = new Element();
  const secretSelection = new Element();
  const resolveResults = new Element();
  const resolveResultList = new Element();
  secretSelection.hidden = true;
  resolveResults.hidden = true;
  const nodes = new Map([
    ['#consumer-token-form', form],
    ['#consumer-token', input],
    ['#consumer-status', status],
    ['#consumer-discovery-results', results],
    ['#consumer-secret-selection', secretSelection],
    ['#consumer-resolve-results', resolveResults],
    ['#consumer-resolve-result-list', resolveResultList]
  ]);
  const created = [];
  return {
    documentRef: {
      querySelector: (selector) => nodes.get(selector),
      createElement: () => { const element = new Element(); created.push(element); return element; }
    },
    form,
    input,
    status,
    results,
    secretSelection,
    resolveResults,
    resolveResultList,
    created
  };
}

function discoveryBody(credentials) {
  return { body: { data: { credentials } } };
}

function credential(credentialKey, fields = []) {
  return { credentialKey, metadata: { displayName: credentialKey }, fields };
}

function secretField(name, overrides = {}) {
  return { name, label: name, inputType: 'password', required: true, secret: true, visible: true, ...overrides };
}

test('Consumer controller initializes the WP5 resolve state without resolving', () => {
  const fixture = documentFixture();
  const controller = createConsumerController({ documentRef: fixture.documentRef, apiClient: { async request() { throw new Error('unexpected request'); } } });

  assert.equal(controller.state.resolveState, 'initial');
  assert.equal(controller.state.resolvedCredential, null);
  assert.equal(controller.state.resolveRequestInFlight, false);
  assert.deepEqual(controller.state.requestedSecretNames, []);
});

test('Consumer UI uses the authenticated discovery endpoint and keeps token in memory', async () => {
  const fixture = documentFixture();
  const calls = [];
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request(...args) { calls.push(args); return { body: { data: { credentials: [{ credentialKey: 'public-key', metadata: { displayName: 'Production API' }, fields: [{ name: 'apiKey', label: 'API key', inputType: 'password', required: true }] }] } } }; } }
  });
  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  assert.deepEqual(calls[0], ['/api/v1/consumer/credentials', 'consumer-secret', { method: 'GET' }]);
  assert.equal(controller.state.authenticationState, 'authenticated');
  assert.equal(controller.state.discoveryState, 'success');
  assert.match(fixture.status.textContent, /Connection successful/);
  assert.equal(fixture.results.children.length, 1);
  assert.match(fixture.results.children[0].children[0].textContent, /Production API/);
  assert.equal(fixture.created.filter((element) => element.type === 'radio').length, 1);
  assert.doesNotMatch(JSON.stringify(fixture.results), /credentialId|providerKey|resolved-secret/);
  assert.doesNotMatch(fs.readFileSync(path.resolve('public/consumer/consumer.js'), 'utf8'), /localStorage|sessionStorage|document\.cookie|location\.(search|hash)/);
});

test('Consumer UI does not request discovery without a token', async () => {
  const fixture = documentFixture();
  let requestCount = 0;
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() { requestCount += 1; } }
  });
  await controller.discover({ preventDefault() {} });
  assert.equal(requestCount, 0);
  assert.equal(controller.state.authenticationState, 'missing');
  assert.equal(controller.state.discoveryState, 'initial');
  assert.match(fixture.status.textContent, /Enter a Consumer API token/);
});

test('Consumer UI renders an empty discovery as success and prevents duplicate requests', async () => {
  const fixture = documentFixture();
  let resolveRequest;
  let requestCount = 0;
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { request() { requestCount += 1; return new Promise((resolve) => { resolveRequest = resolve; }); } }
  });
  fixture.input.value = 'consumer-secret';
  const first = controller.discover({ preventDefault() {} });
  const second = controller.discover({ preventDefault() {} });
  assert.equal(requestCount, 1);
  assert.equal(fixture.form.button.disabled, true);
  resolveRequest({ body: { data: { credentials: [] } } });
  await Promise.all([first, second]);
  assert.equal(controller.state.discoveryState, 'empty');
  assert.deepEqual(controller.state.discoveredCredentials, []);
  assert.match(fixture.status.textContent, /No credentials/);
  assert.equal(fixture.form.button.disabled, false);
});

test('Consumer UI clears old results before retry and renders unknown public fields safely', async () => {
  const fixture = documentFixture();
  let resolveRequest;
  let attempt = 0;
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { request() {
      attempt += 1;
      if (attempt === 1) return Promise.resolve({ body: { data: { credentials: [{ credentialKey: 'first-key', metadata: { displayName: 'First' }, fields: [] }] } } });
      return new Promise((resolve) => { resolveRequest = resolve; });
    } }
  });

  fixture.input.value = 'first-token';
  await controller.discover({ preventDefault() {} });
  assert.equal(fixture.results.children.length, 1);

  fixture.input.value = 'second-token';
  const retry = controller.discover({ preventDefault() {} });
  assert.equal(fixture.results.children.length, 0);
  assert.equal(controller.state.discoveryState, 'loading');
  resolveRequest({ body: { data: { credentials: [{
    credentialKey: '<public-key>',
    metadata: { displayName: '<img src=x onerror=alert(1)>' },
    fields: [{ name: 'safe-name', label: 'Safe label', inputType: 'text', required: false, unexpected: 'ignored' }],
    unexpected: 'ignored'
  }] } } });
  await retry;

  assert.equal(controller.state.discoveryState, 'success');
  const rendered = fixture.results.children[0];
  assert.equal(rendered.children[0].textContent, '<img src=x onerror=alert(1)>');
  assert.equal(rendered.children[1].textContent, 'Credential key: <public-key>');
  assert.equal(rendered.children[3].children.length, 1);
  assert.doesNotMatch(fixture.status.textContent, /alert/);
});

test('Consumer UI enforces single selection and updates the selected public credential key', async () => {
  const fixture = documentFixture();
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() {
      return { body: { data: { credentials: [
        { credentialKey: 'first-key', metadata: { displayName: 'First' }, fields: [] },
        { credentialKey: 'second-key', metadata: { displayName: 'Second' }, fields: [] }
      ] } } };
    } }
  });

  assert.equal(fixture.secretSelection.hidden, true);
  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radios = fixture.created.filter((element) => element.type === 'radio');
  assert.equal(radios.length, 2);
  assert.equal(radios[0].name, radios[1].name);
  assert.equal(controller.state.selectedCredentialKey, null);

  radios[0].checked = true;
  radios[0].listeners.change();
  assert.equal(controller.state.selectedCredentialKey, 'first-key');
  radios[1].checked = true;
  radios[1].listeners.change();
  assert.equal(controller.state.selectedCredentialKey, 'second-key');
});

test('Consumer UI preserves selection across discovery refresh and clears vanished keys', async () => {
  const fixture = documentFixture();
  let credentials = [
    { credentialKey: 'keep-key', metadata: { displayName: 'Keep' }, fields: [secretField('apiKey')] },
    { credentialKey: 'remove-key', metadata: { displayName: 'Remove' }, fields: [] }
  ];
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() { return { body: { data: { credentials } } }; } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const initialRadio = fixture.created.filter((element) => element.type === 'radio')[0];
  initialRadio.checked = true;
  initialRadio.listeners.change();
  assert.equal(controller.state.selectedCredentialKey, 'keep-key');
  const initialSecret = fixture.created.filter((element) => element.type === 'checkbox').at(-1);
  initialSecret.checked = true;
  initialSecret.listeners.change();
  assert.deepEqual(controller.state.requestedSecretNames, ['apiKey']);

  await controller.discover({ preventDefault() {} });
  assert.equal(controller.state.selectedCredentialKey, 'keep-key');
  assert.equal(fixture.created.filter((element) => element.type === 'radio').at(-2).checked, true);
  assert.deepEqual(controller.state.requestedSecretNames, []);
  assert.equal(fixture.created.filter((element) => element.type === 'checkbox').at(-1).checked, false);

  credentials = [{ credentialKey: 'new-key', metadata: { displayName: 'New' }, fields: [] }];
  await controller.discover({ preventDefault() {} });
  assert.equal(controller.state.selectedCredentialKey, null);
});

test('Consumer UI renders and tracks only visible public secret fields', async () => {
  const fixture = documentFixture();
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() {
      return discoveryBody([credential('public-key', [
        secretField('apiKey', { label: 'API key', required: true }),
        secretField('hiddenSecret', { visible: false }),
        secretField('refreshToken', { label: 'Refresh token', required: false }),
        secretField('duplicate'),
        secretField('duplicate'),
        { name: 'displayName', secret: false, visible: true },
        { name: 'providerBinding', secret: true, visible: false, credentialMethodKey: 'method' }
      ])]);
    } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();

  assert.equal(fixture.secretSelection.hidden, false);
  const checkboxes = fixture.created.filter((element) => element.type === 'checkbox');
  assert.deepEqual(checkboxes.map((checkbox) => checkbox.value), ['apiKey', 'refreshToken', 'duplicate']);
  assert.deepEqual(controller.state.requestedSecretNames, []);
  assert.match(fixture.secretSelection.textContent, /API key \(required\)/);
  assert.doesNotMatch(fixture.secretSelection.textContent, /hiddenSecret|displayName|credentialMethodKey/);

  checkboxes[0].checked = true;
  checkboxes[0].listeners.change();
  checkboxes[1].checked = true;
  checkboxes[1].listeners.change();
  assert.deepEqual(controller.state.requestedSecretNames, ['apiKey', 'refreshToken']);
  checkboxes[0].checked = false;
  checkboxes[0].listeners.change();
  assert.deepEqual(controller.state.requestedSecretNames, ['refreshToken']);
});

test('Consumer UI shows a neutral empty state when no public secret fields are available', async () => {
  const fixture = documentFixture();
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() {
      return discoveryBody([credential('public-key', [
        { name: 'displayName', secret: false, visible: true },
        { name: 'hiddenSecret', secret: true, visible: false }
      ])]);
    } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();

  assert.match(fixture.secretSelection.textContent, /No resolvable secret fields are available/);
  assert.equal(fixture.created.filter((element) => element.type === 'checkbox').length, 0);
  assert.deepEqual(controller.state.requestedSecretNames, []);
});

test('Consumer UI sends the selected public fields to the existing Resolve endpoint', async () => {
  const fixture = documentFixture();
  const calls = [];
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request(...args) {
      calls.push(args);
      if (calls.length === 1) return discoveryBody([credential('public/key', [secretField('apiKey'), secretField('refreshToken')])]);
      return { body: { data: { credentialKey: 'public/key', providerKey: 'openai', lifecycleState: 'active', secrets: { apiKey: 'resolved-secret', refreshToken: 'resolved-refresh' } } } };
    } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();
  for (const checkbox of fixture.created.filter((element) => element.type === 'checkbox')) {
    checkbox.checked = true;
    checkbox.listeners.change();
  }

  await controller.resolve();

  assert.deepEqual(calls[1], [
    '/api/v1/consumer/credentials/public%2Fkey/resolve',
    'consumer-secret',
    { method: 'POST', body: JSON.stringify({ secretNames: ['apiKey', 'refreshToken'] }) }
  ]);
  assert.equal(controller.state.resolveState, 'success');
  assert.equal(controller.state.resolveRequestInFlight, false);
  assert.deepEqual(controller.state.resolvedCredential, { credentialKey: 'public/key', providerKey: 'openai', lifecycleState: 'active', secrets: { apiKey: 'resolved-secret', refreshToken: 'resolved-refresh' } });
  assert.equal(fixture.resolveResults.hidden, false);
  assert.equal(fixture.resolveResultList.children.length, 2);
  assert.doesNotMatch(fixture.resolveResultList.textContent, /resolved-secret|resolved-refresh/);
  const resultButtons = fixture.resolveResultList.children.map((article) => article.children[2]);
  resultButtons[0].listeners.click();
  assert.match(fixture.resolveResultList.children[0].children[1].textContent, /resolved-secret/);
  assert.doesNotMatch(fixture.resolveResultList.children[1].children[1].textContent, /resolved-refresh/);
  assert.match(fixture.resolveResultList.children[0].children[2].textContent, /Hide/);
  await new Promise((resolve) => setTimeout(resolve, 5100));
  assert.doesNotMatch(fixture.resolveResultList.children[0].children[1].textContent, /resolved-secret/);
  assert.match(fixture.resolveResultList.children[0].children[2].textContent, /Reveal/);
});

for (const [label, body] of [
  ['malformed', { body: { data: { credentialKey: 'public-key' } } }],
  ['empty', { body: {} }],
  ['unexpected fields', { body: { data: { credentialKey: 'public-key', providerKey: 'openai', lifecycleState: 'active', secrets: { apiKey: 'resolved-secret', unexpected: 'must-not-render' } } } }]
]) {
  test(`Consumer UI discards ${label} Resolve responses without rendering partial data`, async () => {
    const fixture = documentFixture();
    const controller = createConsumerController({
      documentRef: fixture.documentRef,
      apiClient: { async request(path) {
        if (path === '/api/v1/consumer/credentials') return discoveryBody([credential('public-key', [secretField('apiKey')])]);
        return body;
      } }
    });
    fixture.input.value = 'consumer-secret';
    await controller.discover({ preventDefault() {} });
    const radio = fixture.created.find((element) => element.type === 'radio');
    radio.checked = true;
    radio.listeners.change();
    const checkbox = fixture.created.find((element) => element.type === 'checkbox');
    checkbox.checked = true;
    checkbox.listeners.change();

    await controller.resolve();
    assert.equal(controller.state.resolveState, 'error');
    assert.equal(controller.state.resolvedCredential, null);
    assert.equal(fixture.resolveResults.hidden, true);
    assert.equal(fixture.resolveResultList.children.length, 0);
    assert.doesNotMatch(fixture.resolveResultList.textContent, /resolved-secret|must-not-render/);
  });
}

test('Consumer UI clears resolved results on lifecycle reset', async () => {
  const fixture = documentFixture();
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request(path) {
      if (path === '/api/v1/consumer/credentials') return discoveryBody([credential('public-key', [secretField('apiKey')])]);
      return { body: { data: { credentialKey: 'public-key', providerKey: 'openai', lifecycleState: 'active', secrets: { apiKey: 'resolved-secret' } } } };
    } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();
  const checkbox = fixture.created.find((element) => element.type === 'checkbox');
  checkbox.checked = true;
  checkbox.listeners.change();
  await controller.resolve();
  assert.equal(fixture.resolveResults.hidden, false);

  controller.reset();
  assert.equal(fixture.resolveResults.hidden, true);
  assert.equal(fixture.resolveResultList.children.length, 0);
  assert.equal(controller.state.resolvedCredential, null);
});

test('Consumer UI shows Resolve loading state and prevents parallel requests', async () => {
  const fixture = documentFixture();
  let finishResolve;
  let resolveCalls = 0;
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { request(...args) {
      if (args[0] === '/api/v1/consumer/credentials') return discoveryBody([credential('public-key', [secretField('apiKey')])]);
      resolveCalls += 1;
      return new Promise((resolve) => { finishResolve = resolve; });
    } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();
  const checkbox = fixture.created.find((element) => element.type === 'checkbox');
  checkbox.checked = true;
  checkbox.listeners.change();

  const first = controller.resolve();
  const second = controller.resolve();
  assert.equal(resolveCalls, 1);
  assert.equal(controller.state.resolveState, 'loading');
  assert.equal(controller.state.resolveRequestInFlight, true);
  assert.equal(fixture.secretSelection.children.at(-1).disabled, true);
  assert.match(fixture.secretSelection.children.at(-1).textContent, /Resolving/);

  finishResolve({ body: { data: { credentialKey: 'public-key', secrets: {} } } });
  await Promise.all([first, second]);
  assert.equal(controller.state.resolveRequestInFlight, false);
  assert.equal(fixture.secretSelection.children.at(-1).disabled, false);
});

for (const [label, error, expected] of [
  ['HTTP validation', { status: 400, code: 'INVALID_SECRET_REQUEST' }, /selected secret fields/],
  ['HTTP authorization', { status: 403, code: 'CONSUMER_ACCESS_DENIED' }, /not authorized/],
  ['network', new TypeError('socket detail'), /Network error/]
]) {
  test(`Consumer UI handles Resolve ${label} without exposing technical details`, async () => {
    const fixture = documentFixture();
    const controller = createConsumerController({
      documentRef: fixture.documentRef,
      apiClient: { async request(path) {
        if (path === '/api/v1/consumer/credentials') return discoveryBody([credential('public-key', [secretField('apiKey')])]);
        throw error;
      } }
    });
    fixture.input.value = 'consumer-secret';
    await controller.discover({ preventDefault() {} });
    const radio = fixture.created.find((element) => element.type === 'radio');
    radio.checked = true;
    radio.listeners.change();
    const checkbox = fixture.created.find((element) => element.type === 'checkbox');
    checkbox.checked = true;
    checkbox.listeners.change();

    await controller.resolve();
    assert.equal(controller.state.resolveState, 'error');
    assert.equal(controller.state.resolveRequestInFlight, false);
    assert.match(fixture.status.textContent, expected);
    assert.doesNotMatch(fixture.status.textContent, /socket detail|CONSUMER_ACCESS_DENIED|INVALID_SECRET_REQUEST/);
  });
}

test('Consumer UI invalidates a stale Resolve result after a lifecycle reset', async () => {
  const fixture = documentFixture();
  let finishResolve;
  let resolveStarted = false;
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { request(path) {
      if (path === '/api/v1/consumer/credentials') return discoveryBody([credential('public-key', [secretField('apiKey')])]);
      resolveStarted = true;
      return new Promise((resolve) => { finishResolve = resolve; });
    } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();
  const checkbox = fixture.created.find((element) => element.type === 'checkbox');
  checkbox.checked = true;
  checkbox.listeners.change();
  const pending = controller.resolve();
  assert.equal(resolveStarted, true);

  controller.reset();
  finishResolve({ body: { data: { credentialKey: 'public-key', secrets: { apiKey: 'must-not-be-stored' } } } });
  await pending;

  assert.equal(controller.state.resolveState, 'initial');
  assert.equal(controller.state.resolvedCredential, null);
  assert.equal(controller.state.resolveRequestInFlight, false);
  assert.doesNotMatch(JSON.stringify(controller.state), /must-not-be-stored/);
});

test('Consumer controller clears resolve state when the token changes', async () => {
  const fixture = documentFixture();
  let credentials = [credential('public-key', [secretField('apiKey')])];
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() { return discoveryBody(credentials); } }
  });

  fixture.input.value = 'first-token';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();
  const checkbox = fixture.created.find((element) => element.type === 'checkbox');
  checkbox.checked = true;
  checkbox.listeners.change();
  controller.state.resolveState = 'success';
  controller.state.resolvedCredential = { credentialKey: 'public-key' };
  controller.state.resolveRequestInFlight = true;

  fixture.input.value = 'second-token';
  await controller.discover({ preventDefault() {} });

  assert.equal(controller.state.resolveState, 'initial');
  assert.equal(controller.state.resolvedCredential, null);
  assert.equal(controller.state.resolveRequestInFlight, false);
  assert.deepEqual(controller.state.requestedSecretNames, []);
});

test('Consumer controller clears resolve state on discovery refresh while retaining selection', async () => {
  const fixture = documentFixture();
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() { return discoveryBody([credential('public-key', [secretField('apiKey')])]); } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();
  const checkbox = fixture.created.find((element) => element.type === 'checkbox');
  checkbox.checked = true;
  checkbox.listeners.change();
  controller.state.resolveState = 'success';
  controller.state.resolvedCredential = { credentialKey: 'public-key' };
  controller.state.resolveRequestInFlight = true;

  await controller.discover({ preventDefault() {} });

  assert.equal(controller.state.selectedCredentialKey, 'public-key');
  assert.equal(controller.state.resolveState, 'initial');
  assert.equal(controller.state.resolvedCredential, null);
  assert.equal(controller.state.resolveRequestInFlight, false);
  assert.deepEqual(controller.state.requestedSecretNames, []);
});

test('Consumer controller clears resolve state when the selected credential changes', async () => {
  const fixture = documentFixture();
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() {
      return discoveryBody([
        credential('first-key', [secretField('firstSecret')]),
        credential('second-key', [secretField('secondSecret')])
      ]);
    } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radios = fixture.created.filter((element) => element.type === 'radio');
  radios[0].checked = true;
  radios[0].listeners.change();
  const firstCheckbox = fixture.created.find((element) => element.type === 'checkbox');
  firstCheckbox.checked = true;
  firstCheckbox.listeners.change();
  controller.state.resolveState = 'success';
  controller.state.resolvedCredential = { credentialKey: 'first-key' };
  controller.state.resolveRequestInFlight = true;

  radios[1].checked = true;
  radios[1].listeners.change();

  assert.equal(controller.state.selectedCredentialKey, 'second-key');
  assert.equal(controller.state.resolveState, 'initial');
  assert.equal(controller.state.resolvedCredential, null);
  assert.equal(controller.state.resolveRequestInFlight, false);
  assert.deepEqual(controller.state.requestedSecretNames, []);
});

test('Consumer controller clears resolve state when the selected credential disappears', async () => {
  const fixture = documentFixture();
  let credentials = [credential('public-key', [secretField('apiKey')])];
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() { return discoveryBody(credentials); } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();
  const checkbox = fixture.created.find((element) => element.type === 'checkbox');
  checkbox.checked = true;
  checkbox.listeners.change();
  controller.state.resolveState = 'success';
  controller.state.resolvedCredential = { credentialKey: 'public-key' };
  controller.state.resolveRequestInFlight = true;

  credentials = [credential('other-key', [secretField('otherSecret')])];
  await controller.discover({ preventDefault() {} });

  assert.equal(controller.state.selectedCredentialKey, null);
  assert.equal(controller.state.resolveState, 'initial');
  assert.equal(controller.state.resolvedCredential, null);
  assert.equal(controller.state.resolveRequestInFlight, false);
  assert.deepEqual(controller.state.requestedSecretNames, []);
});

test('Consumer UI reset clears selection and discovered credentials without persistence or resolve', async () => {
  const fixture = documentFixture();
  const controller = createConsumerController({
    documentRef: fixture.documentRef,
    apiClient: { async request() { return { body: { data: { credentials: [{ credentialKey: 'public-key', metadata: {}, fields: [secretField('apiKey')] }] } } }; } }
  });

  fixture.input.value = 'consumer-secret';
  await controller.discover({ preventDefault() {} });
  const radio = fixture.created.find((element) => element.type === 'radio');
  radio.checked = true;
  radio.listeners.change();
  const checkbox = fixture.created.find((element) => element.type === 'checkbox');
  checkbox.checked = true;
  checkbox.listeners.change();
  controller.reset();
  assert.equal(controller.state.selectedCredentialKey, null);
  assert.deepEqual(controller.state.discoveredCredentials, []);
  assert.equal(fixture.results.children.length, 0);
  assert.equal(fixture.secretSelection.hidden, true);
  assert.deepEqual(controller.state.requestedSecretNames, []);

  const source = fs.readFileSync(path.resolve('public/consumer/consumer.js'), 'utf8');
  assert.doesNotMatch(source, /localStorage|sessionStorage|document\.cookie|location\.(search|hash)/);
  assert.doesNotMatch(source, /credentialId|credentialMethodKey|providerMethodBinding/);
});

for (const [label, error, expected] of [
  ['401', { status: 401, code: 'API_TOKEN_AUTH_FAILED' }, /Check the Consumer API token/],
  ['403', { status: 403, code: 'CONSUMER_SCOPE_MISSING' }, /not authorized/],
  ['network', new TypeError('socket detail'), /Network error/],
  ['public API', { status: 500, code: 'INTERNAL_ERROR', message: 'internal secret detail' }, /temporarily unavailable/]
]) {
  test(`Consumer UI handles ${label} without exposing technical details`, async () => {
    const fixture = documentFixture();
    const controller = createConsumerController({ documentRef: fixture.documentRef, apiClient: { async request() { throw error; } } });
    fixture.input.value = 'consumer-secret';
    await controller.discover({ preventDefault() {} });
    assert.match(fixture.status.textContent, expected);
    assert.doesNotMatch(fixture.status.textContent, /internal secret detail|socket detail/);
    assert.equal(controller.state.discoveryState, 'error');
  });
}

test('Consumer UI uses only the existing public Resolve boundary without rendering secrets or persisting state', () => {
  const source = fs.readFileSync(path.resolve('public/consumer/consumer.js'), 'utf8');
  assert.match(source, /\/api\/v1\/consumer\/credentials/);
  assert.match(source, /\/api\/v1\/consumer\/credentials\/\$\{encodeURIComponent\(credentialKey\)\}\/resolve/);
  assert.match(source, /JSON\.stringify\(\{ secretNames \}\)/);
  assert.doesNotMatch(source, /management|dynamic|credentialId|credentialMethodKey|providerMethodBinding|localStorage|sessionStorage|document\.cookie|innerHTML/);
});
