import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { evidenceRecord } from './ui-evidence-tools.mjs';

const root = process.cwd();
const directory = path.join(root, 'test-results', 'ui-fixtures');
const statePath = path.join(directory, 'state.json');
export const FIXTURE_NAMESPACE = 'credential-hub-ui-test';

export function createFixtureState({ includeCredential = true, includeApiToken = false, includeGrant = true } = {}) {
  const state = {
    fixture_namespace: FIXTURE_NAMESPACE,
    admin: { id: 'ui-test-admin', token: 'fixture-admin-token' },
    consumer: {
      id: 'ui-test-consumer',
      token: '[REDACTED]',
      invalidToken: '[INVALID]',
      noGrantToken: '[NO_GRANT]',
      emptyToken: '[EMPTY]',
      discoveryErrorToken: '[DISCOVERY_ERROR]',
      resolveInvalidToken: '[RESOLVE_INVALID]',
      missingCredentialToken: '[MISSING_CREDENTIAL]',
      deniedSecretToken: '[DENIED_SECRET]'
    },
    provider: {
      key: 'fixture-provider',
      displayName: 'Fixture API Provider',
      description: 'Deterministic provider used only by the local UI fixture.',
      authType: 'api-key',
      capabilities: ['validation'],
      credentialFields: [
        { key: 'displayName', label: 'Display name', type: 'text', required: true, secret: false, section: 'accountCredentials' },
        { key: 'apiKey', label: 'API key', type: 'api-key', required: true, secret: true, section: 'accountCredentials' },
        { key: 'apiSecret', label: 'API secret', type: 'text', required: false, secret: true, section: 'accountCredentials' }
      ],
      credentialMethods: []
    },
    credential: {
      id: 'ui-test-credential',
      credentialId: 'ui-test-credential',
      credentialKey: 'ui-test-credential-key',
      providerKey: 'fixture-provider',
      providerName: 'Fixture API Provider',
      displayName: 'UI test credential',
      status: 'registered',
      lifecycleState: 'registered',
      metadata: { displayName: 'UI test credential', description: 'Deterministic fixture credential.', custom: {} },
      createdAt: '2026-08-02T00:00:00.000Z',
      updatedAt: '2026-08-02T00:00:00.000Z',
      secretNames: ['apiKey', 'apiSecret']
    },
    token: { id: 'ui-test-consumer-token', name: 'UI test consumer', userId: 'admin', scopes: ['credentials:consume'], plaintext: '[REDACTED]' },
    apiTokens: [],
    grant: includeGrant ? {
      id: 'ui-test-grant', grantId: 'ui-test-grant', consumerId: 'ui-test-consumer', consumerName: 'UI test consumer',
      credentialId: 'ui-test-credential', providerKey: 'fixture-provider', secretNames: ['apiKey'], status: 'active',
      createdAt: '2026-08-02T00:00:00.000Z', updatedAt: '2026-08-02T00:00:00.000Z'
    } : null,
    recovery: { invalidConsumerToken: '[INVALID]', recoverable: true },
    wizard: { createdCredentialIds: [], lastValidation: null },
    wizardInputs: { displayName: 'Wizard fixture credential', validApiKey: '[REDACTED]', invalidApiKey: '[INVALID]', grantEditedSecretNames: 'apiSecret' }
  };
  if (!includeCredential) {
    state.credential = null;
    state.grant = null;
  }
  if (includeApiToken) state.apiTokens.push({ id: 'ui-test-api-token', name: 'Seeded UI test token', type: 'api', createdAt: '2026-08-02T00:00:02.000Z', expiresAt: null, status: 'active', userId: 'admin', tokenPrefix: 'ch-ui-seeded', scopes: ['credentials:read'], credentialId: state.credential?.credentialId ?? null, token: '[REDACTED]' });
  return state;
}

export async function seedFixtures({ includeCredential = true, includeApiToken = false, includeGrant = false } = {}) { await mkdir(directory, { recursive: true }); const state = createFixtureState({ includeCredential, includeApiToken, includeGrant }); await writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`); return state; }
export async function resetFixtures() { const state = JSON.parse(await readFile(statePath, 'utf8')); if (state.fixture_namespace !== FIXTURE_NAMESPACE) throw new Error('Refusing reset: fixture namespace mismatch'); await writeFile(statePath, `${JSON.stringify(createFixtureState({ includeGrant: false }), null, 2)}\n`); }
export async function cleanupFixtures() { await rm(directory, { recursive: true, force: true }); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2] ?? 'seed';
  if (command === 'seed' || command === 'seed-single') console.log(JSON.stringify(evidenceRecord({ test_id: 'UI-FIXTURE-SEED', result: 'PASSED', details: await seedFixtures() }), null, 2));
  else if (command === 'seed-empty') console.log(JSON.stringify(evidenceRecord({ test_id: 'UI-FIXTURE-SEED-EMPTY', result: 'PASSED', details: await seedFixtures({ includeCredential: false }) }), null, 2));
  else if (command === 'seed-grant') console.log(JSON.stringify(evidenceRecord({ test_id: 'UI-FIXTURE-SEED-GRANT', result: 'PASSED', details: await seedFixtures({ includeGrant: true }) }), null, 2));
  else if (command === 'seed-token') console.log(JSON.stringify(evidenceRecord({ test_id: 'UI-FIXTURE-SEED-TOKEN', result: 'PASSED', details: await seedFixtures({ includeApiToken: true }) }), null, 2));
  else if (command === 'reset') { await resetFixtures(); console.log(JSON.stringify(evidenceRecord({ test_id: 'UI-FIXTURE-RESET', result: 'PASSED' }), null, 2)); }
  else if (command === 'cleanup') { await cleanupFixtures(); console.log(JSON.stringify(evidenceRecord({ test_id: 'UI-FIXTURE-CLEANUP', result: 'PASSED' }), null, 2)); }
  else throw new Error(`Unknown fixture command: ${command}`);
}
