import { spawn } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const registryPath = path.join(root, 'scripts/security/attack-registry.json');

export const ATTACK_REGISTRY_SCHEMA = 'SEKALUM-ADVERSARIAL-HACKER-TEST-REGISTRY-V2';
export const ATTACK_FAMILIES = Object.freeze([
  'CONSUMER_GRANT_ESCAPE',
  'BINDING_TIME_AUTHORIZATION_BYPASS',
  'LIFECYCLE_RACE',
  'CANONICALIZATION',
  'OAUTH_CONTEXT_CONFUSION',
  'SSRF_EGRESS',
  'SECRET_EXFILTRATION',
  'ABUSE_HARVESTING',
  'PLANE_PIVOT'
]);
export const ATTACK_STATUS = Object.freeze({
  IMPLEMENTED: 'IMPLEMENTED',
  NOT_IMPLEMENTED: 'NOT_IMPLEMENTED',
  NOT_APPLICABLE: 'NOT_APPLICABLE',
  BLOCKED: 'BLOCKED'
});

const REQUIRED_ENTRY_FIELDS = Object.freeze([
  'id',
  'title',
  'family',
  'threat',
  'attack_chain',
  'security_invariant',
  'security_boundary',
  'expected_result',
  'test_reference',
  'source_reference',
  'severity_or_priority',
  'release_gate',
  'status'
]);
const TEST_REFERENCE = /^(tests\/(?:unit|component|integration)\/[A-Za-z0-9._/-]+\.test\.js)#(.+)$/;
const SAFE_PATH = /^(?:src|tests)\/[A-Za-z0-9._/-]+\.(?:js|mjs)$/;
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function assert(condition, message) {
  if (!condition) throw new Error(`ATTACK_REGISTRY_INVALID: ${message}`);
}

function resolveRepositoryPath(relativePath, field) {
  assert(typeof relativePath === 'string' && SAFE_PATH.test(relativePath), `${field} must be a safe repository source path`);
  const resolved = path.resolve(root, relativePath);
  assert(resolved.startsWith(`${root}${path.sep}`), `${field} escapes repository root`);
  assert(existsSync(resolved), `${field} does not exist: ${relativePath}`);
  return resolved;
}

function validateTestReference(entry) {
  if (entry.status !== ATTACK_STATUS.IMPLEMENTED) {
    assert(entry.test_reference === null, `${entry.id} must use null test_reference until it is implemented`);
    return;
  }

  assert(typeof entry.test_reference === 'string', `${entry.id} must provide a test_reference`);
  const match = entry.test_reference.match(TEST_REFERENCE);
  assert(match, `${entry.id} has an invalid test_reference`);
  const [, testPath, testName] = match;
  const source = readFileSync(resolveRepositoryPath(testPath, `${entry.id}.test_reference`), 'utf8');
  const declaration = new RegExp(`(?:test|it)\\(\\s*['\"]${escapeRegex(testName)}['\"]`);
  assert(declaration.test(source), `${entry.id} test_reference does not name a test in ${testPath}`);
}

export function readAttackRegistry(file = registryPath) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

export function validateAttackRegistry(registry = readAttackRegistry()) {
  assert(registry?.schema === ATTACK_REGISTRY_SCHEMA, 'schema must match the v2 registry schema');
  assert(typeof registry.version === 'string' && registry.version.length > 0, 'version is required');
  assert(Array.isArray(registry.attacks) && registry.attacks.length > 0, 'attacks must be a non-empty array');

  const ids = new Set();
  for (const entry of registry.attacks) {
    assert(entry && typeof entry === 'object' && !Array.isArray(entry), 'each attack entry must be an object');
    for (const field of REQUIRED_ENTRY_FIELDS) assert(Object.hasOwn(entry, field), `${entry.id ?? '<unknown>'} is missing ${field}`);
    assert(typeof entry.id === 'string' && /^[A-Z]+(?:-[A-Z]+)*-ATTACK-\d{3}$/.test(entry.id), 'id must be a stable ATTACK id');
    assert(!ids.has(entry.id), `duplicate id ${entry.id}`);
    ids.add(entry.id);
    for (const field of ['title', 'threat', 'attack_chain', 'security_invariant', 'security_boundary', 'expected_result', 'severity_or_priority']) {
      assert(typeof entry[field] === 'string' && entry[field].trim().length > 0, `${entry.id}.${field} is required`);
    }
    assert(ATTACK_FAMILIES.includes(entry.family), `${entry.id} has unknown family ${entry.family}`);
    assert(Object.values(ATTACK_STATUS).includes(entry.status), `${entry.id} has unknown status ${entry.status}`);
    assert(typeof entry.release_gate === 'boolean', `${entry.id}.release_gate must be boolean`);
    assert(Array.isArray(entry.source_reference) && entry.source_reference.length > 0, `${entry.id}.source_reference must be a non-empty array`);
    for (const reference of entry.source_reference) resolveRepositoryPath(reference, `${entry.id}.source_reference`);
    if (entry.release_gate) assert(entry.status === ATTACK_STATUS.IMPLEMENTED, `${entry.id} release gate must be implemented`);
    validateTestReference(entry);
  }
  return Object.freeze({ attacks: registry.attacks.length, families: new Set(registry.attacks.map((entry) => entry.family)).size });
}

function parseArguments(args) {
  if (args.length === 0 || args.includes('--help')) return { command: 'help' };
  if (args.length === 1 && args[0] === '--validate') return { command: 'validate' };
  if (args.length === 1 && args[0] === '--list') return { command: 'list' };
  if (args.length === 1 && args[0] === '--all') return { command: 'run', selector: { type: 'all' } };
  if (args.length === 1 && args[0] === '--release-gate') return { command: 'run', selector: { type: 'release-gate' } };
  if (args.length === 2 && args[0] === '--family') return { command: 'run', selector: { type: 'family', value: args[1] } };
  if (args.length === 2 && args[0] === '--id') return { command: 'run', selector: { type: 'id', value: args[1] } };
  throw new Error('Usage: --validate | --list | --all | --release-gate | --family <family> | --id <attack-id>');
}

export function selectAttacks(attacks, selector) {
  const selected = selector.type === 'all'
    ? attacks
    : selector.type === 'release-gate'
      ? attacks.filter((entry) => entry.release_gate)
      : selector.type === 'family'
        ? attacks.filter((entry) => entry.family === selector.value)
        : attacks.filter((entry) => entry.id === selector.value);
  if (selected.length === 0) throw new Error(`No attacks selected for ${selector.type}${selector.value ? `=${selector.value}` : ''}`);
  return selected;
}

export function candidateIdentity(cwd = root) {
  const dirty = execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd, encoding: 'utf8' }).trim();
  assert(!dirty, 'candidate working tree must be clean before Hacker Test execution');
  return execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim();
}

function runNodeTest(testReference) {
  const [, testPath, testName] = testReference.match(TEST_REFERENCE);
  const pattern = `^${escapeRegex(testName)}$`;
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-name-pattern', pattern, testPath], {
      cwd: root,
      env: { ...process.env, NODE_ENV: 'test' },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    child.stdout.resume();
    child.stderr.resume();
    child.on('error', (error) => resolve({ code: 1, failure: `Unable to start test process: ${error.code ?? error.message}` }));
    child.on('close', (code, signal) => resolve({
      code: code ?? 1,
      failure: code === 0 ? null : `Test process failed${signal ? ` with signal ${signal}` : ` with exit code ${code ?? 1}`}`
    }));
  });
}

async function executeAttack(entry, candidate) {
  const started = Date.now();
  const timestamp = new Date().toISOString();
  if (entry.status !== ATTACK_STATUS.IMPLEMENTED) {
    return {
      id: entry.id,
      family: entry.family,
      status: entry.status,
      candidate_sha: candidate,
      timestamp,
      duration_ms: 0,
      test_reference: entry.test_reference,
      failure: { code: `ATTACK_${entry.status}`, message: 'Attack is registered but not executable in the current RC3 baseline.' }
    };
  }
  const test = await runNodeTest(entry.test_reference);
  return {
    id: entry.id,
    family: entry.family,
    status: test.code === 0 ? 'PASS' : 'FAIL',
    candidate_sha: candidate,
    timestamp,
    duration_ms: Date.now() - started,
    test_reference: entry.test_reference,
    failure: test.failure ? { code: 'HACKER_TEST_FAILED', message: test.failure } : null
  };
}

function overallStatus(results) {
  if (results.every((result) => result.status === 'PASS')) return 'PASS';
  if (results.some((result) => result.status === 'FAIL')) return 'FAIL';
  if (results.some((result) => result.status === ATTACK_STATUS.BLOCKED)) return ATTACK_STATUS.BLOCKED;
  if (results.some((result) => result.status === ATTACK_STATUS.NOT_IMPLEMENTED)) return ATTACK_STATUS.NOT_IMPLEMENTED;
  return ATTACK_STATUS.NOT_APPLICABLE;
}

async function main() {
  const parsed = parseArguments(process.argv.slice(2));
  if (parsed.command === 'help') {
    console.log('Usage: npm run test:hacker -- --validate|--list|--all|--release-gate|--family <family>|--id <attack-id>');
    return;
  }
  const registry = readAttackRegistry();
  const validation = validateAttackRegistry(registry);
  if (parsed.command === 'validate') {
    console.log(JSON.stringify({ schema: ATTACK_REGISTRY_SCHEMA, status: 'PASS', ...validation }, null, 2));
    return;
  }
  if (parsed.command === 'list') {
    console.log(JSON.stringify({ schema: ATTACK_REGISTRY_SCHEMA, status: 'PASS', attacks: registry.attacks }, null, 2));
    return;
  }
  const selected = selectAttacks(registry.attacks, parsed.selector);
  const started = Date.now();
  const candidate = candidateIdentity();
  const results = [];
  for (const entry of selected) results.push(await executeAttack(entry, candidate));
  const status = overallStatus(results);
  console.log(JSON.stringify({
    schema: 'SEKALUM-ADVERSARIAL-HACKER-TEST-RUN-V2',
    status,
    candidate_sha: candidate,
    timestamp: new Date().toISOString(),
    duration_ms: Date.now() - started,
    coverage: {
      selected: results.length,
      passed: results.filter((result) => result.status === 'PASS').length,
      failed: results.filter((result) => result.status === 'FAIL').length,
      not_implemented: results.filter((result) => result.status === ATTACK_STATUS.NOT_IMPLEMENTED).length,
      families: [...new Set(results.map((result) => result.family))].sort()
    },
    results
  }, null, 2));
  if (status !== 'PASS') process.exitCode = 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(JSON.stringify({ schema: 'SEKALUM-ADVERSARIAL-HACKER-TEST-RUN-V2', status: 'FAIL', failure: { code: 'HACKER_RUNNER_ERROR', message: error.message } }, null, 2));
    process.exitCode = 1;
  });
}
