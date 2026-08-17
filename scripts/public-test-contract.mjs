import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { access, readdir } from 'node:fs/promises';
import path from 'node:path';

export const TEST_PUBLICATION_POLICY_VERSION = '1.0.0';

export const TEST_CLASSIFICATION = Object.freeze({
  PUBLIC: 'PUBLIC',
  PRIVATE: 'PRIVATE',
  OWNER_REVIEW_REQUIRED: 'OWNER REVIEW REQUIRED'
});

export const TEST_CLASSIFICATION_SUITES = Object.freeze([
  {
    id: 'PUBLIC-ARCHITECTURE-CONTRACTS',
    purpose: 'Public licensing, provider metadata and provider capability contracts.',
    classification: TEST_CLASSIFICATION.PUBLIC,
    reason: 'These tests describe externally relevant distribution and provider contracts.',
    files: [
      'tests/architecture/oauth-provider-metadata.test.js',
      'tests/architecture/open-source-governance.test.js',
      'tests/architecture/threads-provider-capabilities.test.js'
    ]
  },
  {
    id: 'PUBLIC-COMPONENT-CONTRACTS',
    purpose: 'Credential, provider, token, persistence and public security component behavior.',
    classification: TEST_CLASSIFICATION.PUBLIC,
    reason: 'These component suites protect public product behavior and public security guarantees.',
    files: [
      'tests/component/api-token-model.test.js',
      'tests/component/api-token-service.test.js',
      'tests/component/api-token-store.test.js',
      'tests/component/commands-provider-manager.test.js',
      'tests/component/credential-connection-test.test.js',
      'tests/component/credential-manager.test.js',
      'tests/component/credential-store.test.js',
      'tests/component/custom-provider-service-provider.test.js',
      'tests/component/custom-provider-service.test.js',
      'tests/component/discord-service-provider.test.js',
      'tests/component/facebook-service-provider.test.js',
      'tests/component/ftp-service-provider.test.js',
      'tests/component/google-service-provider.test.js',
      'tests/component/instagram-service-provider.test.js',
      'tests/component/kick-service-provider.test.js',
      'tests/component/openai-service-provider.test.js',
      'tests/component/provider-configuration-store.test.js',
      'tests/component/provider-manager.test.js',
      'tests/component/provider-registry.test.js',
      'tests/component/secure-credential-persistence.test.js',
      'tests/component/sftp-service-provider.test.js',
      'tests/component/twitch-service-provider.test.js',
      'tests/component/x-service-provider.test.js'
    ]
  },
  {
    id: 'PUBLIC-INTEGRATION-CONTRACTS',
    purpose: 'Public REST, Consumer, authentication, CLI, UI, configuration and build behavior.',
    classification: TEST_CLASSIFICATION.PUBLIC,
    reason: 'These integration suites exercise observable public product contracts.',
    files: [
      'tests/integration/access-management-api.test.js',
      'tests/integration/admin-auth.test.js',
      'tests/integration/admin-ui.test.js',
      'tests/integration/api-token-bearer-auth.test.js',
      'tests/integration/base-path.test.js',
      'tests/integration/consumer-credential-api.test.js',
      'tests/integration/consumer-ui.test.js',
      'tests/integration/credential-creation-flow.test.js',
      'tests/integration/credential-transfer-api.test.js',
      'tests/integration/credentials-cli.test.js',
      'tests/integration/credentials-list-api.test.js',
      'tests/integration/dashboard-api.test.js',
      'tests/integration/docker-image-version.test.js',
      'tests/integration/health-api.test.js',
      'tests/integration/management-api.test.js',
      'tests/integration/oauth-callback-public-language.test.js',
      'tests/integration/oauth-cli.test.js',
      'tests/integration/oauth-http-login.test.js',
      'tests/integration/oauth-provider-configuration.test.js',
      'tests/integration/providers-api.test.js',
      'tests/integration/providers-cli.test.js',
      'tests/integration/refresh-cli.test.js'
    ]
  },
  {
    id: 'PUBLIC-UNIT-CONTRACTS',
    purpose: 'Public domain, lifecycle, security, provider, UI and operations behavior.',
    classification: TEST_CLASSIFICATION.PUBLIC,
    reason: 'These focused suites protect stable public behavior and failure semantics.',
    files: [
      'tests/unit/access-management-service.test.js',
      'tests/unit/api-token-model.test.js',
      'tests/unit/audit-log-service.test.js',
      'tests/unit/audit-log-target-id-filter.test.js',
      'tests/unit/backup-restore-service.test.js',
      'tests/unit/base-path.test.js',
      'tests/unit/connection-target-policy.test.js',
      'tests/unit/consumer-credential-service.test.js',
      'tests/unit/consumer-grant-service.test.js',
      'tests/unit/credential-collection-store-adapter.test.js',
      'tests/unit/credential-controller-connection-test.test.js',
      'tests/unit/credential-controller-creation.test.js',
      'tests/unit/credential-field-definition.test.js',
      'tests/unit/credential-field-sets.test.js',
      'tests/unit/credential-history-service.test.js',
      'tests/unit/credential-method.test.js',
      'tests/unit/credential-model.test.js',
      'tests/unit/credential-policy-service.test.js',
      'tests/unit/credential-rotation-service.test.js',
      'tests/unit/credential-secret-version-service.test.js',
      'tests/unit/credential-transfer-service.test.js',
      'tests/unit/dashboard-service.test.js',
      'tests/unit/discord-oauth-service.test.js',
      'tests/unit/discord-provider-public-errors.test.js',
      'tests/unit/export-service.test.js',
      'tests/unit/facebook-oauth-service.test.js',
      'tests/unit/facebook-provider-public-errors.test.js',
      'tests/unit/ftp-client.test.js',
      'tests/unit/ftp-connection-service.test.js',
      'tests/unit/ftp-provider.test.js',
      'tests/unit/google-oauth-service.test.js',
      'tests/unit/google-provider-public-errors.test.js',
      'tests/unit/grant-attempt.test.js',
      'tests/unit/grant-synchronization.test.js',
      'tests/unit/http-error.test.js',
      'tests/unit/i18n.test.js',
      'tests/unit/instagram-oauth-service.test.js',
      'tests/unit/instagram-provider-public-errors.test.js',
      'tests/unit/kick-oauth-service.test.js',
      'tests/unit/kick-provider-public-errors.test.js',
      'tests/unit/lifecycle-notification-service.test.js',
      'tests/unit/management-service.test.js',
      'tests/unit/metrics-service.test.js',
      'tests/unit/oauth-provider-configuration.test.js',
      'tests/unit/oauth-security-requirements.test.js',
      'tests/unit/oauth-security-service.test.js',
      'tests/unit/openai-client.test.js',
      'tests/unit/openai-connection-service.test.js',
      'tests/unit/openai-provider.test.js',
      'tests/unit/provider-capabilities.test.js',
      'tests/unit/provider-configuration-service.test.js',
      'tests/unit/provider-result.test.js',
      'tests/unit/provider-rotation-framework.test.js',
      'tests/unit/runtime-public-projection-service.test.js',
      'tests/unit/sftp-client.test.js',
      'tests/unit/sftp-connection-service.test.js',
      'tests/unit/sftp-provider.test.js',
      'tests/unit/threads-provider-public-errors.test.js',
      'tests/unit/token-lifecycle-service.test.js',
      'tests/unit/twitch-oauth-service.test.js',
      'tests/unit/twitch-provider-public-errors.test.js',
      'tests/unit/x-oauth-service.test.js',
      'tests/unit/x-provider-public-errors.test.js'
    ]
  },
  {
    id: 'PRIVATE-INTERNAL-ARCHITECTURE',
    purpose: 'Internal source dependency and implementation-boundary enforcement.',
    classification: TEST_CLASSIFICATION.PRIVATE,
    reason: 'These tests protect private implementation structure rather than a public product contract.',
    files: [
      'tests/architecture/no-direct-http-in-provider.test.js',
      'tests/architecture/no-legacy-provider-manager-import.test.js',
      'tests/architecture/no-provider-logging.test.js',
      'tests/architecture/storage-abstraction.test.js'
    ]
  },
  {
    id: 'PRIVATE-PUBLICATION-AND-DOCUMENTATION-TOOLING',
    purpose: 'Private publication security, documentation audit and generated-evidence tooling.',
    classification: TEST_CLASSIFICATION.PRIVATE,
    reason: 'Publication-boundary internals and maintainer evidence tooling are private.',
    files: [
      'tests/unit/documentation-quality-audit.test.js',
      'tests/unit/publication-security.test.js',
      'tests/unit/ui-executable-report.test.js',
      'tests/unit/ui-model-tooling.test.js'
    ]
  },
  {
    id: 'PRIVATE-VALIDATION-FIXTURES',
    purpose: 'Non-production fixture registration, fixture state and private browser evidence.',
    classification: TEST_CLASSIFICATION.PRIVATE,
    reason: 'Internal validation fixtures and evidence mechanics are outside the public product contract.',
    files: [
      'tests/component/validation-fixture-service-provider.test.js',
      'tests/ui/canonical-ui.smoke.spec.mjs',
      'tests/unit/ui-test-infrastructure.test.js'
    ]
  },
  {
    id: 'PRIVATE-LEGACY-NONCANONICAL-TEST',
    purpose: 'Legacy test outside the canonical repository test directories.',
    classification: TEST_CLASSIFICATION.PRIVATE,
    reason: 'The superseded root integration test is not part of the active public test contract.',
    files: [
      'integration/admin-ui.test.js'
    ]
  }
]);

function normalizedTestPath(relativePath) {
  return relativePath.replaceAll('\\', '/').replace(/^\.\//, '');
}

export function isTestArtifactPath(relativePath) {
  const normalized = normalizedTestPath(relativePath);
  return /(?:^|\/)[^/]+\.(?:test\.js|spec\.mjs)$/.test(normalized);
}

export function validateTestClassificationModel(suites = TEST_CLASSIFICATION_SUITES) {
  const validClassifications = new Set(Object.values(TEST_CLASSIFICATION));
  const entries = [];
  const paths = new Set();

  for (const suite of suites) {
    if (!suite.id || !suite.purpose || !suite.reason || !Array.isArray(suite.files) || suite.files.length === 0) {
      throw new Error('Every test classification suite requires id, purpose, reason and files.');
    }
    if (!validClassifications.has(suite.classification)) {
      throw new Error(`Unknown test publication classification in ${suite.id}: ${suite.classification}`);
    }
    for (const file of suite.files) {
      const normalized = normalizedTestPath(file);
      if (!isTestArtifactPath(normalized) || path.isAbsolute(normalized) || normalized.startsWith('../')) {
        throw new Error(`Invalid test classification path in ${suite.id}: ${file}`);
      }
      if (paths.has(normalized)) throw new Error(`Duplicate test classification: ${normalized}`);
      paths.add(normalized);
      entries.push(Object.freeze({
        path: normalized,
        suite: suite.id,
        purpose: suite.purpose,
        classification: suite.classification,
        reason: suite.reason
      }));
    }
  }

  return entries;
}

const CLASSIFICATION_ENTRIES = Object.freeze(validateTestClassificationModel());
const CLASSIFICATION_BY_PATH = new Map(CLASSIFICATION_ENTRIES.map((entry) => [entry.path, entry]));

export const PUBLIC_TEST_FILES = Object.freeze(CLASSIFICATION_ENTRIES
  .filter((entry) => entry.classification === TEST_CLASSIFICATION.PUBLIC)
  .map((entry) => entry.path)
  .sort());

export const EXPLICIT_PRIVATE_TEST_FILES = Object.freeze(CLASSIFICATION_ENTRIES
  .filter((entry) => entry.classification === TEST_CLASSIFICATION.PRIVATE)
  .map((entry) => entry.path)
  .sort());

export const OWNER_REVIEW_TEST_FILES = Object.freeze(CLASSIFICATION_ENTRIES
  .filter((entry) => entry.classification === TEST_CLASSIFICATION.OWNER_REVIEW_REQUIRED)
  .map((entry) => entry.path)
  .sort());

export function classifyTestPath(relativePath) {
  const normalized = normalizedTestPath(relativePath);
  return CLASSIFICATION_BY_PATH.get(normalized) ?? Object.freeze({
    path: normalized,
    suite: 'DEFAULT-PRIVATE',
    purpose: 'Unclassified test artifact.',
    classification: TEST_CLASSIFICATION.PRIVATE,
    reason: 'Tests are private by default; public distribution requires explicit opt-in.'
  });
}

export function isPublicTestPath(relativePath) {
  return classifyTestPath(relativePath).classification === TEST_CLASSIFICATION.PUBLIC;
}

const TEST_DISCOVERY_EXCLUDED_DIRECTORIES = new Set([
  '.git',
  '.nyc_output',
  'coverage',
  'node_modules',
  'playwright-report',
  'test-results'
]);

async function collectFrom(directory, root) {
  const files = [];
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return files;
    throw error;
  }
  for (const entry of entries) {
    if (entry.isDirectory() && TEST_DISCOVERY_EXCLUDED_DIRECTORIES.has(entry.name)) continue;
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await collectFrom(fullPath, root));
    else if (entry.isFile()) {
      const relativePath = normalizedTestPath(path.relative(root, fullPath));
      if (isTestArtifactPath(relativePath)) files.push(relativePath);
    }
  }
  return files;
}

export async function collectTestArtifacts(root) {
  if (existsSync(path.join(root, '.git'))) {
    return execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' })
      .split('\0')
      .filter(isTestArtifactPath)
      .map(normalizedTestPath)
      .sort();
  }
  return (await collectFrom(root, root)).sort();
}

async function pathExists(root, relativePath) {
  try {
    await access(path.join(root, relativePath));
    return true;
  } catch {
    return false;
  }
}

export async function testClassificationSummary(root) {
  const files = await collectTestArtifacts(root);
  const classified = files.map((file) => classifyTestPath(file));
  const missingClassifiedFiles = [];
  for (const entry of CLASSIFICATION_ENTRIES) {
    if (!await pathExists(root, entry.path)) missingClassifiedFiles.push(entry.path);
  }
  return {
    files,
    total: files.length,
    public: classified.filter((entry) => entry.classification === TEST_CLASSIFICATION.PUBLIC).length,
    explicitPrivate: classified.filter((entry) => entry.classification === TEST_CLASSIFICATION.PRIVATE && entry.suite !== 'DEFAULT-PRIVATE').length,
    defaultPrivate: classified.filter((entry) => entry.suite === 'DEFAULT-PRIVATE').length,
    ownerReviewRequired: classified.filter((entry) => entry.classification === TEST_CLASSIFICATION.OWNER_REVIEW_REQUIRED).length,
    missingClassifiedFiles
  };
}

export async function assertSourceTestClassificationIntegrity(root) {
  const summary = await testClassificationSummary(root);
  if (summary.missingClassifiedFiles.length > 0) {
    throw new Error(`Test classification references missing files: ${summary.missingClassifiedFiles.join(', ')}`);
  }
  if (summary.ownerReviewRequired > 0 || OWNER_REVIEW_TEST_FILES.length > 0) {
    throw new Error('OWNER REVIEW REQUIRED test classifications block public publication.');
  }
  return summary;
}

export async function publicTestContractFindings(root) {
  const publishedTests = await collectTestArtifacts(root);
  const publishedSet = new Set(publishedTests);
  const findings = [];
  for (const file of publishedTests) {
    if (!isPublicTestPath(file)) findings.push({ file, type: 'published test lacks explicit PUBLIC classification' });
  }
  for (const file of PUBLIC_TEST_FILES) {
    if (!publishedSet.has(file)) findings.push({ file, type: 'explicit PUBLIC test missing from publication tree' });
  }
  for (const file of OWNER_REVIEW_TEST_FILES) {
    findings.push({ file, type: 'OWNER REVIEW REQUIRED classification blocks publication' });
  }
  return findings;
}
