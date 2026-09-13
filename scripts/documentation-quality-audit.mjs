import { access, readdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The IEP path is part of the private Sekalum adapter boundary.  Keep the
// public audit self-contained: the adapter module is resolved only when the
// private profile actually needs canonical-state validation.
const IEP_RC3_PATH = 'docs/project/issue-execution/IEP-rc3.md';
const SEKALUM_IEP_ADAPTER_URL = new URL('../tools/gov3/sekalum-adapter/iep-rc3-state.mjs', import.meta.url);

const CANONICAL_FIELDS = [
  'title',
  'version',
  'status',
  'category',
  'canonical',
  'maintainer',
  'contact',
  'license',
  'target_audience',
  'change_history'
];

const CURRENT_REQUIRED_FIELDS = [
  'title',
  'document_id',
  'classification',
  'language',
  'version',
  'status',
  'category',
  'canonical',
  'maintainer',
  'contact',
  'license',
  'target_audience',
  'change_history'
];

// Explicit, record-specific classification. This is not a general exemption:
// the source bytes and the active-chain source digest are checked below.
const IMMUTABLE_DIGEST_BOUND_GOVERNANCE_RECORDS = new Map([
  ['docs/adr/ADR-025-Custom-Provider-Lifecycle-State.md', Object.freeze({
    classification: 'IMMUTABLE_DIGEST_BOUND_GOVERNANCE_RECORD',
    activeChain: 'GOV3-SLICE-2',
    sourceContentDigest: '20fe16edec4059596fa61dd01736e7d48af4d6f9546bde7bb01a337184779e14'
  })]
]);

const GERMAN_LANGUAGE_MARKERS = /\b(?:der|die|das|und|nicht|für|ist|sind|eine|einer|eines|von|auf|als|auch|wird|werden|durch|bei|zur|zum|über|ohne|kann|muss|soll|Dokumentation|Verzeichnis|Prüfung|Ergebnis|Freigabe|Entscheidung|Anforderung|historisch|öffentlich|privat|Bitte|Ziel|Stand|Änderung|Übergabe|Bereinigung|Wichtig|Beschreibung|Übersicht|Anleitung|Betrieb|Benutzer|Verbindung|Schlüssel|Speicher|Verschlüsselung|Fuehrende|Aktuelle|Eintraege|Zweck|Abgrenzung|erstellt|verifiziert|geprüft|enthalten|erforderlich)\b/iu;
const HISTORICAL_STATUS_MARKERS = /\b(?:historical|archived|superseded|legacy)\b/i;
const execFileAsync = promisify(execFile);

const REQUIRED_PROJECT_DOCUMENTS = [
  'docs/project/DOCUMENTATION_INVENTORY.md',
  'docs/project/DOCUMENTATION_GOVERNANCE.md'
];

const PUBLIC_PROJECT_DOCUMENTS = [
  'docs/project/LEGAL.md',
  'docs/project/PROJECT_IDENTITY.md',
  'docs/project/THIRD_PARTY_SOFTWARE.md'
];

const SENSITIVE_PATTERNS = [
  { name: 'IPv4 address', expression: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { name: 'private hostname', expression: /\b[a-z0-9-]+\.(?:local|lan|internal)\b/gi },
  { name: 'personal path', expression: /\/(?:Users|home)\/[A-Za-z0-9_.-]+/g },
  { name: 'environment assignment', expression: /^[A-Z][A-Z0-9_]*=(?!$|YOUR_|<)[^\s]+/gm }
];

async function exists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function listMarkdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...await listMarkdownFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      files.push(fullPath);
    }
  }

  return files;
}

function frontMatter(content) {
  if (!content.startsWith('---\n')) {
    return null;
  }

  const end = content.indexOf('\n---', 4);
  if (end === -1) {
    return null;
  }

  return content.slice(4, end).split('\n');
}

function frontMatterKeys(lines) {
  return new Set(
    lines
      .map((line) => line.match(/^([a-z_]+):/i)?.[1])
      .filter(Boolean)
  );
}

function frontMatterValue(lines, key) {
  return lines?.find((line) => line.match(new RegExp(`^${key}:\\s*`, 'i')))?.replace(new RegExp(`^${key}:\\s*`, 'i'), '').trim();
}

function duplicateFrontMatterKeys(lines) {
  const counts = new Map();
  for (const line of lines ?? []) {
    const key = line.match(/^([a-z_][a-z0-9_]*):/i)?.[1]?.toLowerCase();
    if (key) counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()].filter(([, count]) => count > 1).map(([key]) => key);
}

function documentControlVersion(content) {
  return content.match(/^\|\s*Version\s*\|\s*`?([^`|\s]+)`?\s*\|/im)?.[1] ?? null;
}

function latestHistoryVersion(lines) {
  return lines?.find((line) => /^\s*-\s+version:\s*/i.test(line))?.replace(/^\s*-\s+version:\s*/i, '').trim() ?? null;
}

function stripFrontMatter(content) {
  if (!content.startsWith('---\n')) {
    return content;
  }

  const end = content.indexOf('\n---', 4);
  return end === -1 ? content : content.slice(end + 4);
}

function isHistoryPath(displayPath) {
  return displayPath === 'docs/history' || displayPath.startsWith('docs/history/');
}

function isGeneratedOrNonDocumentationPath(displayPath) {
  return displayPath.startsWith('docs/ui/generated/')
    || displayPath.startsWith('docs/assets/');
}

function isCurrentGovernedPath(displayPath) {
  return displayPath.startsWith('docs/')
    && !isHistoryPath(displayPath)
    && !isGeneratedOrNonDocumentationPath(displayPath);
}

function immutableGovernanceRecord(displayPath) {
  return IMMUTABLE_DIGEST_BOUND_GOVERNANCE_RECORDS.get(displayPath);
}

function parseVersion(value) {
  return /^\d+\.\d+\.\d+$/.test(value ?? '');
}

function changedBody(content) {
  return stripFrontMatter(content).replace(/```[\s\S]*?```/g, '');
}

function markdownLinks(content) {
  const links = [];
  const expression = /\[[^\]]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)/g;
  let match;

  while ((match = expression.exec(content)) !== null) {
    links.push(match[1].replace(/^<|>$/g, ''));
  }

  return links;
}

function isExternalLink(target) {
  return /^(?:https?:|mailto:|tel:|#)/i.test(target);
}

function relativePath(root, filePath) {
  return path.relative(root, filePath).split(path.sep).join('/');
}

function findSensitiveMatches(content) {
  const matches = [];

  for (const pattern of SENSITIVE_PATTERNS) {
    for (const match of content.matchAll(pattern.expression)) {
      matches.push({ type: pattern.name, value: match[0] });
    }
  }

  return matches;
}

function isConfidentialDocument(metadata) {
  return frontMatterValue(metadata, 'classification')?.toLowerCase() === 'confidential';
}

function isHistoricalAuditEvidence(files) {
  return files.every((file) => isHistoryPath(file));
}

async function changedFilesSince(root, baseRef) {
  if (!baseRef) {
    return [];
  }

  try {
    const { stdout } = await execFileAsync('git', ['diff', '--name-only', `${baseRef}...HEAD`], { cwd: root });
    return stdout.split('\n').map((line) => line.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

async function gitFileAt(root, ref, displayPath) {
  try {
    const { stdout } = await execFileAsync('git', ['show', `${ref}:${displayPath}`], { cwd: root, maxBuffer: 4 * 1024 * 1024 });
    return stdout;
  } catch {
    return null;
  }
}

async function privateIepConsistency(root, injectedCheck) {
  try {
    const adapter = injectedCheck
      ? { checkIepRc3Consistency: injectedCheck, IEP_RC3_PATH }
      : await import(SEKALUM_IEP_ADAPTER_URL.href);
    const consistency = await adapter.checkIepRc3Consistency(root);
    return { path: adapter.IEP_RC3_PATH ?? IEP_RC3_PATH, consistency };
  } catch (error) {
    return {
      path: IEP_RC3_PATH,
      consistency: {
        result: 'BLOCK',
        diagnostics: [{
          code: 'PRIVATE_GOV3_ADAPTER_UNAVAILABLE',
          reason: error instanceof Error ? error.message : String(error)
        }]
      }
    };
  }
}

export async function auditDocumentation(root = process.cwd(), {
  publicProfile = false,
  baseRef = process.env.DOC_AUDIT_BASE,
  privateRoot = process.env.DOC_AUDIT_PRIVATE_ROOT,
  privateIepConsistency: injectedPrivateIepConsistency
} = {}) {
  const docsDirectory = path.join(root, 'docs');
  const markdownFiles = await listMarkdownFiles(docsDirectory);
  const privateCanonicalSource = publicProfile && await exists(path.join(root, '.git'));
  const resolvePublicationPath = privateCanonicalSource
    ? (await import('./public-projection-contract.mjs')).resolvePublicationPath
    : null;
  const allFiles = [...markdownFiles];
  const rootReadme = path.join(root, 'README.md');

  if (await exists(rootReadme)) {
    allFiles.push(rootReadme);
  }

  const result = {
    documentCount: markdownFiles.length,
    frontMatterCount: 0,
    canonicalDocuments: [],
    canonicalMetadataIssues: [],
    linkIssues: [],
    sensitiveMatches: [],
    duplicateNames: [],
    whitespaceIssues: [],
    missingProjectDocuments: [],
    governanceFindings: [],
    roleFindings: [],
    languageFindings: [],
    headerChangeFindings: [],
    projectionFindings: [],
    documentIdDuplicates: [],
    currentDocumentCount: 0,
    historicalDocumentCount: 0,
    nonDocumentationCount: 0,
    publicDocumentCount: 0,
    currentGermanDocumentCount: 0,
    immutableExceptions: []
  };
  const contentGroups = new Map();
  const documentIds = new Map();
  const changedFiles = new Set(await changedFilesSince(root, baseRef));

  for (const filePath of allFiles) {
    const content = await readFile(filePath, 'utf8');
    const displayPath = relativePath(root, filePath);
    const metadata = frontMatter(content);
    const changedGovernedDocument = Boolean(baseRef && changedFiles.has(displayPath));

    if (isHistoryPath(displayPath)) {
      result.historicalDocumentCount += 1;
    } else if (isGeneratedOrNonDocumentationPath(displayPath)) {
      result.nonDocumentationCount += 1;
    } else if (isCurrentGovernedPath(displayPath)) {
      result.currentDocumentCount += 1;
    }

    if (metadata) {
      result.frontMatterCount += 1;
      const keys = frontMatterKeys(metadata);
      const duplicateKeys = duplicateFrontMatterKeys(metadata);
      if (changedGovernedDocument && duplicateKeys.length > 0) {
        result.governanceFindings.push({ code: 'DOC-HDR-003', file: displayPath, duplicateKeys });
      }

      if (keys.has('canonical') && metadata.some((line) => /^canonical:\s*true\s*$/i.test(line))) {
        result.canonicalDocuments.push(displayPath);
        const missing = CANONICAL_FIELDS.filter((field) => !keys.has(field));

        if (missing.length > 0) {
        if (isCurrentGovernedPath(displayPath) && !immutableGovernanceRecord(displayPath)) {
          result.canonicalMetadataIssues.push({ file: displayPath, missing });
        }
        }
      }
    }

    const immutableRecord = immutableGovernanceRecord(displayPath);
    if (immutableRecord) {
      const actualSourceDigest = createHash('sha256').update(content, 'utf8').digest('hex');
      if (actualSourceDigest !== immutableRecord.sourceContentDigest) {
        result.governanceFindings.push({
          code: 'DOC-IMMUTABLE-001',
          file: displayPath,
          expected: immutableRecord.sourceContentDigest,
          actual: actualSourceDigest
        });
      } else {
        result.immutableExceptions.push({ file: displayPath, ...immutableRecord });
      }
      if (publicProfile && !privateCanonicalSource) {
        result.projectionFindings.push({ code: 'DOC-PUB-002', file: displayPath, classification: immutableRecord.classification });
      }
    } else if (isCurrentGovernedPath(displayPath)) {
      const keys = new Set(metadata ? frontMatterKeys(metadata) : []);
      const missing = CURRENT_REQUIRED_FIELDS.filter((field) => !keys.has(field));
      if (!metadata || missing.length > 0) {
        result.governanceFindings.push({
          code: 'DOC-HDR-001',
          file: displayPath,
          missing: metadata ? missing : CURRENT_REQUIRED_FIELDS
        });
      }

      const classification = frontMatterValue(metadata, 'classification') ?? '';
      const language = frontMatterValue(metadata, 'language');
      const version = frontMatterValue(metadata, 'version');
      const documentId = frontMatterValue(metadata, 'document_id');
      const controlVersion = documentControlVersion(content);
      if (changedGovernedDocument && controlVersion && controlVersion !== version) {
        result.governanceFindings.push({ code: 'DOC-HDR-004', file: displayPath, frontMatterVersion: version, documentControlVersion: controlVersion });
      }
      const historyVersion = latestHistoryVersion(metadata);
      if (changedGovernedDocument && historyVersion && historyVersion !== version) {
        result.governanceFindings.push({ code: 'DOC-HDR-005', file: displayPath, frontMatterVersion: version, latestChangeHistoryVersion: historyVersion });
      }

      if (HISTORICAL_STATUS_MARKERS.test(`${classification} ${frontMatterValue(metadata, 'status') ?? ''}`)) {
        result.roleFindings.push({ code: 'DOC-HIST-001', file: displayPath, classification });
      }
      if (metadata && (!parseVersion(version) || language?.toLowerCase() !== 'en')) {
        result.governanceFindings.push({ code: 'DOC-HDR-002', file: displayPath, version, language });
      }
      if (documentId) {
        const existing = documentIds.get(documentId) ?? [];
        existing.push(displayPath);
        documentIds.set(documentId, existing);
      }
      if (language?.toLowerCase() !== 'en' || GERMAN_LANGUAGE_MARKERS.test(changedBody(content))) {
        result.languageFindings.push({ code: 'DOC-LANG-001', file: displayPath });
        result.currentGermanDocumentCount += 1;
      }
      if (publicProfile) {
        const projectionClassification = privateCanonicalSource
          ? resolvePublicationPath(displayPath, Buffer.from(content)).classification
          : 'PUBLIC';
        if (!privateCanonicalSource || projectionClassification === 'PUBLIC') {
          result.publicDocumentCount += 1;
          if (classification.toLowerCase() !== 'public') {
            result.projectionFindings.push({ code: 'DOC-PUB-002', file: displayPath, classification });
          }
          if (privateRoot && !(await exists(path.join(privateRoot, displayPath)))) {
            result.projectionFindings.push({ code: 'DOC-PUB-001', file: displayPath, reason: 'No private source path.' });
          }
        }
      }

      if (changedFiles.has(displayPath) && baseRef) {
        const previous = await gitFileAt(root, baseRef, displayPath);
        if (previous && changedBody(previous) !== changedBody(content)) {
          const previousMetadata = frontMatter(previous);
          if (frontMatterValue(previousMetadata, 'version') === version) {
            result.headerChangeFindings.push({ code: 'DOC-CHANGE-001', file: displayPath, reason: 'Content changed without a version bump.' });
          }
        }
      }
    }

    if (isHistoryPath(displayPath)) {
      const classification = frontMatterValue(metadata, 'classification') ?? '';
      if (classification.toLowerCase() === 'public') {
        result.projectionFindings.push({ code: 'DOC-HIST-002', file: displayPath, reason: 'Historical documentation cannot be public.' });
      }
      if (publicProfile && !privateCanonicalSource) {
        result.projectionFindings.push({ code: 'DOC-HIST-002', file: displayPath, reason: 'Public projection contains docs/history.' });
      }
    }

    const contentHash = createHash('sha256').update(content).digest('hex');
    const existing = contentGroups.get(contentHash) ?? [];
    existing.push(displayPath);
    contentGroups.set(contentHash, existing);

    const whitespaceLines = content
      .split('\n')
      .map((line, index) => ({ line, number: index + 1 }))
      .filter(({ line }) => /[ \t]{3,}$/.test(line))
      .map(({ number }) => number);

    if (whitespaceLines.length > 0) {
      result.whitespaceIssues.push({ file: displayPath, lines: whitespaceLines });
    }

    if (isHistoryPath(displayPath)) {
      continue;
    }

    for (const target of markdownLinks(content)) {
      if (isExternalLink(target)) {
        continue;
      }

      const localTarget = target.split('#', 1)[0];
      if (!localTarget) {
        continue;
      }

      const resolved = localTarget.startsWith('/')
        ? path.join(root, localTarget)
        : path.resolve(path.dirname(filePath), localTarget);

      if (!(await exists(resolved))) {
        result.linkIssues.push({ file: displayPath, target });
      }
    }

    if (!isConfidentialDocument(metadata)) {
      for (const match of findSensitiveMatches(content)) {
        result.sensitiveMatches.push({ file: displayPath, ...match });
      }
    }
  }

  for (const [documentId, files] of documentIds) {
    if (files.length > 1) {
      result.documentIdDuplicates.push({ code: 'DOC-ID-001', documentId, files });
    }
  }

  for (const [, files] of contentGroups) {
    if (files.length > 1 && !isHistoricalAuditEvidence(files)) {
      result.duplicateNames.push({ name: path.basename(files[0]), files });
    }
  }

  const requiredDocuments = publicProfile ? PUBLIC_PROJECT_DOCUMENTS : REQUIRED_PROJECT_DOCUMENTS;
  for (const document of requiredDocuments) {
    if (!(await exists(path.join(root, document)))) {
      result.missingProjectDocuments.push(document);
    }
  }

  // Gov3 owns the single canonical-state validator; docs:check only routes
  // the Sekalum adapter result into its existing blocking findings channel.
  // A checked-out private repository is the explicit Sekalum mapping context;
  // absence of its required canonical IEP must remain a blocking finding.
  const sekAlumPrivateMapping = !publicProfile && await exists(path.join(root, '.git'));
  const canonicalIepPresent = !publicProfile && await exists(path.join(root, IEP_RC3_PATH));
  if (sekAlumPrivateMapping || canonicalIepPresent) {
    const { path: consistencyPath, consistency } = await privateIepConsistency(root, injectedPrivateIepConsistency);
    if (consistency.result !== 'PASS') {
      result.governanceFindings.push({ code: 'DOC-CANONICAL-STATE-001', file: consistencyPath, reason: 'CANONICAL_STATE_CONSISTENCY_BLOCK', diagnostics: consistency.diagnostics });
    }
  }

  return result;
}

export function strictBlockingFindingCount(result) {
  return result.canonicalMetadataIssues.length
    + result.linkIssues.length
    + result.sensitiveMatches.length
    + result.duplicateNames.length
    + result.whitespaceIssues.length
    + result.missingProjectDocuments.length
    + (result.governanceFindings?.length ?? 0)
    + (result.roleFindings?.length ?? 0)
    + (result.languageFindings?.length ?? 0)
    + (result.headerChangeFindings?.length ?? 0)
    + (result.projectionFindings?.length ?? 0)
    + (result.documentIdDuplicates?.length ?? 0);
}

function printReport(result) {
  console.log(`Markdown documents: ${result.documentCount}`);
  console.log(`Documents with front matter: ${result.frontMatterCount}`);
  console.log(`Canonical documents: ${result.canonicalDocuments.length}`);
  console.log(`Canonical metadata findings: ${result.canonicalMetadataIssues.length}`);
  console.log(`Local link findings: ${result.linkIssues.length}`);
  console.log(`Sensitive-pattern findings: ${result.sensitiveMatches.length}`);
  console.log(`Duplicate document groups: ${result.duplicateNames.length}`);
  console.log(`Whitespace findings: ${result.whitespaceIssues.length}`);
  console.log(`Missing project documents: ${result.missingProjectDocuments.length}`);
  console.log(`Current governed documents: ${result.currentDocumentCount ?? 0}`);
  console.log(`Historical documents: ${result.historicalDocumentCount ?? 0}`);
  console.log(`Documentation governance findings: ${result.governanceFindings?.length ?? 0}`);
  console.log(`Role/history findings: ${result.roleFindings?.length ?? 0}`);
  console.log(`Language findings: ${result.languageFindings?.length ?? 0}`);
  console.log(`Changed-document findings: ${result.headerChangeFindings?.length ?? 0}`);
  console.log(`Projection findings: ${result.projectionFindings?.length ?? 0}`);
  console.log(`Duplicate document IDs: ${result.documentIdDuplicates?.length ?? 0}`);
  console.log(`Immutable digest-bound records: ${result.immutableExceptions?.length ?? 0}`);

  for (const issue of result.canonicalMetadataIssues) {
    console.log(`canonical metadata: ${issue.file} missing ${issue.missing.join(', ')}`);
  }

  for (const issue of result.linkIssues) {
    console.log(`local link: ${issue.file} -> ${issue.target}`);
  }

  for (const issue of result.sensitiveMatches) {
    console.log(`sensitive pattern: ${issue.file} (${issue.type}: ${issue.value})`);
  }

  for (const collection of [
    result.governanceFindings,
    result.roleFindings,
    result.languageFindings,
    result.headerChangeFindings,
    result.projectionFindings,
    result.documentIdDuplicates
  ]) {
    for (const issue of collection ?? []) {
      console.log(`${issue.code ?? 'documentation finding'}: ${issue.file ?? issue.documentId}`);
    }
  }
}

async function main() {
  const strict = process.argv.includes('--strict');
  const result = await auditDocumentation(process.cwd(), { publicProfile: process.argv.includes('--public') });
  printReport(result);

  if (strict) {
    if (strictBlockingFindingCount(result) > 0) {
      process.exitCode = 1;
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
