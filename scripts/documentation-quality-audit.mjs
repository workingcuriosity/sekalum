import { access, readdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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
  return files.every((file) => file.startsWith('docs/architecture/governance/audits/'));
}

export async function auditDocumentation(root = process.cwd(), { publicProfile = false } = {}) {
  const docsDirectory = path.join(root, 'docs');
  const markdownFiles = await listMarkdownFiles(docsDirectory);
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
    missingProjectDocuments: []
  };
  const contentGroups = new Map();

  for (const filePath of allFiles) {
    const content = await readFile(filePath, 'utf8');
    const displayPath = relativePath(root, filePath);
    const metadata = frontMatter(content);

    if (metadata) {
      result.frontMatterCount += 1;
      const keys = frontMatterKeys(metadata);

      if (keys.has('canonical') && metadata.some((line) => /^canonical:\s*true\s*$/i.test(line))) {
        result.canonicalDocuments.push(displayPath);
        const missing = CANONICAL_FIELDS.filter((field) => !keys.has(field));

        if (missing.length > 0) {
          result.canonicalMetadataIssues.push({ file: displayPath, missing });
        }
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

  return result;
}

export function strictBlockingFindingCount(result) {
  return result.canonicalMetadataIssues.length
    + result.linkIssues.length
    + result.sensitiveMatches.length
    + result.duplicateNames.length
    + result.whitespaceIssues.length
    + result.missingProjectDocuments.length;
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

  for (const issue of result.canonicalMetadataIssues) {
    console.log(`canonical metadata: ${issue.file} missing ${issue.missing.join(', ')}`);
  }

  for (const issue of result.linkIssues) {
    console.log(`local link: ${issue.file} -> ${issue.target}`);
  }

  for (const issue of result.sensitiveMatches) {
    console.log(`sensitive pattern: ${issue.file} (${issue.type}: ${issue.value})`);
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
