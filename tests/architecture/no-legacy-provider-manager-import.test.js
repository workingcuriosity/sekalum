import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const SRC_DIR = path.resolve('src');
const LEGACY_PROVIDER_MANAGER = path.normalize('src/services/providerManager.js');

async function listJavaScriptFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      if (entry.name === 'tests') {
        continue;
      }

      files.push(...await listJavaScriptFiles(fullPath));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith('.js') && !entry.name.includes('.bak')) {
      files.push(fullPath);
    }
  }

  return files;
}

test('active source files do not import the legacy services/providerManager.js', async () => {
  const files = await listJavaScriptFiles(SRC_DIR);
  const violations = [];

  for (const file of files) {
    const relativePath = path.relative(process.cwd(), file);

    if (path.normalize(relativePath) === LEGACY_PROVIDER_MANAGER) {
      continue;
    }

    const source = await readFile(file, 'utf8');

    if (/services\/providerManager|services\\providerManager/.test(source)) {
      violations.push(relativePath);
    }
  }

  assert.deepEqual(violations, []);
});
