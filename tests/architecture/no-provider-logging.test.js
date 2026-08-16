import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const PROVIDERS_DIR = path.resolve('src/providers');

async function listJavaScriptFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...await listJavaScriptFiles(fullPath));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith('.js') && !entry.name.includes('.bak')) {
      files.push(fullPath);
    }
  }

  return files;
}

test('providers do not create framework log entries', async () => {
  const files = await listJavaScriptFiles(PROVIDERS_DIR);
  const violations = [];

  for (const file of files) {
    const source = await readFile(file, 'utf8');

    if (/\blogger\b|console\./.test(source)) {
      violations.push(path.relative(process.cwd(), file));
    }
  }

  assert.deepEqual(violations, []);
});
