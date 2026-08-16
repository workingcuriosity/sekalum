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

    if (entry.isFile() && entry.name.endsWith('.js') && !entry.name.includes('.bak') && !entry.name.endsWith('service-provider.js')) {
      files.push(fullPath);
    }
  }

  return files;
}

test('providers do not import or instantiate HttpClient directly', async () => {
  const files = await listJavaScriptFiles(PROVIDERS_DIR);
  const violations = [];

  for (const file of files) {
    const source = await readFile(file, 'utf8');

    if (/http-client|httpClient|HttpClient/.test(source)) {
      violations.push(path.relative(process.cwd(), file));
    }
  }

  assert.deepEqual(violations, []);
});
