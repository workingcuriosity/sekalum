import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

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

test('CredentialManager does not depend on TokenStore directly', async () => {
  const source = await readFile(path.resolve('src/managers/credential-manager.js'), 'utf8');

  assert.equal(source.includes('tokenStore'), false);
  assert.equal(source.includes('TokenStore'), false);
});

test('Commands do not import storage classes directly', async () => {
  const files = await listJavaScriptFiles(path.resolve('src/commands'));
  const violations = [];

  for (const file of files) {
    const source = await readFile(file, 'utf8');

    if (/\.\.\/storage\//.test(source) || /TokenStore|CredentialStore|JsonStore|BackupStore/.test(source)) {
      violations.push(path.relative(process.cwd(), file));
    }
  }

  assert.deepEqual(violations, []);
});


test('CredentialStore does not depend on TokenRecord mapping directly', async () => {
  const source = await readFile(path.resolve('src/storage/credential-store.js'), 'utf8');

  assert.equal(source.includes('../models/token-record.js'), false);
  assert.equal(source.includes('TokenRecord'), false);
  assert.equal(source.includes('new TokenRecord'), false);
});

test('TokenRecord imports stay inside legacy storage and lifecycle boundary', async () => {
  const files = await listJavaScriptFiles(path.resolve('src'));
  const allowedFiles = new Set([
    'src/models/token-record.js',
    'src/storage/token-store.js',
    'src/storage/backup-store.js',
    'src/storage/legacy-token-credential-store-adapter.js',
    'src/services/token-lifecycle-service.js'
  ]);
  const violations = [];

  for (const file of files) {
    const source = await readFile(file, 'utf8');

    if (source.includes('../models/token-record.js')) {
      const relativePath = path.relative(process.cwd(), file);

      if (!allowedFiles.has(relativePath)) {
        violations.push(relativePath);
      }
    }
  }

  assert.deepEqual(violations, []);
});
