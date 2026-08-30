import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const TEST_ENCRYPTION_KEY = '12345678901234567890123456789012';

export function sourcePath(relativePath) {
  return path.join(repositoryRoot, relativePath);
}

export function createIsolatedRuntime(prefix) {
  const cwd = mkdtempSync(path.join(os.tmpdir(), prefix));

  return {
    cwd,
    cleanup() {
      rmSync(cwd, { recursive: true, force: true });
    }
  };
}

export function testEnvironment(overrides = {}) {
  return {
    ...process.env,
    NODE_ENV: 'test',
    TOKEN_ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
    ...overrides
  };
}

export async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;

  await new Promise((resolve) => {
    const finish = () => {
      clearTimeout(forceKillTimer);
      resolve();
    };
    const forceKillTimer = setTimeout(() => child.kill('SIGKILL'), 2000);
    child.once('close', finish);
    child.kill('SIGTERM');
  });
}
