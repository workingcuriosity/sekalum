import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

import {
  createIsolatedRuntime,
  sourcePath,
  testEnvironment
} from '../support/isolated-runtime.js';

test('CLI refresh command runs refresh workflow without regression', () => {
  const runtime = createIsolatedRuntime('sekalum-refresh-cli-');

  try {
    const result = spawnSync(process.execPath, [sourcePath('src/cli/run-refresh.js')], {
      cwd: runtime.cwd,
      encoding: 'utf8',
      env: testEnvironment(),
      timeout: 10000,
    });

    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /Provider registered: threads/);
    assert.match(result.stdout, /Application container built/);
    assert.match(result.stdout, /Checking \d+ credential\(s\) for refresh/);
    assert.match(result.stdout, /Refresh candidates processed: \d+/);
  } finally {
    runtime.cleanup();
  }
});
