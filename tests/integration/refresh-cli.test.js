import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('CLI refresh command runs refresh workflow without regression', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-refresh.js'], {
    encoding: 'utf8',
    timeout: 10000,
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: threads/);
  assert.match(result.stdout, /Application container built/);
  assert.match(result.stdout, /Checking \d+ credential\(s\) for refresh/);
  assert.match(result.stdout, /Refresh candidates processed: \d+/);
});
