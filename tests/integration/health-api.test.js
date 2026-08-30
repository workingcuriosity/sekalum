import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';

import {
  createIsolatedRuntime,
  sourcePath,
  stopChild,
  testEnvironment
} from '../support/isolated-runtime.js';

function waitForOutput(child, pattern, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => {
      reject(new Error(`Timed out waiting for ${pattern}. Output so far:\n${output}`));
    }, timeoutMs);

    const onData = (chunk) => {
      output += chunk.toString();
      if (pattern.test(output)) {
        clearTimeout(timer);
        resolve(output);
      }
    };

    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Process exited with code ${code}. Output:\n${output}`));
    });
  });
}

test('HTTP health endpoint returns UP status', async () => {
  const port = '3001';
  const runtime = createIsolatedRuntime('sekalum-health-api-');
  const child = spawn(process.execPath, [sourcePath('src/index.js')], {
    cwd: runtime.cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: testEnvironment({ OAUTH_CALLBACK_PORT: port }),
  });

  try {
    await waitForOutput(child, /Application started/);

    const response = await fetch(`http://127.0.0.1:${port}/health`);

    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type')?.includes('application/json'), true);

    const body = await response.json();

    assert.deepEqual(body, { status: 'UP' });
  } finally {
    await stopChild(child);
    assert.equal(existsSync('storage'), false, 'application startup must not write publication storage');
    runtime.cleanup();
  }
});
