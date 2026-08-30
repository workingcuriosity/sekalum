import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import path from 'node:path';

import {
  PUBLIC_TEST_FILES,
  publicTestContractFindings
} from './public-test-contract.mjs';

const root = process.cwd();
const PUBLICATION_TEST_KEY = '12345678901234567890123456789012';
const safeEnvironment = {
  PATH: process.env.PATH ?? '/usr/bin:/bin',
  HOME: process.env.HOME ?? '/tmp',
  TMPDIR: process.env.TMPDIR ?? '/tmp',
  NODE_ENV: 'test',
  PUBLIC_PROFILE: '1',
  TOKEN_ENCRYPTION_KEY: PUBLICATION_TEST_KEY,
  TOKEN_ENCRYPTION_KEY_VERSION: '1'
};
const missing = [];
for (const file of PUBLIC_TEST_FILES) {
  try {
    await access(path.join(root, file));
  } catch {
    missing.push(file);
  }
}
if (missing.length > 0) throw new Error(`Explicit PUBLIC tests are missing: ${missing.join(', ')}`);

if (process.env.PUBLIC_PROFILE === '1') {
  const findings = await publicTestContractFindings(root);
  if (findings.length > 0) {
    throw new Error(`Public Test Contract drift: ${findings.map((finding) => `${finding.type}: ${finding.file}`).join('; ')}`);
  }
}

const child = spawn(process.execPath, ['--test', ...PUBLIC_TEST_FILES], {
  stdio: 'inherit',
  env: safeEnvironment
});

child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exitCode = code ?? 1;
});
