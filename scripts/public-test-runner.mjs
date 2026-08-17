import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import path from 'node:path';

import {
  PUBLIC_TEST_FILES,
  publicTestContractFindings
} from './public-test-contract.mjs';

const root = process.cwd();
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
  env: { ...process.env, NODE_ENV: 'test', PUBLIC_PROFILE: '1' }
});

child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exitCode = code ?? 1;
});
