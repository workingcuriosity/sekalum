import { readdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';

async function collect(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await collect(fullPath));
    else if (entry.isFile() && entry.name.endsWith('.test.js')) files.push(fullPath);
  }
  return files;
}

const excluded = new Set([
  'tests/unit/documentation-quality-audit.test.js',
  'tests/unit/ui-executable-report.test.js',
  'tests/unit/ui-model-tooling.test.js'
]);
const files = (await Promise.all(['tests/unit', 'tests/component', 'tests/architecture', 'tests/integration'].map(collect)))
  .flat()
  .filter((file) => !excluded.has(file.replaceAll('\\', '/')))
  .sort();

const child = spawn(process.execPath, ['--test', ...files], {
  stdio: 'inherit',
  env: { ...process.env, NODE_ENV: 'test', PUBLIC_PROFILE: '1' }
});

child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exitCode = code ?? 1;
});
