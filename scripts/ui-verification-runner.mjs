import { spawn } from 'node:child_process';
import { loadModel } from './ui-model-tools.mjs';

function run(script) {
  return new Promise((resolve) => {
    const child = spawn(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', script], { stdio: 'inherit' });
    child.on('close', (code) => resolve(code ?? 1));
    child.on('error', () => resolve(1));
  });
}

const failures = [];
try {
  const { model } = await loadModel(process.cwd());
  const hasExecutableProfile = model.interactions.some((interaction) => interaction.verification);
  const scripts = ['ui:test:seed'];
  for (const script of scripts) if (await run(script) !== 0) failures.push(script);

  if (hasExecutableProfile && await run('ui:test:smoke') !== 0) {
      failures.push('ui:test:smoke');
  }
  if (await run('ui:verification:report') !== 0) failures.push('ui:verification:report');
} finally {
  if (await run('ui:test:cleanup') !== 0) failures.push('ui:test:cleanup');
}
if (failures.length) {
  console.error(`UI verification completed with failures: ${failures.join(', ')}`);
  process.exitCode = 1;
}
