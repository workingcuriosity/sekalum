import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('Docker Compose declares the explicit package-version image and OCI label', () => {
  const packageManifest = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const compose = fs.readFileSync('docker-compose.yml', 'utf8');
  const dockerfile = fs.readFileSync('Dockerfile', 'utf8');

  assert.match(compose, new RegExp(`image: credential-hub:${packageManifest.version.replaceAll('.', '\\.')}`));
  assert.match(compose, new RegExp(`APP_VERSION: ${packageManifest.version.replaceAll('.', '\\.')}`));
  assert.match(dockerfile, /COPY LICENSE NOTICE SECURITY\.md \.\//);
  assert.match(dockerfile, /COPY docs\/project\/THIRD_PARTY_SOFTWARE\.md \.\/docs\/project\//);
  assert.match(dockerfile, /ARG APP_VERSION=/);
  assert.match(dockerfile, /org\.opencontainers\.image\.version="\$\{APP_VERSION\}"/);
  assert.doesNotMatch(compose, /image:\s*.*:latest/);
});

test('local Docker defaults remain portable and observable', () => {
  assert.ok(fs.existsSync('.env.example'));

  const environmentExample = fs.readFileSync('.env.example', 'utf8');
  const compose = fs.readFileSync('docker-compose.yml', 'utf8');
  const dockerfile = fs.readFileSync('Dockerfile', 'utf8');
  const encryptionKey = environmentExample.match(/^TOKEN_ENCRYPTION_KEY=(.+)$/m)?.[1];

  assert.ok(encryptionKey);
  assert.equal(encryptionKey.length, 32);
  assert.doesNotMatch(compose, /external:\s*true/);
  assert.doesNotMatch(compose, /^\s*container_name:/m);
  assert.match(compose, /^\s*-\s+\.\/storage:\/app\/storage\s*$/m);
  assert.match(dockerfile, /^EXPOSE\s+3000\s*$/m);
  assert.match(dockerfile, /^HEALTHCHECK\s+/m);
});
