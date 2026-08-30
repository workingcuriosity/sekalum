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
  const bootstrapToken = environmentExample.match(/^ADMIN_BOOTSTRAP_TOKEN=(.+)$/m)?.[1];

  assert.ok(encryptionKey);
  assert.equal(encryptionKey.length, 32);
  assert.ok(bootstrapToken);
  assert.ok(Buffer.byteLength(bootstrapToken, 'utf8') >= 32);
  assert.notEqual(bootstrapToken, encryptionKey);
  assert.doesNotMatch(compose, /external:\s*true/);
  assert.doesNotMatch(compose, /^\s*container_name:/m);
  assert.match(compose, /^\s*-\s+"127\.0\.0\.1:3000:3000"\s*$/m);
  assert.doesNotMatch(compose, /^\s*-\s+"3000:3000"\s*$/m);
  assert.match(compose, /^\s*-\s+\.\/storage:\/app\/storage\s*$/m);
  assert.match(dockerfile, /^EXPOSE\s+3000\s*$/m);
  assert.match(dockerfile, /^HEALTHCHECK\s+/m);
});

test('Docker image runs as a non-root user and prepares writable storage', () => {
  const dockerfile = fs.readFileSync('Dockerfile', 'utf8');
  assert.match(dockerfile, /addgroup -S app && adduser -S -G app app/);
  assert.match(dockerfile, /mkdir -p \/app\/storage/);
  assert.match(dockerfile, /chown -R app:app \/app/);
  assert.match(dockerfile, /^USER app$/m);
});

test('CI third-party actions use immutable commit references', () => {
  const workflow = fs.readFileSync('.github/workflows/node-ci.yml', 'utf8');
  assert.match(workflow, /uses: actions\/checkout@[0-9a-f]{40}(?:\s+# v[\d.]+)?$/m);
  assert.match(workflow, /uses: actions\/setup-node@[0-9a-f]{40}(?:\s+# v[\d.]+)?$/m);
});
