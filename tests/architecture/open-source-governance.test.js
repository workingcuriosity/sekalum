import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const LICENSE_HEADER = `// Copyright (C) 2026 Working Curiosity
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.
`;

const HEADER_FILES = [
  'src/index.js',
  'src/bootstrap.js',
  'src/config/config.js',
  'src/oauth/oauth-callback-server.js',
  'src/managers/provider-manager.js',
  'src/models/provider-definition.js',
  'src/cli/run-oauth.js',
  'src/cli/run-refresh.js',
  'public/admin/i18n.js',
  'public/admin/wizard.js',
  'public/admin/dashboard.js'
];

test('important entry points and public framework modules use the standard AGPL header', () => {
  for (const file of HEADER_FILES) {
    assert.ok(fs.readFileSync(path.resolve(file), 'utf8').startsWith(LICENSE_HEADER), `${file} is missing the standard header`);
  }
});

test('repository metadata identifies Credential HUB as an AGPL project', () => {
  const packageMetadata = JSON.parse(fs.readFileSync(path.resolve('package.json'), 'utf8'));
  const dockerfile = fs.readFileSync(path.resolve('Dockerfile'), 'utf8');

  assert.equal(packageMetadata.name, 'sekalum');
  assert.equal(packageMetadata.license, 'AGPL-3.0-only');
  assert.equal(packageMetadata.repository.url, 'https://github.com/workingcuriosity/sekalum.git');
  assert.match(dockerfile, /org\.opencontainers\.image\.licenses="AGPL-3\.0-only"/);
});
