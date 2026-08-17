// Copyright (C) 2026 Working Curiosity
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { bootstrap } from '../bootstrap.js';
import { TOKENS } from '../container/tokens.js';

const provider = process.argv[2];
const account = process.argv[3] ?? null;

if (!provider) {
  console.error('Usage: node src/cli/run-oauth.js <provider> [account]');
  process.exit(1);
}

const app = await bootstrap();

const command = app.container.resolve(TOKENS.START_OAUTH_COMMAND);

const result = await command.execute({
  provider,
  account
});

if (!result.success) {
  console.error(result.error?.message ?? 'OAuth start failed');
  process.exit(1);
}

console.log(result.data.authorizationUrl);

process.exit(0);
