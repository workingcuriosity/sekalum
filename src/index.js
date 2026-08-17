// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { bootstrap } from './bootstrap.js';

let app = null;
let stopping = false;

async function stop(signal) {
  if (stopping) {
    return;
  }

  stopping = true;

  try {
    if (app) {
      await app.stop();
    }
    process.exit(0);
  } catch (error) {
    console.error(`Application failed to stop after ${signal}:`, error);
    process.exit(1);
  }
}

process.once('SIGTERM', () => {
  void stop('SIGTERM');
});

process.once('SIGINT', () => {
  void stop('SIGINT');
});

try {
  app = await bootstrap();
  await app.start();
} catch (error) {
  console.error('Application failed to start:', error);
  process.exit(1);
}
