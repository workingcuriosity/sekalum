// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { AsyncLocalStorage } from 'node:async_hooks';

let tail = Promise.resolve();
const coordinatorContext = new AsyncLocalStorage();

/**
 * Serializes authority-bearing restore commits before their individual store
 * queues. The callback must stage, revalidate and publish without network or
 * provider calls. Re-entry is allowed for adapters participating in a commit.
 */
export function withRestoreCommitBoundary(operation) {
  if (coordinatorContext.getStore() === true) return Promise.resolve().then(operation);
  const guarded = () => coordinatorContext.run(true, operation);
  const run = tail.then(guarded, guarded);
  tail = run.catch(() => undefined);
  return run;
}

export class RestoreCommitCoordinator {
  run(operation) {
    if (typeof operation !== 'function') throw new Error('RestoreCommitCoordinator.run() requires a function');
    return withRestoreCommitBoundary(operation);
  }
}
