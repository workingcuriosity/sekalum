// Process-local coordination for cross-store binding admission.
// Credential and Consumer Grant writes share this mutex so a Grant binding
// cannot be invalidated between its final validation and durable persistence.
import { AsyncLocalStorage } from 'node:async_hooks';

let tail = Promise.resolve();
const lockContext = new AsyncLocalStorage();

export function withBindingCommitLock(operation) {
  // Metadata reads can perform a one-time legacy migration while a Grant
  // commit is revalidating. Re-enter the current lock instead of deadlocking.
  if (lockContext.getStore() === true) return Promise.resolve().then(operation);
  const guarded = () => lockContext.run(true, operation);
  const run = tail.then(guarded, guarded);
  tail = run.catch(() => undefined);
  return run;
}
