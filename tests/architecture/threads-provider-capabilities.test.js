import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { ProviderCapability } from '../../src/models/provider-capability.js';

test('ThreadsProvider registers only public provider-operation capabilities', async () => {
  const source = await readFile('src/providers/threads/threads-service-provider.js', 'utf8');

  assert.match(source, /ProviderCapability\.OAUTH/);
  assert.match(source, /ProviderCapability\.REFRESH/);
  assert.match(source, /ProviderCapability\.HEALTH_CHECK/);
  assert.doesNotMatch(source, /ProviderCapability\.BACKUP/);
  assert.doesNotMatch(source, /ProviderCapability\.SCHEDULER/);
});

test('non-provider framework capabilities are still declared but not used by ThreadsProvider', () => {
  assert.equal(ProviderCapability.BACKUP, 'backup');
  assert.equal(ProviderCapability.SCHEDULER, 'scheduler');
});
