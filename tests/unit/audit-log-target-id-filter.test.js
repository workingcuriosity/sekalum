import test from 'node:test';
import assert from 'node:assert/strict';

import { AuditLogService } from '../../src/services/audit-log-service.js';

test('AuditLogService filters audit entries by targetId', async () => {
  const service = new AuditLogService({
    clock: () => new Date('2026-07-08T10:00:00.000Z')
  });

  await service.record({ action: 'credential.created', targetType: 'credential', targetId: 'cred-1' });
  await service.record({ action: 'credential.created', targetType: 'credential', targetId: 'cred-2' });

  const entries = await service.list({ targetType: 'credential', targetId: 'cred-1' });

  assert.equal(entries.length, 1);
  assert.equal(entries[0].targetId, 'cred-1');
});
