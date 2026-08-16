const Token = require('../models/Token');

const token = new Token({
    provider: 'threads',
    accessToken: 'TEST_TOKEN',
    expiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
    status: 'valid',
    metadata: {
        source: 'test'
    }
});

console.log('[Test] isExpired:', token.isExpired());
console.log('[Test] daysUntilExpiration:', token.daysUntilExpiration());
console.log('[Test] shouldRefresh 14 days:', token.shouldRefresh(14));

const stored = token.toStorageObject();
console.log('[Test] Storage Object:', stored);

const restored = Token.fromStorageObject(stored);
console.log('[Test] Restored Provider:', restored.provider);
console.log('[Test] Restored Metadata:', restored.metadata);
