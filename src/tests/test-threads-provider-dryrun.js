const ThreadsProvider = require('../providers/threadsProvider');
const OperationContext = require('../models/OperationContext');
const Token = require('../models/Token');

async function main() {
    const provider = new ThreadsProvider();

    const context = new OperationContext({
        source: 'test',
        dryRun: true
    });

    const currentToken = new Token({
        provider: 'threads',
        accessToken: 'TEST_TOKEN',
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });

    const result = await provider.refresh(context, currentToken);

    console.log('[Test] Result:', result);
}

main().catch((err) => {
    console.error('[Test] Failed:', err.message);
    process.exit(1);
});
