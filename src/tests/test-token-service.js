const TokenService = require('../services/tokenService');
const getRedis = require('../config/redis');

async function main() {
    const tokenService = new TokenService();

    await tokenService.saveToken('threads', {
        access_token: 'TEST_TOKEN',
        expires_at: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
        refreshed_at: new Date().toISOString(),
        status: 'test'
    });

    const saved = await tokenService.getToken('threads');

    console.log('[Test] Token from Redis:', saved);

    await getRedis().quit();
    process.exit(0);
}

main().catch((err) => {
    console.error('[Test] Failed:', err.message);
    process.exit(1);
});
