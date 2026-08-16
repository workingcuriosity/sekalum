const getRedis = require('../config/redis');

async function main() {
    const redis = getRedis();

    const pong = await redis.ping();
    console.log('[Test] Redis ping:', pong);

    await redis.quit();
    process.exit(0);
}

main().catch(async (err) => {
    console.error('[Test] Failed:', err.message);
    process.exit(1);
});
