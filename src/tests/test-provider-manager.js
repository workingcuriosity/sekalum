const ProviderManager = require('../services/providerManager');

class FakeProvider {
    constructor() {
        this.name = 'fake';
    }

    async refresh(context) {
        return {
            refreshed: true,
            contextReceived: !!context
        };
    }
}

async function main() {
    const manager = new ProviderManager();

    manager.register(new FakeProvider());

    console.log('[Test] Providers:', manager.listProviders());

    const result = await manager.refreshProvider('fake', {
        source: 'test'
    });

    console.log('[Test] Single Refresh:', result);

    const all = await manager.refreshAll({
        source: 'test-all'
    });

    console.log('[Test] Refresh All:', all);
}

main().catch((err) => {
    console.error('[Test] Failed:', err.message);
    process.exit(1);
});
