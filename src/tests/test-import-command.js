const CommandDispatcher = require('../commands/CommandDispatcher');
const ImportTokenCommand = require('../commands/ImportTokenCommand');

async function main() {

    const dispatcher = new CommandDispatcher();

    dispatcher.register(
        new ImportTokenCommand()
    );

    console.log('[Test] Commands:', dispatcher.list());

    const result = await dispatcher.execute(
        'import-token',
        'threads'
    );

    console.log('\n[Test] Result:\n');
    console.dir(result, { depth: null });

}

main().catch((err) => {
    console.error('[Test] Failed:', err);
    process.exit(1);
});
