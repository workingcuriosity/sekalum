const BaseCommand = require('../commands/BaseCommand');
const CommandDispatcher = require('../commands/CommandDispatcher');

class FakeCommand extends BaseCommand {
    constructor() {
        super('fake');
    }

    async execute(input = {}) {
        return this.success('fake.execute', {
            received: input
        });
    }
}

async function main() {
    const dispatcher = new CommandDispatcher();

    dispatcher.register(new FakeCommand());

    console.log('[Test] Commands:', dispatcher.list());

    const result = await dispatcher.execute('fake', {
        hello: 'world'
    });

    console.log('[Test] Result:', result);
}

main().catch((err) => {
    console.error('[Test] Failed:', err.message);
    process.exit(1);
});
