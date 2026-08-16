const OperationContext = require('../models/OperationContext');

const context = new OperationContext({
    source: 'scheduler',
    dryRun: true,
    force: false,
    metadata: {
        provider: 'threads'
    }
});

console.log('[Test] Source:', context.getSource());
console.log('[Test] DryRun:', context.isDryRun());
console.log('[Test] Force:', context.isForced());
console.log('[Test] OperationId:', context.getOperationId());
console.log('[Test] Metadata:', context.getMetadata());
