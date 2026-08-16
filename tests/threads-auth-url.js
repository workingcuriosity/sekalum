import { bootstrap } from '../src/bootstrap.js';
import { TOKENS } from '../src/container/tokens.js';

const app = await bootstrap();
const provider = app.container.resolve(TOKENS.THREADS_PROVIDER);

const state = `threads-${Date.now()}`;

const url = provider.oauthService.getAuthorizationUrl({ state });

console.log('\nThreads OAuth URL:\n');
console.log(url);
console.log('\nState:\n');
console.log(state);
