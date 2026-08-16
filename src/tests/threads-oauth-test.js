import { bootstrap } from '../src/bootstrap.js';
import { TOKENS } from '../src/container/tokens.js';

const app = await bootstrap();

const container = app.container;

const provider = container.resolve(TOKENS.THREADS_PROVIDER);

const code = process.argv[2];

if (!code) {
  console.error(
    'Usage: node tests/threads-oauth-test.js <authorization-code>'
  );
  process.exit(1);
}

const redirectUri =
  process.env.THREADS_REDIRECT_URI;

const result = await provider.authenticate({
  code,
  redirectUri
});

console.log('\nOAuthResult\n');
console.dir(result, { depth: null });
