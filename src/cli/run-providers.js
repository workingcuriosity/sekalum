import { bootstrap } from '../bootstrap.js';
import { TOKENS } from '../container/tokens.js';

const [, , action, ...args] = process.argv;

const SUPPORTED_ACTIONS = [
  'list',
  'get',
  'capabilities',
  'catalog',
];

function usage() {
  console.error(
    `Usage: node src/cli/run-providers.js <${SUPPORTED_ACTIONS.join('|')}>`
  );
}

function success(data) {
  console.log(JSON.stringify({
    success: true,
    data,
  }, null, 2));
}

function failure(error) {
  console.error(JSON.stringify({
    success: false,
    error: {
      code: error.code ?? 'CLI_ERROR',
      message: error.message,
    },
  }, null, 2));
}

try {
  if (!action || !SUPPORTED_ACTIONS.includes(action)) {
    usage();
    process.exit(1);
  }

  const app = await bootstrap();
  const providerManager = app.container.resolve(TOKENS.PROVIDER_MANAGER);

  switch (action) {

    case 'list': {
      const providers = await providerManager.listProviders();
      success(providers);
      break;
    }

    case 'get': {
      const provider = await providerManager.getProvider(args[0]);
      success(provider);
      break;
    }

    case 'capabilities': {
      const capabilities = await providerManager.getProviderCapabilities(args[0]);
      success(capabilities);
      break;
    }

    case 'catalog': {
      if (args.length > 0) {
        const error = new Error('The catalog command does not accept positional arguments');
        error.code = 'INVALID_ARGUMENT';
        throw error;
      }
      success(providerManager.listProviderCatalog());
      break;
    }

  }

} catch (error) {
  failure(error);
  process.exit(1);
}
