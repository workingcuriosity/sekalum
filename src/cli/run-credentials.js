import { bootstrap } from '../bootstrap.js';
import { TOKENS } from '../container/tokens.js';
import { safeError } from '../utils/safe-diagnostics.js';

const [, , action, ...args] = process.argv;

const SUPPORTED_ACTIONS = [
  'list',
  'get',
  'create',
  'update',
  'delete',
  'validate',
  'refresh',
  'revoke',
  'health-check',
];

function printUsage() {
  console.error(
    `Usage: node src/cli/run-credentials.js <${SUPPORTED_ACTIONS.join('|')}> [credentialId] [jsonPayload] [--credential-method <key>]`
  );
}

function toJSON(value) {
  return value && typeof value.toJSON === 'function' ? value.toJSON() : value;
}

function printSuccess(data) {
  console.log(JSON.stringify({ success: true, data }, null, 2));
}

function printFailure(error) {
  const safe = safeError(error, { fallbackMessage: 'Credential CLI command failed' });
  console.error(
    JSON.stringify(
      {
        success: false,
        error: {
          code: safe.code ?? 'CLI_ERROR',
          message: safe.message,
        },
      },
      null,
      2,
    ),
  );
}

function parseJSONArgument(value, argumentName) {
  if (!value) {
    const error = new Error(`${argumentName} is required`);
    error.code = 'CLI_ERROR';
    throw error;
  }

  try {
    return JSON.parse(value);
  } catch {
    const error = new Error(`${argumentName} must be valid JSON`);
    error.code = 'CLI_ERROR';
    throw error;
  }
}

function withCredentialMethodKey(payload, optionArguments) {
  if (optionArguments.length === 0) return payload;
  if (optionArguments.length !== 2 || optionArguments[0] !== '--credential-method' || !optionArguments[1]?.trim()) {
    const error = new Error('credential method option must be --credential-method <key>');
    error.code = 'CLI_ERROR';
    throw error;
  }
  return { ...payload, credentialMethodKey: optionArguments[1].trim() };
}

async function executeLifecycleAction(credentialManager, lifecycleAction, credentialId) {
  if (!credentialId) {
    const error = new Error(`Credential id is required for ${lifecycleAction}`);
    error.code = 'CLI_ERROR';
    throw error;
  }

  const credential = await credentialManager.executeLifecycleAction(
    credentialId,
    lifecycleAction,
  );

  printSuccess(toJSON(credential));
}

if (!action || !SUPPORTED_ACTIONS.includes(action)) {
  printUsage();
  process.exit(1);
}

try {
  const app = await bootstrap();
  const credentialManager = app.container.resolve(TOKENS.CREDENTIAL_MANAGER);

  switch (action) {
    case 'list': {
      const credentials = await credentialManager.listCredentials();
      printSuccess(credentials.map((credential) => toJSON(credential)));
      break;
    }

    case 'get': {
      const [credentialId] = args;
      const credential = await credentialManager.getCredential(credentialId);
      printSuccess(toJSON(credential));
      break;
    }

    case 'create': {
      const [jsonPayload, ...optionArguments] = args;
      const credential = await credentialManager.register(
        withCredentialMethodKey(parseJSONArgument(jsonPayload, 'Credential payload'), optionArguments),
      );
      printSuccess(toJSON(credential));
      break;
    }

    case 'update': {
      const [credentialId, jsonPayload, ...optionArguments] = args;
      const credential = await credentialManager.updateCredential(
        credentialId,
        withCredentialMethodKey(parseJSONArgument(jsonPayload, 'Credential update payload'), optionArguments),
      );
      printSuccess(toJSON(credential));
      break;
    }

    case 'delete': {
      const [credentialId] = args;
      const credential = await credentialManager.deleteCredential(credentialId);
      printSuccess(toJSON(credential));
      break;
    }

    case 'validate':
      await executeLifecycleAction(credentialManager, 'validate', args[0]);
      break;

    case 'refresh':
      await executeLifecycleAction(credentialManager, 'refresh', args[0]);
      break;

    case 'revoke':
      await executeLifecycleAction(credentialManager, 'revoke', args[0]);
      break;

    case 'health-check':
      await executeLifecycleAction(credentialManager, 'health-check', args[0]);
      break;
  }

  process.exit(0);
} catch (error) {
  printFailure(error);
  process.exit(1);
}
