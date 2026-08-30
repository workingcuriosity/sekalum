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
    `Usage: node src/cli/run-credentials.js <${SUPPORTED_ACTIONS.join('|')}> [credentialId] [--stdin] [--credential-method <key>]`
  );
}

function cliError(message, code = 'CLI_ERROR') {
  const error = new Error(message);
  error.code = code;
  return error;
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

function parseJSONInput(value, inputName) {
  if (!value?.trim()) throw cliError(`${inputName} is required`);

  try {
    return JSON.parse(value);
  } catch {
    throw cliError(`${inputName} must be valid JSON`);
  }
}

async function readStdinPayload(optionArguments) {
  const options = parseCredentialOptions(optionArguments);
  if (!options.stdin) {
    throw cliError('Credential create/update input must be provided through --stdin', 'CLI_INPUT_REQUIRED');
  }

  if (process.stdin.isTTY) {
    throw cliError('Credential create/update input must be piped through stdin', 'CLI_INPUT_REQUIRED');
  }

  let input = '';
  try {
    for await (const chunk of process.stdin) input += chunk;
  } catch {
    throw cliError('Credential stdin input could not be read', 'CLI_INPUT_ERROR');
  }

  const payload = parseJSONInput(input, 'Credential stdin payload');
  return options.credentialMethodKey
    ? { ...payload, credentialMethodKey: options.credentialMethodKey }
    : payload;
}

function parseCredentialOptions(optionArguments) {
  let stdin = false;
  let credentialMethodKey = null;

  for (let index = 0; index < optionArguments.length; index += 1) {
    const option = optionArguments[index];
    if (option === '--stdin') {
      if (stdin) throw cliError('The --stdin option may only be provided once');
      stdin = true;
      continue;
    }

    if (option === '--credential-method') {
      const value = optionArguments[index + 1];
      if (!value?.trim()) {
        throw cliError('credential method option must be --credential-method <key>');
      }
      credentialMethodKey = value.trim();
      index += 1;
      continue;
    }

    if (!option.startsWith('-')) {
      throw cliError('Credential create/update input must be provided through --stdin', 'CLI_INPUT_REQUIRED');
    }
    throw cliError('Credential input accepts only --stdin and --credential-method <key>');
  }

  return { stdin, credentialMethodKey };
}

function toCliCredentialMetadata(credential) {
  if (credential && typeof credential.toMetadataJSON === 'function') {
    return credential.toMetadataJSON();
  }

  throw cliError('Credential command returned an unsupported output shape', 'CLI_OUTPUT_UNSUPPORTED');
}

function toCliHealthMetadata(healthResult) {
  if (!healthResult || typeof healthResult !== 'object') {
    throw cliError('Credential health-check returned an unsupported output shape', 'CLI_OUTPUT_UNSUPPORTED');
  }

  return {
    healthy: Boolean(healthResult.healthy),
    status: typeof healthResult.status === 'string' ? healthResult.status : 'unknown',
    checkedAt: healthResult.checkedAt instanceof Date
      ? healthResult.checkedAt.toISOString()
      : String(healthResult.checkedAt ?? '')
  };
}

async function executeLifecycleAction(credentialManager, lifecycleAction, credentialId, extraArguments) {
  if (!credentialId) {
    throw cliError(`Credential id is required for ${lifecycleAction}`);
  }
  if (extraArguments.length > 0) {
    throw cliError(`${lifecycleAction} does not accept additional arguments`);
  }

  const credential = await credentialManager.executeLifecycleAction(
    credentialId,
    lifecycleAction,
  );

  printSuccess(lifecycleAction === 'health-check'
    ? toCliHealthMetadata(credential)
    : toCliCredentialMetadata(credential));
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
      if (args.length > 0) throw cliError('list does not accept arguments');
      const credentials = await credentialManager.listCredentialMetadata();
      printSuccess(credentials);
      break;
    }

    case 'get': {
      const [credentialId, ...extraArguments] = args;
      if (extraArguments.length > 0) throw cliError('get accepts only a credential id');
      const credential = await credentialManager.getCredentialMetadata(credentialId);
      printSuccess(credential);
      break;
    }

    case 'create': {
      const [ ...optionArguments ] = args;
      const credential = await credentialManager.register(
        await readStdinPayload(optionArguments),
      );
      printSuccess(toCliCredentialMetadata(credential));
      break;
    }

    case 'update': {
      const [credentialId, ...optionArguments] = args;
      const credential = await credentialManager.updateCredential(
        credentialId,
        await readStdinPayload(optionArguments),
      );
      printSuccess(toCliCredentialMetadata(credential));
      break;
    }

    case 'delete': {
      const [credentialId, ...extraArguments] = args;
      if (extraArguments.length > 0) throw cliError('delete accepts only a credential id');
      const credential = await credentialManager.deleteCredential(credentialId);
      printSuccess(toCliCredentialMetadata(credential));
      break;
    }

    case 'validate':
      await executeLifecycleAction(credentialManager, 'validate', args[0], args.slice(1));
      break;

    case 'refresh':
      await executeLifecycleAction(credentialManager, 'refresh', args[0], args.slice(1));
      break;

    case 'revoke':
      await executeLifecycleAction(credentialManager, 'revoke', args[0], args.slice(1));
      break;

    case 'health-check':
      await executeLifecycleAction(credentialManager, 'health-check', args[0], args.slice(1));
      break;
  }

  process.exit(0);
} catch (error) {
  printFailure(error);
  process.exit(1);
}
