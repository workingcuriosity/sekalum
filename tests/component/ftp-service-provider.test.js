import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { FtpServiceProvider } from '../../src/providers/ftp/ftp-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

test('FtpServiceProvider registers FTP provider metadata and connection capabilities', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new FtpServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('ftp');

  assert.equal(definition.name, 'ftp');
  assert.equal(definition.displayName, 'FTP Credentials');
  assert.equal(definition.description, 'FTP username/password provider for file transfer credentials');
  assert.deepEqual(definition.capabilities.toArray(), [
    'validation',
    'health-check'
  ]);
  assert.deepEqual(definition.oauthSecurityRequirements.toJSON(), {
    state: 'required',
    pkce: 'disabled',
    nonce: 'disabled'
  });
  assert.deepEqual(definition.metadata, {
    authType: 'username-password',
    protocol: 'ftp',
    defaultPort: 21,
    requiredSecrets: ['host', 'username', 'password'],
    optionalSecrets: ['port'],
    credentialType: 'connection'
  });
});
