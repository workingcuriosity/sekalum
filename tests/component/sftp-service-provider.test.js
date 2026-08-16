import test from 'node:test';
import assert from 'node:assert/strict';

import { Container } from '../../src/container/container.js';
import { ApplicationServiceProvider } from '../../src/container/application-service-provider.js';
import { SftpServiceProvider } from '../../src/providers/sftp/sftp-service-provider.js';
import { TOKENS } from '../../src/container/tokens.js';

test('SftpServiceProvider registers SFTP provider metadata and connection capabilities', () => {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new SftpServiceProvider().register(container);

  const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);
  const definition = registry.get('sftp');

  assert.equal(definition.name, 'sftp');
  assert.equal(definition.displayName, 'SFTP Credentials');
  assert.equal(definition.description, 'SFTP username/password provider for secure file transfer credentials');
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
    protocol: 'sftp',
    defaultPort: 22,
    requiredSecrets: ['host', 'username', 'password'],
    optionalSecrets: ['port'],
    credentialType: 'connection'
  });
});
