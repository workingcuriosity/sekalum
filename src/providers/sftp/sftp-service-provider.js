import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { connectionCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { SftpClient } from '../../api/sftp/sftp-client.js';
import { SftpConnectionService } from '../../connections/sftp/sftp-connection-service.js';
import { SftpProvider } from './sftp-provider.js';

export class SftpServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.SFTP_CLIENT, () => {
      return new SftpClient();
    });

    container.singleton(TOKENS.SFTP_CONNECTION_SERVICE, (c) => {
      return new SftpConnectionService({
        client: c.resolve(TOKENS.SFTP_CLIENT)
      });
    });

    container.singleton(TOKENS.SFTP_PROVIDER, (c) => {
      return new SftpProvider({
        connectionService: c.resolve(TOKENS.SFTP_CONNECTION_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'sftp',
        provider: container.resolve(TOKENS.SFTP_PROVIDER),
        apiClient: container.resolve(TOKENS.SFTP_CLIENT),
        displayName: 'SFTP Credentials',
        description: 'SFTP username/password provider for secure file transfer credentials',
        capabilities: new ProviderCapabilities([
          ProviderCapability.VALIDATION,
          ProviderCapability.HEALTH_CHECK
        ]),
        credentialFields: connectionCredentialFields({ defaultPort: 22 }),
        credentialMethods: [new CredentialMethod({ key: 'username-password', displayName: 'Username and password', authenticationMethod: 'username-password', credentialFields: connectionCredentialFields({ defaultPort: 22 }), operationCapabilities: [ProviderCapability.VALIDATION, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'username-password' })],
        metadata: {
          authType: 'username-password',
          protocol: 'sftp',
          defaultPort: 22,
          requiredSecrets: ['host', 'username', 'password'],
          optionalSecrets: ['port'],
          credentialType: 'connection'
        }
      })
    );
  }
}
