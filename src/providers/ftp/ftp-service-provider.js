import { ServiceProvider } from '../../container/service-provider.js';
import { TOKENS } from '../../container/tokens.js';

import { ProviderDefinition } from '../../models/provider-definition.js';
import { ProviderCapabilities } from '../../models/provider-capabilities.js';
import { ProviderCapability } from '../../models/provider-capability.js';
import { connectionCredentialFields } from '../credential-field-sets.js';
import { CredentialMethod } from '../../models/credential-method.js';
import { ProviderMethodBinding } from '../../models/provider-method-binding.js';

import { FtpClient } from '../../api/ftp/ftp-client.js';
import { FtpConnectionService } from '../../connections/ftp/ftp-connection-service.js';
import { FtpProvider } from './ftp-provider.js';

export class FtpServiceProvider extends ServiceProvider {
  register(container) {
    container.singleton(TOKENS.FTP_CLIENT, (c) => {
      return new FtpClient({ egressPolicy: c.resolve(TOKENS.EGRESS_POLICY) });
    });

    container.singleton(TOKENS.FTP_CONNECTION_SERVICE, (c) => {
      return new FtpConnectionService({
        client: c.resolve(TOKENS.FTP_CLIENT)
      });
    });

    container.singleton(TOKENS.FTP_PROVIDER, (c) => {
      return new FtpProvider({
        connectionService: c.resolve(TOKENS.FTP_CONNECTION_SERVICE)
      });
    });

    const registry = container.resolve(TOKENS.PROVIDER_REGISTRY);

    registry.register(
      new ProviderDefinition({
        name: 'ftp',
        provider: container.resolve(TOKENS.FTP_PROVIDER),
        apiClient: container.resolve(TOKENS.FTP_CLIENT),
        displayName: 'FTP Credentials',
        description: 'FTP username/password provider for file transfer credentials',
        capabilities: new ProviderCapabilities([
          ProviderCapability.VALIDATION,
          ProviderCapability.HEALTH_CHECK
        ]),
        credentialFields: connectionCredentialFields({ defaultPort: 21 }),
        credentialMethods: [new CredentialMethod({ key: 'username-password', displayName: 'Username and password', authenticationMethod: 'username-password', credentialFields: connectionCredentialFields({ defaultPort: 21 }), operationCapabilities: [ProviderCapability.VALIDATION, ProviderCapability.HEALTH_CHECK] })],
        providerMethodBindings: [new ProviderMethodBinding({ methodKey: 'username-password' })],
        metadata: {
          authType: 'username-password',
          protocol: 'ftp',
          defaultPort: 21,
          requiredSecrets: ['host', 'username', 'password'],
          optionalSecrets: ['port'],
          credentialType: 'connection'
        }
      })
    );
  }
}
