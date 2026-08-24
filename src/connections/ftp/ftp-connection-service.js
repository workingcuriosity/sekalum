import { safeErrorMessage } from '../../utils/safe-diagnostics.js';

export class FtpConnectionService {
  constructor({ client }) {
    if (!client) {
      throw new Error('FtpConnectionService requires client');
    }

    this.client = client;
  }

  async validateCredential(credential) {
    const connectionOptions = this.#connectionOptionsFromCredential(credential);
    const result = await this.client.testConnection(connectionOptions);

    return {
      valid: true,
      protocol: 'ftp',
      host: result.host ?? connectionOptions.host,
      port: result.port ?? connectionOptions.port,
      checkedAt: new Date().toISOString()
    };
  }

  async healthCheck(credential) {
    try {
      const validation = await this.validateCredential(credential);

      return {
        healthy: true,
        status: 'up',
        protocol: 'ftp',
        host: validation.host,
        port: validation.port,
        checkedAt: validation.checkedAt,
        message: 'FTP connection validated successfully'
      };
    } catch (error) {
      return {
        healthy: false,
        status: 'down',
        protocol: 'ftp',
        checkedAt: new Date().toISOString(),
        message: safeErrorMessage(error, 'FTP health check failed')
      };
    }
  }

  #connectionOptionsFromCredential(credential) {
    if (!credential) {
      throw new Error('FTP credential is required');
    }

    const secretMap = this.#secretMap(credential);
    const metadata = credential.metadata?.toJSON?.() ?? credential.metadata ?? {};
    const custom = metadata.custom ?? {};

    const host = secretMap.host ?? custom.host;
    const port = Number(secretMap.port ?? custom.port ?? 21);
    const username = secretMap.username ?? custom.username;
    const password = secretMap.password;
    const timeoutMs = custom.timeoutMs ? Number(custom.timeoutMs) : undefined;
    const verificationHost = custom.connectionVerificationHost ?? host;

    if (!host) throw new Error('FTP credential requires host');
    if (!Number.isInteger(port) || port <= 0) {
      throw new Error('FTP credential requires a valid port');
    }
    if (!username) throw new Error('FTP credential requires username');
    if (!password) throw new Error('FTP credential requires password');

    return {
      host,
      port,
      username,
      password,
      timeoutMs,
      verificationHost
    };
  }

  #secretMap(credential) {
    const entries = credential.secrets ?? [];
    const map = {};

    for (const secret of entries) {
      map[secret.name] = secret.value;
    }

    return map;
  }
}
