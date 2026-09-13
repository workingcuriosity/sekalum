import { safeErrorMessage } from '../../utils/safe-diagnostics.js';

export class SftpConnectionService {
  constructor({ client }) {
    if (!client) {
      throw new Error('SftpConnectionService requires client');
    }

    this.client = client;
  }

  async validateCredential(credential, { purpose = 'PROVIDER_VALIDATION', pathId = 'SFTP-STORED' } = {}) {
    const connectionOptions = this.#connectionOptionsFromCredential(credential);
    const result = await this.client.testConnection({ ...connectionOptions, purpose, pathId });

    return {
      valid: true,
      protocol: 'sftp',
      host: result.host ?? connectionOptions.host,
      port: result.port ?? connectionOptions.port,
      checkedAt: new Date().toISOString()
    };
  }

  async healthCheck(credential, context = {}) {
    try {
      const validation = await this.validateCredential(credential, {
        ...context,
        purpose: 'PROVIDER_HEALTH_CHECK',
        pathId: 'SFTP-STORED'
      });

      return {
        healthy: true,
        status: 'up',
        protocol: 'sftp',
        host: validation.host,
        port: validation.port,
        checkedAt: validation.checkedAt,
        message: 'SFTP connection validated successfully'
      };
    } catch (error) {
      return {
        healthy: false,
        status: 'down',
        protocol: 'sftp',
        checkedAt: new Date().toISOString(),
        message: safeErrorMessage(error, 'SFTP health check failed'),
        code: error?.code ?? null
      };
    }
  }

  #connectionOptionsFromCredential(credential) {
    if (!credential) {
      throw new Error('SFTP credential is required');
    }

    const secretMap = this.#secretMap(credential);
    const metadata = credential.metadata?.toJSON?.() ?? credential.metadata ?? {};
    const custom = metadata.custom ?? {};

    const host = secretMap.host ?? custom.host;
    const port = Number(secretMap.port ?? custom.port ?? 22);
    const username = secretMap.username ?? custom.username;
    const password = secretMap.password;
    const timeoutMs = custom.timeoutMs ? Number(custom.timeoutMs) : undefined;
    const verificationHost = custom.connectionVerificationHost ?? host;

    if (!host) throw new Error('SFTP credential requires host');
    if (!Number.isInteger(port) || port <= 0) {
      throw new Error('SFTP credential requires a valid port');
    }
    if (!username) throw new Error('SFTP credential requires username');
    if (!password) throw new Error('SFTP credential requires password');

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
