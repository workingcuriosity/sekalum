import { EgressError, EgressPolicy, EGRESS_PURPOSES } from '../../services/egress-policy.js';

export class FtpClient {
  constructor({ connector = null, timeoutMs = 10000, egressPolicy = new EgressPolicy() } = {}) {
    this.connector = connector;
    this.timeoutMs = timeoutMs;
    this.egressPolicy = egressPolicy;
  }

  async testConnection(connectionOptions = {}) {
    this.#validateConnectionOptions(connectionOptions);

    if (!this.connector) {
      throw new Error('FTP transport adapter is not configured');
    }

    let session = null;

    try {
      const route = await this.egressPolicy.admit(connectionOptions.host, {
        pathId: connectionOptions.pathId ?? 'FTP-STORED',
        purpose: connectionOptions.purpose ?? EGRESS_PURPOSES.CREDENTIAL_CONNECTION_TEST,
        protocol: 'ftp',
        port: connectionOptions.port,
        providerKey: 'ftp'
      });
      // Connect to the policy-pinned address while preserving the original host
      // for TLS-capable connector implementations.
      const connectorOptions = {
        ...connectionOptions,
        host: route.connectAddress,
        verificationHost: connectionOptions.verificationHost ?? route.verificationHost,
        servername: connectionOptions.verificationHost ?? route.verificationHost
      };
      session = await this.#withTimeout(
        this.connector.connect(connectorOptions),
        connectionOptions.timeoutMs ?? this.timeoutMs
      );

      if (session?.disconnect) {
        await session.disconnect();
      }

      return {
        connected: true,
        host: connectionOptions.verificationHost ?? route.verificationHost,
        port: route.port
      };
    } catch (error) {
      if (session?.disconnect) {
        try {
          await session.disconnect();
        } catch {
          // Ignore disconnect errors while reporting the original connection failure.
        }
      }

      throw error;
    }
  }

  #validateConnectionOptions({ host, port, username, password }) {
    if (!host) throw new Error('FTP host is required');
    if (!port) throw new Error('FTP port is required');
    if (!username) throw new Error('FTP username is required');
    if (!password) throw new Error('FTP password is required');
  }

  async #withTimeout(promise, timeoutMs) {
    let timeoutHandle;

    const timeout = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        reject(new EgressError('EGRESS_TIMEOUT', null, { statusCode: 504 }));
      }, timeoutMs);
    });

    try {
      return await Promise.race([promise, timeout]);
    } finally {
      clearTimeout(timeoutHandle);
    }
  }
}
