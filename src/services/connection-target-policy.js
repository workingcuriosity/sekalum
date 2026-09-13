import { EgressPolicy } from './egress-policy.js';

// Compatibility facade for callers that still consume the historical target
// shape. All resolution and classification is owned by EgressPolicy.
export class ConnectionTargetPolicy {
  constructor({ lookup, allowPrivateNetworks = false, privateException = null } = {}) {
    this.policy = new EgressPolicy({ lookup, allowPrivateNetworks, privateException });
  }

  async resolveAllowedTarget(host) {
    try {
      const route = await this.policy.admit(host, {
        pathId: 'LEGACY-CONNECTION-TARGET',
        purpose: 'CREDENTIAL_CONNECTION_TEST',
        protocol: 'ftp',
        port: 21
      });
      return Object.freeze({ host: route.verificationHost, address: route.connectAddress });
    } catch (error) {
      if (error?.code === 'EGRESS_DNS_FAILED') {
        const dnsError = new Error('Connection target could not be resolved');
        dnsError.code = 'CREDENTIAL_CONNECTION_DNS_FAILED';
        dnsError.statusCode = 422;
        dnsError.messageKey = 'credential.connectionTest.dnsFailed';
        dnsError.details = { field: 'host' };
        throw dnsError;
      }
      const blockedError = new Error('Connection target is not allowed');
      blockedError.code = 'CREDENTIAL_CONNECTION_TARGET_BLOCKED';
      blockedError.statusCode = 400;
      blockedError.messageKey = 'credential.connectionTest.targetBlocked';
      throw blockedError;
    }
  }
}
