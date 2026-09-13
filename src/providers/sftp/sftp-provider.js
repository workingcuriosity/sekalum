import { Provider } from '../provider.js';
import { ProviderResult } from '../../models/provider-result.js';

export class SftpProvider extends Provider {
  constructor({ connectionService }) {
    super();

    if (!connectionService) {
      throw new Error('SftpProvider requires connectionService');
    }

    this.connectionService = connectionService;
  }

  async validateCredential(credential, context = {}) {
    try {
      const validation = await this.connectionService.validateCredential(credential, context);
      return ProviderResult.success(validation);
    } catch (error) {
      return ProviderResult.failure(error);
    }
  }

  async healthCheck(credential, context = {}) {
    try {
      const health = await this.connectionService.healthCheck(credential, context);

      if (!health.healthy) {
        const error = new Error(health.message ?? 'SFTP health check failed');
        if (health.code) error.code = health.code;
        return ProviderResult.failure(error);
      }

      return ProviderResult.success(health);
    } catch (error) {
      return ProviderResult.failure(error);
    }
  }
}
