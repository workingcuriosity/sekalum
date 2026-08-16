# MS9 F7.1 – SFTP Provider

## Added

- Added `SftpProvider` for non-OAuth SFTP credentials.
- Added `SftpServiceProvider` registration.
- Added `SftpConnectionService` for validation and health-check orchestration.
- Added `SftpClient` transport boundary.
- Added provider metadata for username/password SFTP credentials.
- Added unit tests for SFTP client, connection service, and provider.
- Added component test for provider registration and capabilities.
- Added CLI provider-list integration assertion.
- Added SFTP provider documentation.

## Architecture

This package validates that Credential Hub is credential-centered and not OAuth-centered. SFTP uses the same ProviderManager, CredentialManager, ProviderRegistry, CredentialStore, REST, and CLI infrastructure without OAuth services.

## Test result

Local test run:

```text
tests 196
pass 196
fail 0
```
