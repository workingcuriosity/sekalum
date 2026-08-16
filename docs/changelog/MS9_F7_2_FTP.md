# MS9 F7.2 FTP Provider

## Added

- Added `FtpProvider` for username/password FTP credentials.
- Added `FtpConnectionService` for validation and health checks.
- Added `FtpClient` with injectable transport adapter for tests and future runtime adapters.
- Added `FtpServiceProvider` registration.
- Added CLI provider-list integration coverage.
- Added component and unit tests for FTP provider, connection service and client.

## Architecture

- FTP is implemented as a non-OAuth connection provider.
- Supported capabilities are `validation` and `health-check`.
- Credential storage continues through the encrypted CredentialStore path.
