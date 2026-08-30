# Changelog

This file contains only changes that are appropriate for the public Sekalum repository. Internal governance, audit evidence, security-scan identifiers, private work-package history, and development-only control-plane changes are intentionally excluded.

## [1.0.0-rc.2] — 2026-08-30

### Added

- Consumer Discovery filtering by display name and tags.
- Consumer profile templates for common automation runtimes, while keeping the existing Consumer Grant security model unchanged.
- Public Consumer integration examples for curl, Node.js, Python, PowerShell, and n8n.
- Bounded Consumer Batch Resolve support for resolving multiple independently authorized credentials in one request.
- Explicit provider-profile/version handling across credential and OAuth lifecycles.
- Canonical OAuth expiry normalization and safer handling of rotated or missing refresh-token state.
- Derived short-lived runtime credential support where provider contracts derive temporary access material from a durable identity.
- Credential usage and health observability using secret-free runtime/audit information.

### Changed

- Credential, API-token, user, grant, provider-configuration, import/export, and OAuth lifecycle operations now use stronger concurrency and terminal-state protections.
- Credential identity is kept consistent across persistence, management, migration/restore, and Consumer Resolve paths.
- Secret materialization is limited to authorized operations that actually require plaintext secret values.
- Provider HTTP/OAuth diagnostics are normalized and redacted before they can reach logs, audit records, persisted diagnostics, or user-visible errors.
- Production startup now validates storage and encryption-key readiness before serving requests.
- First-administrator bootstrap is protected by an explicit bootstrap trust boundary and terminates after successful provisioning.
- Public-origin and reverse-proxy handling for OAuth callbacks is validated more strictly.
- Credential transfer/import is bounded and atomic, with stronger cryptographic and concurrency admission checks.
- Audit persistence uses deterministic retention/cap rules and fails closed where required for security-relevant operations.
- Public documentation, provider documentation, installation guidance, security guidance, and Consumer integration guidance were consolidated and updated.

### Security

- Strengthened isolation between Consumer identities, grants, credential generations, secret versions, and resolved fields.
- Strengthened revocation/deletion terminality so stale concurrent operations cannot silently restore or reuse invalid authorization state.
- Strengthened secret-safe projection, export, logging, exception, and diagnostic boundaries.
- Strengthened custom-provider metadata and endpoint handling while keeping custom providers declarative and non-executable.
- Strengthened backup/restore, import, CSV, and persisted-state boundaries against unsafe path, formula, lifecycle, and partial-state behavior.

### Compatibility

- The existing Consumer API, Management API, Consumer Grant model, and stable logical Credential identity remain the public integration model.
- n8n remains a normal Consumer integration using the same public Consumer API boundary as other runtimes.
- This release is published as `1.0.0-rc.2`.

## R2 – Public Beta & Release Hardening

### Added

- Public-Beta onboarding in the repository README, including Docker start, environment guidance, Admin UI and Dashboard URLs, first credential creation, troubleshooting, and documentation links.
- A self-contained Compose installation path based on `.env.example` and `docker compose up --build`.

### Changed

- The Installation Guide identifies the Public Beta release as `1.0.0-beta.1` and documents the self-contained Compose contract.

## MS15 F9.1C - Configurable Base Path and Reverse Proxy

### Added

- Configurable `BASE_PATH` for root and subpath deployments.
- Prefix-aware Admin UI, health, REST API, OAuth callbacks, and credential metadata.
- Reverse-proxy guidance with neutral examples.
- Unit and integration coverage for `/` and `/credential-hub/` deployments.

### Compatibility

- `BASE_PATH` defaults to `/`; existing root deployments need no configuration change.
- A reverse proxy must preserve the configured base path.

## MS15 F9.1B – CSV Credential Import

### Added

- CSV migration import in `CredentialTransferService`.
- CSV parser without an additional package dependency.
- Required-field validation for `providerKey`, `externalReference`, and at least one secret column.
- Dynamic secret columns through `secret.<name>`.
- Convenience secret columns such as `username`, `password`, `apiKey`, `token`, `accessToken`, `refreshToken`, `clientId`, and `clientSecret`.
- CSV preview through the existing import-preview and conflict logic.
- CSV import through the existing `skip`, `overwrite`, and `rename` conflict strategies.
- REST support for `sourceFormat: "csv"` in import preview and import.
- Admin UI selection between a Sekalum export file and CSV migration import.
