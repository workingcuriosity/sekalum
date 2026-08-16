# MS15 F9.1B – Provider Metadata and Dynamic Credential Workflows

Date: 2026-07-12  
Status: implemented

## Changes

- Added validated and ordered credential-field metadata for all built-in providers.
- Extended the public Provider API with credential fields, authentication type, default scopes, and OAuth security metadata.
- Replaced the Wizard's fixed provider and field catalog with metadata-driven authentication and provider selection.
- Added safe CSV alias mapping and mapping reports to the shared credential transfer service.
- Added declarative custom provider definitions through `CUSTOM_PROVIDER_DEFINITIONS`; executable extensions and custom OAuth flows are rejected.
- Redirected OAuth success, cancellation, and failure outcomes back to explicit Wizard actions.
- Added direct navigation between the Dashboard and Credential Wizard.

## Compatibility and boundaries

- Existing built-in provider metadata remains backward-compatible.
- Custom providers declare no runtime operations and therefore cannot validate, refresh, revoke, or execute OAuth flows without a separately implemented provider integration.
- CSV mapping reports contain column mappings only and never include secret values.
