---
title: MS16 Provider API and Custom Provider Onboarding
version: 1.0.0
status: Active
category: Release Notes
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 Working Curiosity"
target_audience:
  - Administratoren
  - Entwickler
  - Integratoren
dependent_documents:
  - docs/api-reference/index.md
  - docs/configuration-reference/index.md
  - docs/user-guide/index.md
change_history:
  - version: 1.0.0
    date: 2026-07-17
    change: Records provider-method API completion and declarative custom-provider onboarding.
---

# MS16 Provider API and Custom Provider Onboarding

## Added

- Provider list and detail responses now always publish public `credentialMethods` and `providerMethodBindings` arrays.
- Administrators can create a declarative custom provider through the Admin UI or `POST /api/v1/providers`.
- Created definitions persist in application storage, hydrate at startup, and become selectable in the Credential Wizard immediately.

## Security and architecture boundary

Custom-provider onboarding accepts metadata, credential methods, credential fields, and method bindings only. OAuth configuration, provider-configuration fields, runtime operations, executable code, hooks, scripts, Provider/API-client objects, and provider-definition secret values are rejected. Field-level secret metadata remains permitted because it describes a later Credential value and never serializes that value.

## Compatibility

The existing `CUSTOM_PROVIDER_DEFINITIONS` startup configuration remains supported. UI-created providers do not require changes to environment or project files. Integrated and custom providers share the public Provider API contract; internal runtime objects remain private.
