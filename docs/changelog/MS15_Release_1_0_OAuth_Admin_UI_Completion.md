---
title: Release 1.0 OAuth and Admin UI Completion
version: 1.2.0
status: Active
category: Release Notes
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Users
  - Administrators
  - Developers
dependent_documents:
  - docs/history/milestones/MS15/F9_1D_OAuth_Admin_UI_Completion.md
  - docs/user-guide/index.md
change_history:
  - version: 1.2.0
    date: 2026-07-13
    change: Adds registration compensation and serialized generic Credential collection mutations.
  - version: 1.1.0
    date: 2026-07-13
    change: Records completion of the non-OAuth credential creation, encrypted persistence, and Wizard outcome chain.
  - version: 1.0.0
    date: 2026-07-12
    change: Records the completed OAuth provider-configuration and Admin UI chain.
---

# Release 1.0 OAuth and Admin UI Completion

Credential HUB now collects OAuth application configuration through provider metadata in the Credential Wizard, validates it before authorization, and stores it encrypted for callback and refresh use. Existing provider-specific environment variables remain available as a compatibility fallback.

Failed and cancelled OAuth attempts remove their temporary encrypted provider configuration, including callback, token-exchange, and credential-import failures. Successful credentials retain the internal configuration reference required for refresh.

The Admin UI now provides shared BASE_PATH-aware navigation, provider cards, complete English/German labels, a unified Dashboard model, and public support/legal links. Threads is classified consistently as OAuth. OAuth cancellation and failure return safe, stable outcomes with a retry path; raw provider errors and secrets are not displayed.

The public API adds an authorized OAuth-start route and exposes only field definitions, never provider application values. The implementation is covered across model, storage, provider, OAuth, API, Admin UI, and security boundaries.

The Release 1.0 creation path now validates registered provider field contracts before storing API-key and connection credentials. OpenAI, FTP, and SFTP credentials use generic encrypted Credential persistence while existing OAuth token files remain available through the legacy compatibility adapter. Creation responses never return secret values, and stable error codes cover missing or invalid fields, unknown providers, encryption, persistence, and unexpected creation failures. The Wizard presents dedicated success and recoverable failure states, including direct Dashboard navigation.

Initial Secret-Version failures now trigger registration compensation so failed creations do not remain visible. Generic Credential collection mutations are serialized within the supported single Release-1.0 application process; multi-process writers remain outside the Release 1.0 deployment contract.
