---
title: MS15 Credential Connection Tests
version: 1.0.0
status: Active
category: Release Notes
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 Working Curiosity"
target_audience:
  - Administrators
  - Developers
  - Operators
dependent_documents:
  - docs/api-reference/index.md
  - docs/security-guide/index.md
  - docs/user-guide/index.md
  - docs/providers/README.md
change_history:
  - version: 1.0.0
    date: 2026-07-13
    change: Records the Release-1.0 Credential connection-test capability, security boundary, and known transport limitation.
---

# MS15 Credential Connection Tests

## Added

- An authorized, non-persistent draft connection-test endpoint for providers with the `validation` capability.
- Capability-gated connection-test actions in the Credential Wizard and Credential Management.
- Stable public connection-test errors with English and German user-facing messages.
- Backend-only provider connections, network-target filtering for FTP and SFTP, bounded client timeouts, and session cleanup.
- Responsive Wizard and Credential Management verification for root and `BASE_PATH` paths.

## Security boundary

Draft secrets are used only by the request-scoped backend test. They are not persisted, versioned, rendered in the UI, returned by the API, or included in public errors. Saved Credential validation continues to use the existing lifecycle endpoint and can activate a Credential only after a successful provider result.

## Known limitation

The Release-1.0 standard image includes the active OpenAI HTTP validation path. FTP and SFTP expose the secure framework contract but do not include a production transport adapter in the standard image. The UI may therefore present a safe provider-unavailable outcome for those providers; this release does not claim live FTP/SFTP validation, file transfer, TLS verification, or SSH host-key verification.

## Validation

The package is covered by provider, manager, API, Admin UI, base-path, and browser-responsive checks. Deployment evidence is maintained through the repository's public validation scripts and release records.
