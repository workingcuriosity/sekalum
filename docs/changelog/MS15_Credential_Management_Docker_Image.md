---
title: MS15 Credential Management and Versioned Docker Image
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
  - Betreiber
dependent_documents:
  - docs/user-guide/index.md
  - docs/api-reference/index.md
  - docs/installation-guide/index.md
  - docs/operations-guide/index.md
change_history:
  - version: 1.0.0
    date: 2026-07-13
    change: Records the secure Credential-management UI and the explicit Docker image version contract.
---

# MS15 Credential Management and Versioned Docker Image

## Added

- A BASE_PATH-safe Admin page for listing, editing, and deleting Credentials.
- Provider-contract-driven editable fields and deliberate, secret-safe replacement inputs.
- A delete confirmation that identifies the Credential and provider, avoids a destructive default focus, and waits for a confirmed API response.
- English and German UI strings, keyboard-close behavior, and visible focus styles.
- An explicit `credential-hub:0.1.0` Compose image and OCI image-version label.

## Security boundary

Credential IDs, provider keys, lifecycle fields, and system-managed metadata cannot be changed through the public update route. Secret values are never returned to, displayed in, or retained by the browser. Empty secret inputs leave stored encrypted values unchanged.

## Deferred

Activation and deactivation lifecycle controls remain a proposed post-Release-1.0 architecture item. They are not part of this UI package.
