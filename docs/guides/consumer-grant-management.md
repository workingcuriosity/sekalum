---
title: Consumer Grant Management
document_id: DOC-CONSUMER-GRANT-MANAGEMENT
classification: PUBLIC
language: en
version: 1.1.1
category: Guide
status: Active
owner: Sekalum
canonical: false
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Administrators
  - Integrators
change_history:
  - version: 1.1.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.1.0
    date: 2026-08-24
    change: Migrates the Consumer Grant guide to English and aligns its terminology with the current Consumer API boundary.
---

# Consumer Grant Management

Consumer Grants define which Credential fields a Consumer may resolve. An
administrator creates the grant; the Consumer receives no management
metadata and cannot expand its own grant.

## Safe workflow

1. Create or identify the Consumer API token.
2. Select the Credential and the exact secret fields the integration needs.
3. Save the grant through the management API or Admin UI.
4. Use Consumer Discovery to select the opaque `credentialKey`.
5. Use Consumer Resolve with the granted field names only.

Revoked Credentials, revoked tokens and missing grants fail closed. The
Consumer API never returns unrequested secret fields or raw provider errors.
The internal management `credentialId` and the public Consumer `credentialKey`
are different identifiers and must not be substituted.
