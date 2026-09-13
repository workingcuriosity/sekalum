---
title: Consumer Grant Management
document_id: DOC-CONSUMER-GRANT-MANAGEMENT
classification: PUBLIC
language: en
version: 1.2.0
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
  - version: 1.2.0
    date: 2026-09-05
    change: Adds dedicated-Consumer identity, smallest-practical boundary, named-field minimization, rotation and revocation safe-use guidance.
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

1. Create or identify a dedicated Consumer API token; do not use a Management Token for runtime access.
2. Scope the Consumer to the smallest practical application or workload boundary.
3. Select the Credential and only the exact named Secret fields the integration needs.
4. Review the Credential, provider and field list, then save the grant through the management API or Admin UI.
5. Use Consumer Discovery to select the opaque logical `credentialKey`.
6. Use Consumer Resolve with the granted field names only and pass the result to the immediate target where practical.

Revoked Credentials, revoked tokens and missing grants fail closed. The
Consumer API never returns unrequested secret fields or raw provider errors.
The internal management `credentialId` and the public Consumer `credentialKey`
are different identifiers and must not be substituted. The logical key is not
Secret Version or Secret material. Rotation can preserve the key while
replacing material; revocation or Grant removal blocks future Resolve and does
not permit cached plaintext fallback. Do not copy, persist, log, export or pin
resolved values in workflow state, URLs, source control, retries, exports,
screenshots or recordings.
