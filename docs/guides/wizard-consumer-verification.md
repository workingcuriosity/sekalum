---
title: Consumer Integration Verification
document_id: DOC-CONSUMER-INTEGRATION-VERIFICATION
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
  - Integrators
  - Developers
change_history:
  - version: 1.2.0
    date: 2026-09-05
    change: Adds bounded verification guidance for dedicated Consumer identity, minimum named fields, placeholder-only examples and the external-runtime responsibility boundary.
  - version: 1.1.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.1.0
    date: 2026-08-24
    change: Migrates the Consumer verification guide to English and preserves the distinction between Credential readiness and completed integration.
---

# Consumer Integration Verification

The Admin UI can verify a Consumer integration after a Credential has been
created and a grant has been configured. A Credential being ready does not by
itself mean that a Consumer Resolve request is authorized.

## Verification sequence

1. Confirm that the Credential is active and has the required provider data.
2. Confirm that the dedicated Consumer token is active and has the required scope; do not use a Management Token for runtime verification.
3. Confirm that the grant names the exact Credential and minimum required Secret fields.
4. Discover the Credential through the generic Consumer API and carry only its logical `credentialKey`.
5. Resolve only the explicitly granted fields and use them for the immediate target where practical.

The result is a safe success or failure outcome. Generated examples are
documentation-only, placeholder-only and are not automatically executed or
stored. Secret values are used only for the authorized runtime operation and
are never copied into workflow state, Set/Edit Fields, Code-node constants,
logs, execution output, retry payloads, URLs, source control, exports,
screenshots, recordings or audit evidence. `credentialKey` is not Secret
Version or Secret material; revocation blocks future Resolve but cannot erase
plaintext already delivered to an external runtime.
