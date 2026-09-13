---
title: OAuth API
document_id: DOC-API-OAUTH-API
classification: PUBLIC
language: en
version: 1.1.0
category: API
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
  - version: 1.1.0
    date: 2026-09-04
    change: Adds the RC3-08 Context Binding pointer and records exact transaction, client, provider/profile, redirect, scope and Credential checks as a future architecture boundary; no route implementation is authorized.
  - version: 1.0.2
    date: 2026-08-24
    change: Records explicit English as the current governed documentation language.
  - version: 1.0.1
    date: 2026-08-24
    change: Completes the canonical header metadata for the current documentation source.
  - version: 1.0.0
    date: 2026-08-24
    change: Adds the current governed documentation header and records the existing source as the canonical content baseline.
---
# OAuth API Notes

The canonical, code-verified OAuth route reference is API Reference.

OAuth login and callback routes are public HTTP routes. The authorized Wizard start route creates a one-time state bound to the initiating actor and returns a state-specific HttpOnly/SameSite browser binding cookie. The callback requires that binding cookie and the expected provider context before consuming state; actor values supplied by the callback request are ignored. Missing, mismatched, replayed, or expired state is rejected. Provider-specific fields, redirect configuration, and capabilities are documented in their respective follow-up packages.

The architecture owner is ADR-031 – OAuth Context Binding.
It separates state admission, provider evidence admission and Credential commit
authorization. Browser input cannot override a server-side context mismatch;
safe result codes do not expose provider messages, configuration values or
account-existence information.
