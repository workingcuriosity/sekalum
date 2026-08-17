---
title: Sekalum Project Identity
version: 1.3.0
status: Active
category: Project
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Users
  - Contributors
  - Auditors
dependent_documents:
  - LICENSE
  - NOTICE
  - DISCLAIMER.md
  - docs/project/LEGAL.md
change_history:
  - version: 1.3.0
    date: 2026-08-17
    change: Removes obsolete legal attribution and retains Working Curiosity solely as the project and maintainer identity under AGPL-3.0-only.
  - version: 1.1.0
    date: 2026-08-16
    change: Establishes Sekalum as the current product and root package identity while preserving legacy runtime, persistence and API identifiers for compatibility.
  - version: 1.2.0
    date: 2026-08-16
    change: Aligns the active maintainer identity with Working Curiosity and records the current private/public repository and redirect structure.
  - version: 1.0.0
    date: 2026-07-16
    change: Adds required canonical metadata.
---

# Sekalum – Project Identity

## Project
Sekalum

## Maintainer
Working Curiosity

## Contact
luiscyphre404@gmail.com

## Repository
https://github.com/workingcuriosity/sekalum

## License
GNU Affero General Public License v3.0 only (AGPL-3.0-only)

This document is the canonical source for project identity information.

Project metadata identifies Working Curiosity as the maintainer. It does not
assign legal ownership through project metadata.

## Repository structure

| Area | Public canonical source |
|---|---|
| Sekalum Core | `workingcuriosity/sekalum` |
| Sekalum n8n | `workingcuriosity/sekalum-n8n` |
| Credential HUB history | `luiscyphre404-cmd/credential-hub-becomes-sekalum` |

## Technical identity compatibility

The current product and root package identity is `Sekalum` / `sekalum`. The
following identifiers remain legacy-compatible and are not renamed by this
migration: the `/credential-hub` base-path form, `x-credential-hub-user`
test-only header, `CREDENTIAL_HUB_*` variables used by historical evidence,
credential transfer and encrypted-storage format identifiers, OAuth result
event types, and existing persistence keys. These identifiers are external,
persisted or historical contracts; changing them requires a separately
approved migration and compatibility plan.
