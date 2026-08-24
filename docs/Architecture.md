---
title: Architecture Overview
document_id: DOC-ARCHITECTURE-OVERVIEW
classification: PUBLIC
language: en
version: 1.1.1
category: Architecture
status: Active
owner: Sekalum
canonical: false
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Users
  - Developers
  - Operators
change_history:
  - version: 1.1.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.1.0
    date: 2026-08-24
    change: Replaces the obsolete German architecture note with an English public overview of the current runtime boundaries.
---

# Architecture Overview

Sekalum is a credential lifecycle platform with a generic Credential model,
provider integrations, a management API and a separate Consumer API.

## Runtime boundaries

```text
Admin UI / CLI / OAuth callbacks
            |
        Application
            |
  Credential and Provider services
            |
 Provider clients and encrypted storage
```

The application owns lifecycle, authorization, audit and safe error handling.
Providers own provider-specific API and OAuth behavior. Storage owns encrypted
persistence and key continuity. Consumer integrations receive only explicitly
authorized public metadata and secret fields.

For installation and operation, see the [Installation Guide](installation-guide/index.md),
[Operations Guide](operations-guide/index.md), and [Developer Guide](developer-guide/index.md).
