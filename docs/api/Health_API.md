---
title: Health API
document_id: DOC-API-HEALTH-API
classification: PUBLIC
language: en
version: 1.0.2
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
# Health API

`GET /health` is implemented and returns `200` with:

```json
{ "status": "UP" }
```

The canonical route reference is API Reference.
