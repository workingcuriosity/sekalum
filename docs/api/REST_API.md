---
title: REST API Notes
document_id: DOC-REST-API-NOTES
classification: PUBLIC
language: en
version: 1.1.1
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
  - version: 1.1.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.1.0
    date: 2026-08-24
    change: Replaces the obsolete German topic note with an English public route summary.
---

# REST API Notes

The public HTTP surface includes the health endpoint, OAuth callback routes,
management routes and the explicitly authorized Consumer API.

```text
GET  /health
GET  /oauth/:provider/login
GET  /oauth/:provider/callback
GET  /api/v1/consumer/credentials
POST /api/v1/consumer/credentials/:credentialKey/resolve
```

Management routes require the configured Bearer authentication and permission
boundary. Consumer Resolve requires an active API token, the Consumer scope
and an explicit grant. Responses never expose unrequested secret fields or
raw provider errors.

See the [Health API](Health_API.md), [OAuth API notes](OAuth_API.md), and the
[Consumer integration guide](../guides/wizard-consumer-verification.md).
