---
title: Instagram Provider
document_id: DOC-PROVIDER-INSTAGRAM
classification: PUBLIC
language: en
version: 1.2.0
category: Provider
status: Active
owner: Sekalum
canonical: false
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience: [Users, Integrators]
change_history:
  - version: 1.2.0
    date: 2026-08-27
    change: Documents the Instagram token transport exception and secret-safe HTTP diagnostics.
  - version: 1.1.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.1.0
    date: 2026-08-24
    change: Migrates the Instagram provider page to English.
---

# Instagram Provider

Instagram is an OAuth2 provider in the supported Meta provider family. OAuth
configuration, scopes and capabilities are resolved from provider metadata;
secret material is never included in public documentation.

## OAuth and HTTP transport

The authorization-code exchange uses a form-encoded `POST` body containing the
required client credentials and code. The profile lookup uses a Bearer header
for the access token and keeps its `fields` query non-sensitive.

Instagram requires the long-lived-token refresh endpoint to receive its access
token in the documented `GET` query parameter. This is a narrow
`QUERY_EXCEPTION`: the value is transiently present only in the network
request. It is never retained in `HttpError`, logs, diagnostics, telemetry or
persisted data.

`HttpError` preserves only a redacted request target. Sensitive query keys,
including `access_token`, `refresh_token`, `client_secret`, `token`, `api_key`,
`password` and `code`, are replaced with `[REDACTED]`; non-sensitive path and
query context may remain available for diagnosis.
