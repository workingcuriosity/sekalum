---
title: Threads Provider
document_id: DOC-PROVIDER-THREADS
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
    change: Documents the explicit Threads token transport exceptions and secret-safe HTTP diagnostics.
  - version: 1.1.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.1.0
    date: 2026-08-24
    change: Migrates the Threads provider page to English.
---

# Threads Provider

Threads is an OAuth2 provider in the supported Meta family. It exposes only
the public provider-operation capabilities declared in its metadata.

## OAuth and HTTP transport

The authorization URL contains only authorization inputs such as the client
identifier, redirect URI, scopes and state. Provider secrets and access tokens
must not be placed in that URL.

The authorization-code exchange uses a form-encoded `POST` body. Meta requires
the long-lived-token exchange, long-lived-token refresh and authenticated
profile lookup to use their documented `GET` query parameters. These are
narrow `QUERY_EXCEPTION`s: the required values exist only in the transient
network request and are never retained in `HttpError`, logs, diagnostics,
telemetry or persisted data.

`HttpError` preserves only a redacted request target. Sensitive query keys,
including `access_token`, `refresh_token`, `client_secret`, `token`, `api_key`,
`password` and `code`, are replaced with `[REDACTED]`; non-sensitive path and
query context may remain available for diagnosis.
