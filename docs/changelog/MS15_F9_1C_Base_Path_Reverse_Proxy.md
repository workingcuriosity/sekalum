---
title: MS15 F9.1C Base Path and Reverse Proxy
version: 1.0.1
status: Active
category: Release
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 Working Curiosity"
target_audience:
  - Administratoren
  - Betreiber
  - Entwickler
dependent_documents:
  - docs/configuration-reference/index.md
  - docs/installation-guide/index.md
  - docs/operations-guide/index.md
change_history:
  - version: 1.0.1
    date: 2026-07-17
    change: Classifies this as historical release evidence and points to the current configuration, installation, operations, and API references.
  - version: 1.0.0
    date: 2026-07-12
    change: Records the configurable base-path and reverse-proxy support delivered by MS15 F9.1C.
---

# MS15 F9.1C - Base Path and Reverse Proxy

> Historical release evidence, not the current operating or configuration reference. The active contracts are the [Configuration Reference](../configuration-reference/index.md), [Installation Guide](../installation-guide/index.md), [Operations Guide](../operations-guide/index.md), and [API Reference](../api-reference/index.md). Later additions such as `PUBLIC_BASE_URL` are documented there and are not retroactively part of the original F9.1C delivery.

## Added

- Configurable `BASE_PATH` with `/` as the backward-compatible default.
- A single route mount for the Admin UI, health endpoint, REST API, and OAuth callbacks.
- Prefix-aware admin browser requests and OAuth redirects.
- Prefix-aware credential API metadata.
- Neutral Nginx, Caddy, Traefik, and Apache reverse-proxy guidance.

## Compatibility

Existing root deployments remain available without configuration changes. Deployments below a path prefix must register OAuth callback URIs with the same prefix and configure the reverse proxy to preserve it.

## Validation

- Unit tests cover base-path normalization, validation, and browser path derivation.
- Integration tests cover root redirects, prefixed Admin UI, health, credential metadata, and the absence of unprefixed health routes for a prefixed deployment.

The neutral reverse-proxy examples are configuration guidance. This historical release note does not assert product-specific proxy acceptance or a complete public OAuth end-to-end test.
