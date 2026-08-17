---
title: Release Guide
version: 1.0.0
status: Active
category: Release Guide
canonical: false
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Projektverantwortliche
  - Entwickler
  - Betreiber
dependent_documents:
  - docs/changelog/README.md
  - docs/operations-guide/index.md
  - docs/security-guide/index.md
change_history:
  - version: 1.0.0
    date: 2026-07-12
    change: CP-011 promotes the Release Guide entry point from Draft to active navigation for release and operations sources.
---

# Release Guide

## Zweck

This guide is the active entry point for release context and release evidence.
It points to the leading sources instead of repeating historical milestone
states or an unverified release flow.

## Release-Quellen

| Thema | Fuehrende Quelle |
|---|---|
| Current and future release notes | [Changelog](../changelog/README.md) |
| Projektfortschritt | Projektstatus |
| Geplante Arbeit | Roadmap |
| Architekturentscheidungen | ADR Index |
| Betriebspruefungen | [Operations Guide](../operations-guide/index.md) |
| Security boundaries and messages | [Security Guide](../security-guide/index.md) |
| Testvorgehen | Testing Strategy |
| Credential connection-test capability and limitation | [MS15 Credential Connection Tests](../changelog/MS15_Credential_Connection_Tests.md) |

Historical changelog and milestone documents remain evidence of completed work.
New release notes are maintained exclusively in the canonical `docs/changelog/`
namespace.

## Abgrenzung

This guide defines no release automation, version-number rules or
deployment-specific steps. Such decisions require a verified source and,
where appropriate, an ADR.
