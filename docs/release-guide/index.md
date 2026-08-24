---
title: Release Guide
document_id: DOC-RELEASE-GUIDE
classification: PUBLIC
language: en
version: 1.1.2
status: Active
category: Release Guide
canonical: false
owner: Sekalum
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Project owners
  - Developers
  - Operators
dependent_documents:
  - docs/changelog/README.md
  - docs/operations-guide/index.md
  - docs/security-guide/index.md
change_history:
  - version: 1.1.2
    date: 2026-08-24
    change: Records explicit English as the current governed documentation language.
  - version: 1.1.1
    date: 2026-08-24
    change: Completes the canonical header metadata for the current documentation source.
  - version: 1.1.0
    date: 2026-08-24
    change: Removes historical private project links and keeps the English public release and operations sources.
  - version: 1.0.0
    date: 2026-07-12
    change: CP-011 promotes the Release Guide entry point from Draft to active navigation for release and operations sources.
---

# Release Guide

## Purpose

This guide is the active entry point for release context and release evidence.
It points to the leading sources instead of repeating historical milestone
states or an unverified release flow.

## Release sources

| Topic | Leading source |
|---|---|
| Current and future release notes | Changelog |
| Project behavior | [Handbook](../index.md) |
| Architecture overview | [Architecture](../Architecture.md) |
| Operations | [Operations Guide](../operations-guide/index.md) |
| Security boundaries and messages | [Security Guide](../security-guide/index.md) |
| Testing and security | [Security Guide](../security-guide/index.md) |
| Credential connection-test capability and limitation | MS15 Credential Connection Tests |

Historical changelog and milestone documents remain evidence of completed work.
New release notes are maintained exclusively in the canonical `docs/changelog/`
namespace.

## Boundary

This guide defines no release automation, version-number rules or
deployment-specific steps. Such decisions require a verified source and,
where appropriate, an ADR.
