---
title: Release Guide
document_id: DOC-RELEASE-GUIDE
classification: PUBLIC
language: en
version: 1.3.0
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
  - docs/security-guide/adversarial-testing.md
change_history:
  - version: 1.3.0
    date: 2026-09-13
    change: Documents the stable Security Assurance Methodology reference and future release-record requirements without redefining canonical governance or release authority.
  - version: 1.2.1
    date: 2026-09-10
    change: Clarifies that Release Assurance applicability is owned by the canonical Agent Suite Lifecycle while this document remains a non-canonical public guide.
  - version: 1.2.0
    date: 2026-09-01
    change: Makes the Public Security Assurance Record a normative release deliverable and defines its candidate-bound contents and publication restrictions.
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

Release Assurance applicability and its required verification gates are owned
by the canonical Agent Suite Lifecycle runtime source.
Release decision authority remains with the owner defined by
`ownership.md`. This guide is a supporting/public projection (`canonical:
false`) and cannot create a release requirement or Full Deep Security Scan
trigger by itself.

## Public Security Assurance Record

Every security-bearing RC3, RC4, Stable 1.0 or later release that materially
changes security controls, identity, authorization, lifecycle, network
boundaries or assurance coverage MUST publish a public-safe Security Assurance
Record at `docs/security-guide/adversarial-testing.md`. The record is bound to
the exact released commit/tag and is produced through the governed private to
public projection; it is not edited manually in a public checkout.

The record reports the Hacker framework/version, registered/implemented/
executed/passed/deferred distinction, aggregate attack-family coverage,
Critical/High counts, required Deep Scan aggregate result, public test result
where applicable, known limitations and the public registry/runner reference.
Unimplemented or deferred attacks are never presented as passing.

The record must not disclose private scan IDs or manifests, Gov3 evidence,
Owner authorizations, private paths, secrets, private findings or unnecessary
exploit detail. Release readiness remains blocked by unresolved Critical/High
findings or a failed required release-gate Hacker Test.

## Future Security Assurance Records

Future Security Assurance Records for security-bearing release candidates and
releases should use the stable [Security Assurance Methodology](../security-guide/index.md)
defined in the Security Guide. A release-specific record contains, where
applicable:

- the exact release or candidate binding;
- the current Security Closure result;
- release-specific aggregate assurance results;
- a reference to the risk and assessment methodology;
- known limitations; and
- the explicit certification and compliance boundary.

This Release Guide projects the existing canonical Security Governance
standards basis. It does not independently redefine risk methodology,
Security Governance authority, Full Deep Security Scan triggers or release
authority, and its `canonical: false` status remains unchanged.
