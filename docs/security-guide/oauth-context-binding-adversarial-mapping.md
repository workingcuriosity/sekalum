---
title: OAuth Context Binding Adversarial Mapping
document_id: DOC-SECURITY-OAUTH-CONTEXT-BINDING-ADVERSARIAL-MAPPING
version: 1.1.0
classification: PUBLIC
language: en
status: Accepted
category: Security
canonical: true
owner: Sekalum
approved_by: Project Owner / Repository Maintainer
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Developers
  - Security reviewers
  - Auditors
  - Operators
dependent_documents:
  - docs/adr/ADR-031-OAuth-Context-Binding.md
  - docs/architecture/OAUTH_CONTEXT_BINDING_PATH_MATRIX.md
  - docs/security-guide/index.md
  - docs/project/issue-execution/RC3-08_OAUTH_CONTEXT_BINDING_IMPLEMENTATION_WORK_PACKAGE.md
change_history:
  - version: 1.1.0
    date: 2026-09-04
    change: Records Owner Review PASS, reuses OAUTH-ATTACK-001 for proven provider-mismatch, expiry and one-time-replay coverage, and accepts only semantically distinct planned cases; no registry or execution change.
  - version: 1.0.0
    date: 2026-09-04
    change: Maps RC3-08 OAuth context threats to bounded future adversarial cases; reuses the existing OAUTH-ATTACK-001 registry boundary and does not modify the Hacker registry.
---

# OAuth Context Binding Adversarial Mapping

This document is a public-safe architecture mapping. It is not evidence of
execution. The existing `OAUTH-ATTACK-001` remains the registry-owned baseline.
The planned cases below are not registered, executed or PASS until separately
authorized implementation and certification exist.

| Planned case | Adversarial condition | Required invariant | Status |
|---|---|---|---|
| OAUTH-ATTACK-002 | valid token is admitted without required provider evidence | capability and requirement are separate; required NOT_AVAILABLE blocks | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |
| OAUTH-ATTACK-003 | client ID or redirect URI is substituted | client fingerprint and exact redirect must match | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |
| OAUTH-ATTACK-004 | requested, granted and method-required scopes are conflated | method-required scopes cannot be assumed from request | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |
| OAUTH-ATTACK-005 | profile/account response belongs to another account | returned account and provider profile bind to transaction | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |
| OAUTH-ATTACK-006 | existing Credential is overwritten after identity or generation change | durable binding and version remain bound | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |
| OAUTH-ATTACK-007 | refresh response rebinds provider account or client | refresh compares current binding and preserves account identity | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |
| OAUTH-ATTACK-008 | browser or callback error attempts an override | browser is not authority; no continue-anyway path | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |
| OAUTH-ATTACK-009 | restart resumes from stale PASS or partial state | restart reconstructs and freshly revalidates all inputs | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |
| OAUTH-ATTACK-010 | secret or raw provider response leaks through logs/UI/audit | only safe projections and typed evidence are durable | NOT_IMPLEMENTED / NOT_REGISTERED / NOT_EXECUTED |

## Required test shape

Each future case must identify its exact transaction, provider/profile,
Credential target, expected stable error family and proof that no unauthorized
Credential write occurred. Tests must cover both fresh callback and recovery/
restart paths. A provider's missing capability must be tested as an explicit
blocking disposition, not as a skipped assertion.

The existing Hacker runner and `scripts/security/attack-registry.json` are out
of scope for this architecture package. `OAUTH-ATTACK-001` is reused for its
proven callback provider mismatch, expired-context and one-time-consumption
coverage; the current tests prove all three. Adding or executing registry cases
requires the separately authorized implementation/certification work package.

## Public safety boundary

This mapping intentionally omits tokens, codes, client secrets, provider
configuration values, live endpoints and private account data. It does not
claim that any case currently passes and cannot authorize a release,
deployment, publication or public apply.
