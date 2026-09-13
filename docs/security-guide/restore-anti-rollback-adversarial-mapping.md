---
title: Restore Anti-Rollback Adversarial Mapping
document_id: DOC-SECURITY-RESTORE-ANTI-ROLLBACK-ADVERSARIAL-MAPPING
version: 1.2.0
classification: PUBLIC
language: en
status: Active
category: Security
canonical: false
owner: Sekalum
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Security reviewers
  - Maintainers
  - Test engineers
  - Operators
dependent_documents:
  - docs/adr/ADR-029-Restore-Anti-Rollback.md
  - docs/architecture/RESTORE_ANTI_ROLLBACK_PATH_MATRIX.md
  - docs/security-guide/index.md
  - docs/project/issue-execution/IEP-rc3.md
change_history:
  - version: 1.2.0
    date: 2026-09-03
    change: Records implementation of the eight bounded RC3-06 attack cases, exact registry references and candidate-bound release-gate execution.
  - version: 1.1.0
    date: 2026-09-03
    change: Records Owner Review acceptance of the eight attack-to-invariant mappings before implementation.
  - version: 1.0.0
    date: 2026-09-03
    change: Prepares the RC3-06 adversarial attack-to-invariant mapping without registering or implementing attacks; all cases remain planned until separate implementation authorization and terminal evidence.
---

# Restore Anti-Rollback Adversarial Mapping

This is a public-safe evidence map for the RC3-06 hacker-test package. It maps
each attack intent to the accepted architecture, exact source boundary and
regression test. The executable registry and candidate-bound runner provide
the authoritative execution status.

| Case | Attack chain | Invariant/control | Regression assertion | Status |
|---|---|---|---|---|
| `RESTORE-ATTACK-001` | Revoked Credential → old active archive → restore | `RESTORE-TERMINAL-001`, `REVOKE-FIRST-001` | Restore is blocked; Credential remains non-consumable; no Secret is returned. | `IMPLEMENTED / RELEASE_GATE` |
| `RESTORE-ATTACK-002` | Deleted Credential → old archive → restore | `RESTORE-TOMBSTONE-001`, `ORPHAN-RESURRECTION-001` | Tombstone blocks identity reuse; no automatic rebind occurs. | `IMPLEMENTED / RELEASE_GATE` |
| `RESTORE-ATTACK-003` | Tombstoned identity → rename/recreate input → restore | `RESTORE-TOMBSTONE-001`, `RESTORE-GENERATION-001` | A new identity may be created only through normal admission; old identity/generation is never reused. | `IMPLEMENTED / RELEASE_GATE` |
| `RESTORE-ATTACK-004` | Revoked API token → future historical restore | `RESTORE-TOKEN-001` | Token remains unauthenticatable; plaintext is never reconstructed or exposed. | `IMPLEMENTED / RELEASE_GATE` |
| `RESTORE-ATTACK-005` | Old principal generation → restore with authority-bearing role | `RESTORE-GENERATION-001`, `RESTORE_PRINCIPAL_CONFLICT` | Old principal generation cannot gain authority; explicit non-terminal resolution is required where allowed. | `IMPLEMENTED / RELEASE_GATE` |
| `RESTORE-ATTACK-006` | Preview passes → concurrent revoke/delete/rebind → commit | `RESTORE-PREFLIGHT-001`, `RESTORE-COMMIT-REVALIDATION-001` | Final Core check detects the changed state and persists no partial authority increase. | `IMPLEMENTED / RELEASE_GATE` |
| `RESTORE-ATTACK-007` | Historical Grant → replacement Credential generation → resolve | `RESTORE-BINDING-001`, `ORPHAN-001` | Exact generation mismatch blocks the Grant; no replacement Secret is delivered. | `IMPLEMENTED / RELEASE_GATE` |
| `RESTORE-ATTACK-008` | Atomic restore failure after staged writes | `RESTORE-ATOMICITY-001`, `RESTORE-CONFLICT-001` | Failure leaves no partial authority increase and records a safe failure result. | `IMPLEMENTED / RELEASE_GATE` |

## Registry and evidence boundary

The executable registry remains the authority for registered, implemented,
executed and release-gate status. The eight cases are registered under
`scripts/security/attack-registry.json` and covered by
`tests/component/rc3-06-restore-anti-rollback.test.js`. A release-gate result
is valid only for the exact candidate commit reported by the IEP.
