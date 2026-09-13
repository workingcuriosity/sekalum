---
title: Restore Anti-Rollback UI and UX Architecture Projection
document_id: DOC-UI-RESTORE-ANTI-ROLLBACK-UX
version: 1.1.0
classification: PUBLIC
language: en
status: Active
category: UI Governance
canonical: false
owner: Sekalum
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Architecture Governance
  - UI contributors
  - API maintainers
  - Security reviewers
  - Test engineers
dependent_documents:
  - docs/ui/CANONICAL_UI_INTERACTION_MODEL.md
  - docs/adr/ADR-029-Restore-Anti-Rollback.md
  - docs/api-reference/index.md
  - docs/security-guide/index.md
  - docs/architecture/CRITICAL_USER_FLOWS_AND_STATE_MODELS.md
change_history:
  - version: 1.1.0
    date: 2026-09-03
    change: Records Owner Review acceptance of the existing-surface state model, safe terminology, browser non-authority and no-UI-model-impact boundary; runtime UI implementation remains separately unauthorized.
  - version: 1.0.0
    date: 2026-09-03
    change: Defines the existing-surface UI state, wording, visibility, re-check and non-goal projection for RC3-06; no UI route, YAML node, browser authorization logic or new page is authorized.
---

# Restore Anti-Rollback UI and UX Architecture

## Ownership and scope

This is a supporting projection of the [Canonical UI Interaction
Model](CANONICAL_UI_INTERACTION_MODEL.md). The canonical YAML source remains
the only structural UI truth. This document defines the UX contract that a
future implementation may project onto existing backup, import and Credential
management surfaces. It does not create an executable interaction, a new
navigation area or a browser-side security decision.

The current UI inventory classifies management backups as API-only. The Owner
Review accepts that boundary; this RC3-06 architecture package changes no YAML,
generated UI tree, Mermaid flow or browser test. When a real existing surface
is authorized later, its YAML model and generated views must be updated in the
same governed change.

## User-visible state model

```text
SELECTING
    → CHECKING
        → CAN_RESTORE
        → CONFLICTS
        → BLOCKED
        → NEEDS_RE_CHECK

CAN_RESTORE --Restore--> CHECKING
CHECKING --current state changed--> NEEDS_RE_CHECK
CONFLICTS --explicit administrative resolution--> CHECKING
BLOCKED --no override--> BLOCKED
NEEDS_RE_CHECK --run review again--> CHECKING
```

The browser renders the Core result. It does not calculate whether a record is
terminal, compare generations, decide a Grant binding or infer that a visible
record is restorable.

| State | Meaning | Allowed presentation | Restore action |
|---|---|---|---|
| `SELECTING` | An existing backup/import candidate is selected but not checked. | Candidate name, source type, timestamp and safe counts. | Start Review. |
| `CHECKING` | Core is evaluating the complete candidate. | Progress and disabled mutation controls. | No mutation. |
| `CAN_RESTORE` | The current preflight found no conflict. | “Restore review” and factual change summary. | Submit restore; Core must revalidate. |
| `CONFLICTS` | One or more records need explicit administrative resolution. | “Security conflicts”, current versus historical safe metadata, remediation. | Only a separately authorized explicit resolution may continue. |
| `BLOCKED` | A terminal barrier, revoked identity, generation/binding barrier or unavailable security evidence prevents restore. | “Blocked” and a stable safe reason. | No Restore-anyway action. |
| `NEEDS_RE_CHECK` | Candidate, current state or actor authority changed after review. | “Current state changed” and “Needs re-check”. | Run the review again. |

## Required terminology

Use:

- **Restore review**
- **Security conflicts**
- **Blocked**
- **Needs re-check**
- **Current state changed**
- **Historical state cannot be restored**

Do not use:

- Safe
- Secure
- Risk-free
- Guaranteed secure
- Restore anyway
- Automatically repair or rebind

The UI must explain that a preview is a review result, not permission. It must
not display Secret values, token plaintext, raw payloads, stack traces,
provider internals or internal-only evidence.

## Existing-surface integration

| Existing surface | Projection | Explicit boundary |
|---|---|---|
| Management backup review, if later exposed | Candidate selection, review result, conflict summary and final re-check. | Current inventory is API-only; no new page is added here. |
| Credential import preview | Add safe anti-rollback conflict state to the existing preview/result. | Core owns generation, lifecycle and terminal decisions. |
| Credential detail/history | Show a factual blocked or unavailable historical operation result. | Secret values and internal security evidence remain hidden. |
| Consumer Grant management | Show exact binding conflict if a future Grant historical path exists. | No rebind, no parallel restore workflow and no change to ADR-020. |
| API-token management | No current restore UI. | Future token restore must preserve revocation and principal generation. |

## Interaction rules

1. Selecting a visible backup, Credential or historical entry is not an
   authorization decision.
2. Review results are bound to a candidate digest and current-state digest.
3. The final Restore action invokes Core revalidation; it never trusts a stale
   review receipt.
4. A changed state clears the prior positive result and moves to
   `NEEDS_RE_CHECK`.
5. Hard terminal blocks remain visible as blocks and cannot be overridden by a
   role label, confirmation checkbox or client-side retry.
6. Explicit administrative resolution is a separate governed mutation, is
   shown as such and remains subject to current authority and final Core
   validation.
7. Success is reported only after the Core commit result is durable. A pending
   cleanup or audit finalization state must not be presented as a successful
   security-state rollback.

## UI architecture gate

```text
Owner review: Accepted
New page required: No
New navigation area required: No
Current UI YAML changed: No
Browser authority: No
Restore override: No
Secret or token display: No
UI gate: Pass
```

The projection is ready for a separately authorized implementation only. It
does not claim that the current product exposes a management backup restore
flow in the browser.
