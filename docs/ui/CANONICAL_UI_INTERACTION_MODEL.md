---
title: Canonical UI Interaction Model
version: 0.6.0
status: Active
category: UI Governance
canonical: true
owner: Sekalum
maintainer: cyphre-san productions
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 cyphre-san productions"
target_audience:
  - Maintainers
  - Architecture Governance
  - Documentation Engineers
  - Test Engineers
  - Security Engineers
  - UI contributors
dependent_documents:
  - docs/ui/CANONICAL_UI_INTERACTION_MODEL_COMPLETION_RECORD.md
  - docs/architecture/CRITICAL_USER_FLOWS_AND_STATE_MODELS.md
  - docs/architecture/ARCHITECTURE_KNOWLEDGE_MAP.md
  - docs/project/IMPLEMENTATION_STRATEGY_AND_UI_QUALITY_GATES.md
  - docs/ui/canonical-ui-interaction-model.yaml
  - docs/ui/canonical-ui-interaction-model.schema.json
  - docs/ui/generated/ui-tree.md
  - docs/ui/generated/ui-flow.mmd
change_history:
  - version: 0.7.0
    date: 2026-08-16
    change: Aligns the current UI model ownership and application identity with Sekalum; no UI route, interaction, API or security contract changes.
  - version: 0.6.0
    date: 2026-08-06
    change: Completes the current 1.x interaction graph with explicit route, API-only and terminal path records; Issue #153 remains a separate future 2.0 architecture scope.
  - version: 0.5.2
    date: 2026-08-02
    change: Links the accepted canonical completion record for the completed UI interaction-model work package.
  - version: 0.5.1
    date: 2026-08-02
    change: Classifies every modeled interaction as executable, blocked, or not executed; report coverage distinguishes these classes without adding browser flows.
  - version: 0.5.0
    date: 2026-08-02
    change: Makes selected canonical interactions executable through YAML-bound browser verification and generates redacted coverage, traceability and regression reports; no product behavior was changed.
---

# Canonical UI Interaction Model

## Purpose

This document defines the governance and ownership boundary for the
Canonical UI Interaction Model and records the Phase 2 repository inventory.
The YAML source is the single machine-readable UI truth; generated views have
no independent authority.

The normative structural source is
[`canonical-ui-interaction-model.yaml`](canonical-ui-interaction-model.yaml).
The JSON Schema validates that source. Markdown and Mermaid views are fully
generated and have no independent authority; the generated tree includes the
route matrix, API-only paths and terminal UI paths, while the Mermaid view
includes the canonical route graph.

## 1.x scope boundary

Issue #143 completes the interaction model for the existing Sekalum 1.x
surface. Issue #153 is explicitly excluded: it defines future 2.0 UI and
access architecture and must not be inferred from this 1.x model.

## Ownership and authority

| Area | Authority |
|---|---|
| UI structure, navigation and interaction model | This document family and its YAML source |
| Architecture, architectural state models and fachliche flows | `docs/architecture/CRITICAL_USER_FLOWS_AND_STATE_MODELS.md` |
| API contracts | `docs/api-reference/index.md` and applicable ADRs |
| Security model and security rules | `docs/security-guide/index.md` and applicable governance sources |
| Product intent and invariants | `docs/architecture/governance/PRODUCT_INTENT.md` and `PRODUCT_INVARIANTS.md` |
| Generated presentation | `docs/ui/generated/`; never authoritative |

The Critical User Flows document remains unchanged in responsibility. This
UI model does not extend it with navigation or implementation-specific UI
detail, and it does not redefine architecture, API, data-model or security
rules.

The owner is Sekalum. The maintainer is cyphre-san productions.
Architecture Governance reviews scope and cross-document consistency;
Documentation Engineering maintains traceability; Test Engineering owns
validation and test binding; Security Engineering reviews security boundaries
and evidence handling. None of these roles may change the ownership boundary
or approve a new architecture decision autonomously.

## Source of truth

There is exactly one normative structural source:

```text
docs/ui/canonical-ui-interaction-model.yaml
```

The source is YAML, validated against
`canonical-ui-interaction-model.schema.json`. The generator produces:

- `docs/ui/generated/ui-tree.md` — human-readable generated tree, route
  matrix, API-only path register and terminal-path register;
- `docs/ui/generated/ui-flow.mmd` — generated Mermaid hierarchy and route
  graph.

Generated files must never be edited manually. CI detects drift by
regenerating them and comparing the result with the committed files.

## Scope

The model family owns:

- UI applications, areas, pages, panels, tabs, dialogs, modals, drawers and
  wizards;
- forms, fields, buttons, links, menus, tables, row actions and redirects;
- UI-visible states, visibility conditions and role-dependent exposure;
- user interactions, expected next states and user feedback;
- UI-to-capability and UI-to-evidence traceability.

It does not own:

- architecture decisions or architectural state models;
- API specifications, backend contracts or data models;
- the security model, security policy or authorization decisions;
- product requirements, release approval or implementation code;
  - a judgment that non-exposed code is defective;
  - implementation changes, UX remediation, dead-code removal or browser
  automation.

## Document control and versioning

The governance document and YAML source use explicit semantic versions. A
change to the structural source requires the source version, generated views,
traceability references and relevant validation evidence to be updated in the
same change. The schema version changes when the accepted structural contract
changes. Generator changes require regenerated outputs and a validator test.

The active status records the current repository inventory. Dynamic repeated
controls are represented by their rendering containers and handlers; the audit
marks selector-level expansion and authenticated live evidence as follow-up
work. A schema or ownership change requires Architecture Governance review
before implementation.

## Traceability contract

The model supports bidirectional traceability:

```text
UI node / interaction
  → capability
  → source file or handler
  → API / service
  → canonical requirement or contract
  → test reference
  → live evidence
```

The reverse direction is required for Phase 2 coverage analysis:

```text
route / handler / capability
  → UI usage or intentional exposure classification
  → test reference
  → canonical UI model reference
```

No Phase 2 coverage claim may be inferred from the empty foundation source.

## Change control

The YAML source must be reviewed when any of the following changes:

- a page, route, panel, tab, dialog, modal or wizard;
- a form, field, button, link, menu or row action;
- a visible state, message, loading state, error or recovery path;
- a role, permission-dependent visibility rule or authentication boundary;
- a capability exposed through UI;
- a UI API call, navigation target or external handoff;
- a test selector, test reference or live-evidence reference.

The change must either update the YAML source and regenerate its views or
include an explicit, reviewed `no-ui-model-impact` explanation. Product,
architecture, API, data-model and security changes remain governed by their
own canonical sources.

## Phase 2 audit result

The audited inventory and every interaction, capability and feedback total are
derived only from the YAML source. The generated UI tree and verification
report are the authoritative rendered locations for current totals; this
document deliberately contains no independently maintained count.

The audit identifies API-only management capabilities for users, roles,
audit-log, metrics and backups. They are classified as intentional pending
owner review; no UI exposure is inferred. The source also records the
application route matrix and intentional terminal UI paths so each modeled
surface has an explicit entry or terminal disposition. Interaction-level `live_verified`
values remain false because the available live evidence was limited to
read-only route smoke checks, not authenticated browser execution.

## Phase 3 quality automation

### Implementation assessment

The existing YAML, JSON Schema, generator and validator were sufficient for
page/flow traceability but lacked stable control selectors, DOM checks and a
browser runner. The minimal extension adds selector metadata and evidence
fields to the existing source, one static selector validator, a controlled
Playwright fixture and smoke tests. It does not alter application API,
architecture, the security model or user-facing product behavior. Dynamic
controls remain warning-class static-analysis cases; authenticated live tests
require explicit safe fixtures.

Phase 3 extends the same YAML source; it does not create a second UI model.
Controls in critical automated flows carry `selectors` entries with strategy,
value, scope, source file, required and runtime-generated fields. Preferred
strategies are `test_id`, then stable `id`; route and structural selections are
fallbacks. `data-testid` uses lowercase kebab-case and is added only where an
existing semantic identifier is insufficient.

`npm run ui:selectors:check` validates selector strategies, marker presence,
source-file references and duplicate exclusive selectors. `npm run
ui:test:smoke` runs model-bound Playwright checks against a controlled local
fixture for root routing, protected Admin entry, invalid-login feedback and
Consumer discovery entry. Browser console and page errors fail the smoke run.

Authenticated live testing is deliberately separate. an approved authenticated live-test profile
returns `SKIPPED_WITH_REASON` until an approved redacted evidence sink and
safe environment variables are supplied. No token, secret or screenshot is
stored in the repository. Every future live result must contain environment,
timestamp, commit, test ID, result, evidence reference and limitations.

### Test-infrastructure status

| Component | Status | Constraint |
|---|---|---|
| Browser framework | Present | Playwright Chromium; install with `npx playwright install chromium` locally. |
| Local UI fixture | Present | Static, controlled and contains no secrets. |
| Test Admin / Consumer token | Blocked | Safe expiring credentials have not been provisioned. |
| Test credential / grant | Blocked | Requires controlled seed/reset process. |
| OAuth test | Blocked | Requires a controlled provider test environment. |
| Network-error simulation | Partial | Local fixture provides deterministic failed requests; provider paths are not exercised. |
| Screenshot redaction | Not used | Screenshots are disabled for this baseline. |
| VPS live mode | Guarded | Runner skips until approved environment variables and evidence sink exist. |

## Phase 4 safe test infrastructure

The local fixture namespace is `credential-hub-ui-test`. It defines a
`ui-test-admin`, `ui-test-consumer`, `ui-test-credential`, `ui-test-grant` and
fixture-only tokens. They exist only in the controlled fixture server or the
ignored `test-results/ui-fixtures/` directory; they are not written to the
application's storage, sent to the VPS or accepted by production services.

`npm run ui:test:seed` creates the deterministic fixture state. `ui:test:reset`
restores that exact state only after checking its namespace, and
`ui:test:cleanup` removes only the dedicated fixture directory. The CI flow
seeds before browser tests and always cleans up afterward.

Structured evidence passes through automatic redaction. Values of fields and
headers that imply authorization, cookies, sessions, tokens, secrets, API
keys, passwords, access or refresh values are replaced with `[REDACTED]`.
Screenshots remain disabled. The authenticated local suite covers Admin login,
Consumer Discovery and Consumer Resolve plus their unauthenticated error
paths. OAuth stays out of automation until a controlled provider environment,
mock or replay contract is approved.

## Phase 5 executable verification

An interaction may declare a `verification` block in the canonical YAML. It
contains the test ID, local fixture environment, route, fixture alias, generic
verification mode, expected feedback and evidence target. Playwright discovers
only these declarations; it does not own a parallel flow inventory. Each
executed test attaches redacted evidence containing its interaction ID and
capability IDs.

`npm run ui:verification:check` runs seed, YAML-derived browser verification,
report generation and cleanup, with cleanup guaranteed even after a failed
seed, browser run or report operation. It produces JSON, Markdown, Mermaid,
HTML, JUnit and redacted evidence under `test-results/ui-verification/`.
Reports consume only structured Playwright results and label absent execution
as `NOT_EXECUTED`. Regression is `REGRESSION_NOT_AVAILABLE` without an actual
baseline; it is never inferred. Scores are unweighted measured ratios.

Every interaction has exactly one entry in `interaction_execution`: `EXECUTABLE`
requires a local YAML verification, `BLOCKED` records reason, evidence and its
external dependency, and `NOT_EXECUTED` records the missing fixture and work.
Coverage reports these three classes separately; blocked and intentionally
unexecuted interactions are not reported as failed executable coverage.

## Definition of Done

Phase 1 is complete when:

- one YAML source and one JSON Schema exist;
- the YAML source validates successfully;
- IDs, references, parent relationships and enums are validated;
- Markdown and Mermaid views are generated from the YAML source;
- generator drift is detected by CI;
- the validator and generators have automated tests;
- traceability, ownership, scope and change control are documented;
- the existing Critical User Flows responsibility remains unchanged;
- the CI gate executes schema, reference, generator and output checks;
- the current UI inventory, interaction bindings, capability classifications,
  feedback catalogue and audit findings are represented in YAML;
- generated views are regenerated and drift-checked;
- non-exposed capabilities and live-evidence limits are explicit;
- no product, API, architecture, data-model or security implementation was
  changed.

## Local commands

```bash
npm run ui:model:validate
npm run ui:model:generate
npm run ui:model:check
```

`ui:model:check` validates the YAML source, checks the JSON Schema and
compares generated Markdown and Mermaid output with the committed files.
