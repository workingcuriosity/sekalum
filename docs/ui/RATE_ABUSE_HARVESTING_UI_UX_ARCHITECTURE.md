---
title: Rate Abuse and Harvesting UI UX Architecture
document_id: DOC-UI-RATE-ABUSE-HARVESTING-UI-UX-ARCHITECTURE
version: 1.1.0
classification: PUBLIC
language: en
status: Accepted
category: UI Governance
canonical: true
owner: Sekalum
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - UI contributors
  - UX contributors
  - Developers
  - Security reviewers
  - Accessibility reviewers
approved_by: Project Owner / Repository Maintainer
dependent_documents:
  - docs/adr/ADR-032-Rate-Limit-Abuse-and-Harvesting-Baseline.md
  - docs/ui/CANONICAL_UI_INTERACTION_MODEL.md
  - docs/architecture/RATE_ABUSE_HARVESTING_PATH_MATRIX.md
  - docs/security-guide/rate-abuse-harvesting-adversarial-mapping.md
  - docs/project/issue-execution/IEP-rc3.md
change_history:
  - version: 1.1.0
    date: 2026-09-04
    change: Records Owner Review PASS and accepts the existing-surface UI projection, safe 429 contract, accessibility boundary and no-new-UI-model decision.
  - version: 1.0.0
    date: 2026-09-04
    change: Defines the existing-surface UI/UX projection for RC3-09 throttling and abuse outcomes; no UI implementation or YAML model change is authorized.
---

# RC3-09 – Rate, Abuse and Harvesting UI/UX Architecture

## UI decision and authority boundary

| UI boundary | Decision |
|---|---|
| New UI page | NO |
| New navigation | NO |
| Security dashboard | NO |
| Current UI YAML change | NO |
| Browser security authority | NO |
| UI implementation | NOT AUTHORIZED |

The rate-limit architecture projects transient admission outcomes through the
existing Admin actions, Consumer API result surfaces and OAuth wizard. The
browser remains an intent and presentation client; it does not calculate
budgets, select keys, bypass a throttle, or authorize a retry.

## Existing surfaces

| Surface | Existing projection | RC3-09 behavior | New canonical state |
|---|---|---|---|
| Admin management action | existing status/result panel | show safe `RATE_LIMITED` outcome and bounded retry guidance | none |
| Admin credential/provider action | existing operation result | preserve current pending/success/error surface; no secret/provider existence detail | none |
| Consumer discovery/resolve | existing Consumer status and result region | show safe transient failure; do not distinguish missing, unauthorized or throttled resource | none |
| Consumer batch Resolve | existing batch result | one safe bounded result; no per-item budget detail or partial secret projection | none |
| OAuth start | existing Wizard `CONFIGURE` / `AUTHORIZE` action | limited start returns to existing configure/authorize context with safe retry guidance | none |
| OAuth callback | existing callback result | invalid/cancelled callback stays `ERROR`; valid callback continues existing `WAIT_CALLBACK` / `CREDENTIAL_READY` flow | none |
| Revocation/containment | existing management action | separate high-priority admission may proceed; still uses existing authz and result surface | none |
| Static assets and health | existing edge/health behavior | no user-visible limiter state; health must not reveal internal bucket state | none |

## Safe 429 projection

The server's public contract is the only source of truth:

```text
HTTP 429
error.code = RATE_LIMITED
Retry-After = positive bounded seconds
Cache-Control = no-store
```

The message is generic and must not include IP/source identity, token prefix,
bucket name, threshold, remaining capacity, resource existence, provider
identity or another actor's activity. The UI may say “Too many requests.
Please retry later.” It may display a bounded countdown derived from
`Retry-After`, but the countdown is informative and never a security
decision.

No automatic mutation retry is allowed. If a user explicitly repeats a
mutation after the server guidance, it is a new request and is re-admitted
from scratch. A client-side debounce is permitted solely to improve UX and
does not replace server admission. Read-only refresh may use bounded backoff;
unbounded polling is prohibited.

## Accessibility and interaction contract

Existing `role="status"` and `aria-live="polite"` regions remain the
projection mechanism where present, including the Consumer status region and
discovery results. A throttle message must be announced once, remain
understandable without color, and preserve keyboard focus on the originating
control. Disabled controls must expose why they are temporarily unavailable
without presenting a bypass action. The UI must not expose a raw server
diagnostic or an internal retry calculation.

The UI does not add a new global “rate limited” state to the canonical UI
model. A rate-limited operation is a transient result of the existing action;
it must not turn into a durable credential, provider, OAuth or authorization
state. Existing `ERROR`, `WAIT_CALLBACK` and `CREDENTIAL_READY` semantics
remain unchanged.

## Security boundaries

The UI cannot:

```text
select or display limiter keys
override a 429
turn a failed authentication into an admitted request
retry a mutation automatically
choose a provider/account identity for admission
authorize a browser-only exception
```

The server performs all source normalization, identity binding, cost charging,
concurrency reservation, failure handling and audit decisions. OAuth browser
state remains one-time context binding, not rate-limit authority. The UI
projection must remain safe if a resource exists or does not exist.

## Validation boundary

The architecture gate checks that no new page, navigation, YAML selector,
browser authority or durable UI state is introduced. Implementation, browser
tests, server tests and certification are separately unauthorized by this
document. Any future UI change requires its own UI model and selector review.
