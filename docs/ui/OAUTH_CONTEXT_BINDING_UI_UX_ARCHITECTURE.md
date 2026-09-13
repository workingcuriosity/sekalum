---
title: OAuth Context Binding UI and UX Architecture
document_id: DOC-UI-OAUTH-CONTEXT-BINDING-UI-UX-ARCHITECTURE
version: 1.1.0
classification: PUBLIC
language: en
status: Accepted
category: UI Governance
canonical: true
owner: Sekalum
approved_by: Project Owner / Repository Maintainer
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - UI contributors
  - UX contributors
  - Developers
  - Security reviewers
  - Accessibility reviewers
dependent_documents:
  - docs/adr/ADR-031-OAuth-Context-Binding.md
  - docs/ui/CANONICAL_UI_INTERACTION_MODEL.md
  - docs/api-reference/index.md
  - docs/security-guide/index.md
  - docs/project/issue-execution/IEP-rc3.md
change_history:
  - version: 1.1.0
    date: 2026-09-04
    change: Records Owner Review PASS and accepts the existing-Wizard projection, canonical CONFIGURE/AUTHORIZE/WAIT_CALLBACK/CREDENTIAL_READY/ERROR mapping and no-UI-model-change boundary.
  - version: 1.0.0
    date: 2026-09-04
    change: Defines the existing-surface OAuth Context Binding projection, safe context visibility, error handling and no-UI-model-change gate; no UI implementation is authorized.
---

# OAuth Context Binding UI/UX Architecture

## UI decision

RC3-08 uses the existing Credential Wizard and callback result surface.

| UI decision | Value |
|---|---|
| New page | No |
| New navigation | No |
| Security center | No |
| Current UI path | Credential Wizard to OAuth callback result |
| Current UI YAML changed | No |

The browser is a presentation and intent channel. It is not an authority,
does not select an alternate provider context after start and cannot override a
server-side mismatch.

## User-visible context

Before the browser handoff, the Wizard may show non-secret context that the user
is about to authorize: provider display name, Credential Method, safe account
target label when already known, requested scopes and the configured public
redirect origin. It must not show client secrets, authorization codes, tokens,
PKCE material, provider configuration values or internal digests that do not
help the user make the authorization decision.

At callback completion, success is displayed only after evidence admission and
Credential persistence. The result contains a stable success code and safe
provider/Credential identifiers. A failure contains a stable outcome family and
an actionable generic message; it does not contain raw provider text, token
content, configuration values or a reason that enables account enumeration.

## Server phase and canonical Wizard state mapping

The following labels are server phases or outcome classes, not new canonical UI
state values. The current Wizard model remains authoritative:

| Server/outcome phase | Existing Wizard state | Mapping decision |
|---|---|---|
| Ready | `CONFIGURE` or `AUTHORIZE` as applicable | current inputs are collected; no new state |
| Authorization pending | `WAIT_CALLBACK` | one-time transaction and browser binding exist |
| Callback validating | `WAIT_CALLBACK` | server validation continues while the same visible state remains |
| Succeeded | `CREDENTIAL_READY` | evidence and Credential commit both passed |
| Rejected | `ERROR` or `CONFIGURE` depending existing behavior | no Credential write; user may start a fresh attempt |
| Expired/replayed | `ERROR` | old transaction is unusable; fresh transaction required |

`Callback validating` is not a visible progress step. The transition is
`WAIT_CALLBACK -> server validation ongoing -> WAIT_CALLBACK`; the browser has
no authority to advance, override or substitute context. These mappings are
documentation descriptions and do not add YAML nodes or canonical state
values.

Changing provider, method, configuration or required scopes invalidates the
pending transaction. Retry always starts a new transaction. A callback error
does not offer “continue anyway”, “trust token”, risk-score override or manual
issuer/client substitution.

## UI model gate

| UI model gate | Result |
|---|---|
| New UI state | No |
| New UI page | No |
| New navigation | No |
| Current UI YAML changed | No |
| Browser authority | No |
| Canonical UI states unchanged | Yes |
| Server phases distinguished from UI states | Yes |

## Safe error projection

The public result maps the architecture's stable families to minimal UI copy:

```text
OAUTH_CONTEXT_INVALID
OAUTH_CONTEXT_EXPIRED
OAUTH_PROVIDER_MISMATCH
OAUTH_PROFILE_MISMATCH
OAUTH_METHOD_MISMATCH
OAUTH_CLIENT_MISMATCH
OAUTH_ISSUER_MISMATCH
OAUTH_AUDIENCE_MISMATCH
OAUTH_SCOPE_MISMATCH
OAUTH_ACCOUNT_MISMATCH
OAUTH_REDIRECT_URI_MISMATCH
OAUTH_CREDENTIAL_BINDING_MISMATCH
OAUTH_CREDENTIAL_STATE_CHANGED
OAUTH_EVIDENCE_UNAVAILABLE
```

The UI may say that authorization could not be completed for the selected
context and invite a fresh retry. It must not expose whether another account,
client, provider profile or Credential exists.

## Accessibility and interaction requirements

The projection retains the existing Wizard's keyboard order, focus return,
visible labels, semantic status announcements and non-color-only error
communication. Callback success and failure must be understandable without
browser console access. The callback page must remain usable when the provider
closes or denies authorization.

These are architecture requirements for future implementation review. They do
not authorize changes to the canonical UI YAML, generated views or product
code. The UI model gate must therefore report a deliberate no-change result.

## Boundary and evidence rules

No durable UI PASS is authority for later recovery. A restart or retry obtains a
fresh server decision. Browser-visible values are safe projections only; audit
evidence remains secret-free and outside the browser. Provider authorization
network transport is outside this UI architecture and remains owned by the
existing server/provider boundary.
