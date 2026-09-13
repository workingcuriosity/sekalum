---
title: Consumer Integration Safe-Use UI UX Architecture
document_id: DOC-UI-CONSUMER-INTEGRATION-SAFE-USE-UI-UX-ARCHITECTURE
version: 1.0.0
classification: PUBLIC
language: en
status: Proposed
category: UI Governance
canonical: true
owner: Sekalum
approved_by: pending
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - UI contributors
  - UX contributors
  - Developers
  - Security reviewers
  - Accessibility reviewers
  - Integrators
dependent_documents:
  - docs/architecture/governance/PRODUCT_INVARIANTS.md
  - docs/adr/ADR-020-Credential-Consumer-API.md
  - docs/ui/CANONICAL_UI_INTERACTION_MODEL.md
  - docs/api-reference/index.md
  - docs/security-guide/index.md
  - docs/architecture/CONSUMER_INTEGRATION_GUIDANCE_SURFACE_MATRIX.md
  - docs/architecture/CONSUMER_INTEGRATION_SAFE_USE_GUIDANCE_ARCHITECTURE.md
  - docs/project/issue-execution/IEP-rc3.md
change_history:
  - version: 1.0.0
    date: 2026-09-05
    change: Defines the bounded existing-surface UI/UX projection for RC3-10 safe Consumer integration guidance; no new page, route, navigation, UI state, YAML model, API or runtime capability is authorized.
---

# RC3-10 – Consumer Integration Safe-Use UI/UX Architecture

## UI decision and authority boundary

The UI is an intent and presentation client. It does not authenticate a
different authority, calculate Grants, broaden Secret fields, decide whether a
runtime may retain a value or override a server response.

| UI boundary | Decision |
|---|---|
| New UI page | NO |
| New navigation | NO |
| New route or API | NO |
| New UI-YAML selector/model | NO |
| New durable UI state | NO |
| Browser security authority | NO |
| Copy-resolved-secret action | NO |
| Automatic execution of generated examples | NO |
| Bounded existing-surface guidance | YES, subject to separate implementation authorization |

The proposed projection adds concise warnings and links to the existing Admin
Grant/Wizard and Consumer result surfaces. It does not change their security
semantics.

## Existing-surface map

| Existing surface | Current role | RC3-10 projection | New state |
|---|---|---|---|
| Admin Consumer Grants (`public/admin/consumer-grants.html`, `.js`) | Select Consumer, Credential, provider and named Secret fields; review a secret-free summary. | Explain minimum named fields, dedicated Consumer identity, and the fact that a Grant limits delivery but cannot erase external copies. | None |
| Admin Wizard consumer verification (`public/admin/wizard.html`, `.js`) | Create a dedicated Consumer token, select/verify Grant access, show placeholder curl example. | Label verification as a bounded check; say examples are documentation-only and no Management Token or automatic execution is involved. | None |
| Consumer page (`public/consumer/index.html`, `.js`) | Enter Consumer token, run Discovery, select a public `credentialKey`, select named fields, Resolve, view masked/timed result. | Place an explicit safe-use reminder near Resolve/result: use immediately, do not copy/persist/log/export or place values in URLs; external runtime controls remain outside the page. | Existing auth/discovery/resolve/result states only |
| Resolve example generator (`public/consumer/client-generator.js`) | Produce curl/Node/Python/PowerShell/n8n placeholder examples. | Preserve placeholders, show direct-target pattern and comments warning against workflow state, logs, retry payloads and source control. | None |
| Consumer profile templates (`public/admin/consumer-profiles.js`) | Suggest an identifier, existing scope and named fields. | Mark `FORM_SUGGESTION_ONLY`; do not imply authorization, auto-save or a storage guarantee. | None |
| n8n reference examples (`examples/n8n/*`) | Show generic Consumer API Discovery/Resolve and direct target request. | Add safe-use text in the reference entry; keep n8n ordinary and generic HTTP canonical. | None |

## Interaction model

The existing logical flow remains:

```text
empty/authentication
  → Discovery loading/result
  → credential selection
  → named-field selection
  → Resolve loading/result
  → masked value with timed reveal
  → clear on selection/request/session according to existing UI behavior
```

| Interaction | Required UX behavior | Security reason |
|---|---|---|
| Consumer token entry | Describe it as a dedicated Consumer token; keep it in page memory and never suggest a Management Token. | Separates management authority from runtime authority. |
| Discovery | Use public display metadata, tags and opaque logical `credentialKey`; never show Secret values or internal provider details. | Prevents metadata from becoming an enumeration or Secret channel. |
| Field selection | Show only fields returned by the public Field Contract; require explicit selection. | Makes minimum Secret-field scope visible and reviewable. |
| Resolve submit | Keep the existing server request and error contract; no wildcard helper or client-side authorization decision. | Server-side Grant/lifecycle checks remain authoritative. |
| Result rendering | Mask by default, retain timed reveal behavior, and do not add copy/download/export controls. | Reduces accidental spread in browser UX. |
| Generated example | Read-only, placeholder-only, documentation output; never auto-run or save as a workflow. | Prevents the UI from becoming a secret/configuration injector. |
| Rotation/revocation message | Explain logical-reference continuity and that a fresh authorized Resolve may be needed. Do not display Secret Version or material. | Keeps the stable key distinct from version/material. |
| Failure | Use existing safe status/error region and link to corrective Grant/token action where appropriate. | Avoids raw diagnostics and authority escalation. |

## Safe-use copy contract

The following copy is proposed for reuse across existing surfaces. Wording may
be localized later under the existing language model, but the security meaning
must remain unchanged.

```text
Use a dedicated Consumer token, not a Management Token.
Request only the named Secret fields required for the next operation.
Use resolved values immediately where practical. Do not copy, persist, log,
export, pin, place them in URLs, or include them in retry payloads.
Sekalum limits what is delivered; the external runtime controls what happens
after delivery.
```

The copy must not claim that `Cache-Control: no-store`, page cleanup or a Grant
retroactively erases a value from n8n, an automation platform, a queue, an
execution history or an external log.

## Existing UI state and no-model-change contract

| State/event | Existing projection | RC3-10 rule |
|---|---|---|
| Authentication | Existing token gate and status region | Keep token in transient page state; do not create a persistent credential state. |
| Discovery | Existing loading/result region | Present public metadata and field contract only. |
| Credential selection | Existing selection controls | Clear prior Resolve result when selection changes; do not pin material. |
| Field selection | Existing checkboxes/selection controls | Limit requests to selected authorized names. |
| Resolve success | Existing masked result and timed reveal | No copy/export/download action; do not add a durable “secret available” state. |
| Resolve failure | Existing safe error/status region | Do not show raw API diagnostics, token data or resource-existence detail. |
| Generated example | Existing read-only output panel | Keep placeholder-only and non-executable. |

No new state key, navigation item, selector, storage bucket or browser-side
authority is proposed. A future implementation must therefore be a bounded
copy/content change on already reviewed selectors, with no UI-YAML mutation.

## Accessibility and usability

Existing `role="status"` and `aria-live` regions remain the projection path
where present. Guidance must:

- be visible without relying on color;
- be associated with the Grant/Resolve action it explains;
- announce a material warning once without repeatedly interrupting a workflow;
- preserve keyboard focus on the originating control after a safe error;
- describe why a temporary failure or unavailable action occurs without
  exposing server diagnostics;
- keep masked result labels understandable to screen readers; and
- avoid a “copy secret” affordance or a bypass action.

The safe-use warning is informative. The server remains responsible for
authentication, authorization, field scope, lifecycle and response behavior.

## n8n projection

n8n has no special UI authority in Sekalum. The generic HTTP Consumer API
remains the canonical platform-neutral model. The existing native n8n node is
the preferred n8n reference UX for the completed Issue #131 node work and must
provide the same visible safe-use cues: dedicated Consumer identity, explicit
field selection, direct target use, and no static/pinned/logged plaintext. It
does not create special authority. Issue #173 is open adoption, video and
reference-workflow evidence only; it is not a future-node or product-runtime
authority. RC3-10 does not introduce a new Sekalum page, navigation, state or
product-repository runtime capability.

## UI gate conclusions

| Gate | Decision |
|---|---|
| Existing-surface projection | SELECTED |
| New UI page | NO |
| New navigation | NO |
| New route | NO |
| New UI-YAML selector | NO |
| New durable UI state | NO |
| Browser authority | NO |
| Copy resolved Secret | NO |
| Auto-execute examples | NO |
| Privileged n8n UI | NO |
