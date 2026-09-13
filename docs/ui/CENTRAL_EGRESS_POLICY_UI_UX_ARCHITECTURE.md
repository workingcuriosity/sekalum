---
title: Central Egress Policy UI and UX Architecture
document_id: DOC-UI-CENTRAL-EGRESS-POLICY-UX
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
  - docs/adr/ADR-030-Central-SSRF-and-Egress-Policy.md
  - docs/api-reference/index.md
  - docs/security-guide/index.md
  - docs/project/CREDENTIAL_CONNECTION_TEST_STRATEGY.md
  - docs/project/issue-execution/IEP-rc3.md
change_history:
  - version: 1.1.0
    date: 2026-09-03
    change: Records Owner Review acceptance of the existing-surface UI projection, no-browser-authority boundary and no-current-UI-YAML-change decision; UI implementation remains separately unauthorized.
  - version: 1.0.0
    date: 2026-09-03
    change: Defines the RC3-07 existing-surface UI/UX gate, safe wording, Core-result state projection, no-override boundary and no-UI-model-impact decision; no UI implementation is authorized.
---

# Central Egress Policy UI and UX Architecture

## Ownership and scope

This is a supporting projection of the [Canonical UI Interaction
Model](CANONICAL_UI_INTERACTION_MODEL.md). The YAML source remains the only
structural UI truth. This document defines how a future implementation may
project Core Egress results onto existing connection-test, Credential
Validate/Health and OAuth result surfaces. It creates no page, route,
navigation area, model node or browser-side security authority.

Central Egress is a Core security boundary, not a new security product. The
browser renders the Core result; it does not resolve DNS, classify addresses,
enable private networks, choose a port, approve a redirect or override a
blocked target.

## UI gate UI-01..UI-18

| ID | Decision | Boundary |
|---|---|---|
| UI-01 | No new page | Use existing Credential, Provider and OAuth result surfaces. |
| UI-02 | No new navigation area | No Security Center, Egress dashboard or navigation entry. |
| UI-03 | Browser has no authority | Browser receives and presents the Core result only. |
| UI-04 | No “Allow anyway” | A blocked Egress result cannot be overridden in UI. |
| UI-05 | No private-network checkbox in Credential UI | Private exceptions are operator/deployment policy, not a user toggle. |
| UI-06 | Reuse connection-test surfaces | Draft and stored Credential tests project existing action/result areas. |
| UI-07 | Reuse Validate/Health feedback | Existing lifecycle and health feedback remain the presentation boundary. |
| UI-08 | Reuse OAuth/server failure surface | OAuth network failures return through the existing safe result path. |
| UI-09 | Minimize private IP disclosure | Public UI does not expose resolved private addresses or resolver detail. |
| UI-10 | No secret/header/body disclosure | Never render secrets, bearer values, raw request bodies or provider responses. |
| UI-11 | Admission is not authorization | `TARGET_ADMITTED` is an intermediate Core state, not a permanent grant. |
| UI-12 | Target edits invalidate prior result | Host, port, scheme, protocol or relevant credential input changes require a new check. |
| UI-13 | Exceptions are operator-configured | Deployment/governance configuration controls the bounded private exception. |
| UI-14 | No Egress dashboard | No new monitoring product or aggregate security view is introduced. |
| UI-15 | No risk score | Show factual connection outcome, not a numeric security score. |
| UI-16 | No Custom Provider network editor | Declarative custom providers remain data-only. |
| UI-17 | Human reason plus stable code | Show safe human wording with a stable technical family where useful. |
| UI-18 | Canonical YAML only for visible change | The YAML changes only when an actual visible interaction/state changes. |

## State model

The Core result projects onto existing surfaces using this bounded state model:

```text
IDLE
  → CHECKING_TARGET
      → TARGET_BLOCKED
      → DNS_FAILED
      → TARGET_ADMITTED
          → CONNECTING
              → CONNECTED
              → CONNECTION_FAILED
              → TIMEOUT
              → RESPONSE_LIMIT
```

`TARGET_ADMITTED` is an internal/intermediate state. It may be represented by
existing progress feedback but is not presented as “trusted”, “safe” or
authorized for future use. A changed target or policy context returns the
surface to `CHECKING_TARGET`; a previous result cannot be reused as permission.

## Safe wording

Prefer:

- “Connection blocked”
- “Target could not be resolved”
- “Connection not permitted by network policy”
- “Provider connection blocked”
- “Connection timed out”
- “Response exceeded the allowed limit”

Avoid:

- “Safe”
- “Secure”
- “Trusted”
- “SSRF safe”
- “Guaranteed”
- “Allow anyway”

The UI may show a stable code such as `EGRESS_TARGET_BLOCKED` beside a safe
human reason. It must not reveal resolver output, private IP details,
authorization headers, secrets, response bodies or raw stack traces.

## Existing-surface projections

| Existing surface | Success projection | Failure projection | UI authority |
|---|---|---|---|
| Draft Credential connection test | `CONNECTED` result with provider, protocol and checked time. | Safe human reason and stable code; no save or lifecycle mutation is inferred. | None. |
| Stored Credential Validate | Existing validation success/lifecycle feedback. | Existing connection failure family, mapped from Core without raw details. | None. |
| Stored Credential Health Check | Existing health status and checked time. | Existing down/timeout/blocked result. | None. |
| OAuth callback/token/profile operation | Existing OAuth success or failure result. | Safe provider-operation failure; no new page or Egress control. | None. |
| Operator diagnostics | Existing authorized diagnostic channel may include safe reason, correlation ID and restricted private detail. | Same. | Cannot change the policy result. |

## Explicit authority prohibitions

The UI cannot override Egress policy, enable private networks, follow a
server-side redirect or forward credentials on a redirect.

The browser OAuth authorization redirect is an external handoff and remains
outside server-side Egress admission. It does not authorize the browser to
change a server-side network decision. OAuth callback context binding remains
the RC3-08 boundary.

## Canonical UI model decision

No visible interaction, state node, route, page or navigation is added by this
architecture package. Therefore:

The gate is `PASS`: the current UI YAML is unchanged; there is no new page,
navigation area, browser authority, Egress override or private-network UI
override.

The Owner Review acceptance is recorded in the
RC3-07 Owner Review record.
If a separately authorized implementation changes an actual visible state or
message, it must update the canonical YAML, schema-compatible generated views,
selectors and UI evidence in the same governed change. This architecture-only
package does not pre-authorize that work.
