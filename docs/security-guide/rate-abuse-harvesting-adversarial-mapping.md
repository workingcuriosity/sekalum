---
title: Rate Abuse and Harvesting Adversarial Mapping
document_id: DOC-SECURITY-RATE-ABUSE-HARVESTING-ADVERSARIAL-MAPPING
version: 1.2.0
classification: PUBLIC
language: en
status: Accepted
category: Security
canonical: true
owner: Sekalum
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Security reviewers
  - Maintainers
  - Test engineers
  - Operators
approved_by: Project Owner / Repository Maintainer
dependent_documents:
  - docs/adr/ADR-032-Rate-Limit-Abuse-and-Harvesting-Baseline.md
  - docs/architecture/RATE_ABUSE_HARVESTING_PATH_MATRIX.md
  - docs/security-guide/index.md
  - docs/project/issue-execution/RC3-09_RATE_ABUSE_IMPLEMENTATION_WORK_PACKAGE.md
  - docs/project/issue-execution/IEP-rc3.md
change_history:
  - version: 1.2.0
    date: 2026-09-04
    change: Records the bounded RC3-09 implementation and exact ABUSE-ATTACK-001 through ABUSE-ATTACK-015 registry bindings; candidate-bound certification evidence remains in the implementation receipt and Hacker result.
  - version: 1.1.0
    date: 2026-09-04
    change: Records Owner Review PASS, accepts semantic distinctness and coverage of planned ABUSE-ATTACK-002 through ABUSE-ATTACK-015, and confirms no registry mutation or execution.
  - version: 1.0.0
    date: 2026-09-04
    change: Maps RC3-09 abuse threats to required invariants and future adversarial cases; no registry mutation or execution is authorized.
---

# Rate, Abuse and Harvesting Adversarial Mapping

This is a public-safe threat and implementation mapping, not execution
evidence. The existing registry entry `ABUSE-ATTACK-001` remains the
registry-owned Resolve/Discovery harvesting baseline and is reused without
duplication. `ABUSE-ATTACK-002` through `ABUSE-ATTACK-015` are now registered
with exact implementation/test bindings under RC3-09. This mapping does not
itself claim candidate certification PASS; the implementation receipt and
clean-candidate Hacker result are authoritative for that outcome.

## Required invariants

| Invariant | Required property | Evidence required later |
|---|---|---|
| `ABUSE-ADMISSION-001` | every protected path reaches the correct pre-parser, identity or cost boundary | route-to-policy trace and negative bypass tests |
| `ABUSE-BOUND-001` | body, keys, leases, cleanup and retry time remain bounded | state/lease/cleanup stress evidence |
| `ABUSE-IDENTITY-001` | raw client headers, raw tokens and arbitrary input never become authority keys | proxy, IPv4/IPv6 and malformed-key tests |
| `ABUSE-COST-001` | batch and expensive operations pay weighted cost | single-vs-batch and invalid-shape tests |
| `ABUSE-ENUMERATION-001` | throttle and failure responses do not disclose existence | present/absent/unauthorized equivalence tests |
| `ABUSE-AUDIT-001` | rejection cannot amplify audit/storage work | coalescing and failure-mode tests |
| `ABUSE-CONTAINMENT-001` | revocation and containment retain separate admission access | exhausted ordinary bucket plus revoke test |
| `ABUSE-RETRY-001` | Retry-After is bounded and no hidden retry loop exists | clock, response and client-behavior tests |

## Implemented adversarial cases

| Case | Attack chain | Required control | Status |
|---|---|---|---|
| `ABUSE-ATTACK-001` | repeated invalid/broad Resolve or Discovery requests amplify work for harvesting | central composed admission, Consumer and batch cost, safe response | `REUSED / IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-002` | raw `X-Forwarded-For` rotation bypasses a source budget | trusted proxy/socket source semantics and canonical digest key | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-003` | IPv4, IPv6 or mapped-IPv6 spellings create unbounded source buckets | canonical address normalization and bounded domains | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-004` | invalid bearer values become unique limiter keys and exhaust state | fixed reason/source keys; no raw token key | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-005` | unauthenticated credential/resource probing reveals existence through throttle differences | uniform safe 429/error projection | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-006` | 20-item batch is charged as one request or invalid items are free | weighted cost 1..20 and invalid-shape max charge | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-007` | parallel batch fan-out exceeds worker/resource bounds | batch concurrency reservation and lease | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-008` | OAuth invalid callbacks trigger provider exchange or audit amplification | invalid-callback phase admission, no exchange, coalesced audit | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-009` | repeated OAuth start or valid callback creates provider work burst | provider/actor cost and concurrency policy | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-010` | management mutation burst changes users/grants/providers/tokens | actor/source mutation budget with existing authz | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-011` | expensive health/provider operation bypasses Central Egress admission | rate/concurrency admission before operation and Central Egress before I/O | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-012` | attacker exhausts ordinary budget and blocks token revoke or containment | separate high-priority containment budget | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-013` | limiter key churn evicts active identities or grows without bound | quotas, TTL, cleanup and shared overflow bucket | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-014` | process restart or clock manipulation grants unbounded admission | injected clock, restart reset evidence, no request-supplied time | `IMPLEMENTED / REGISTERED / PASS` |
| `ABUSE-ATTACK-015` | client retries every 429 immediately, server retries internally or an attack flood displaces useful audit evidence | bounded Retry-After, no automatic mutation retry, coalescing and audit-priority/overflow control | `IMPLEMENTED / REGISTERED / PASS` |

## Evidence and registry boundary

Each future case must bind its exact route, phase, policy class, key domain,
cost and expected safe outcome. It must demonstrate that an admitted request
still passes existing authentication/authorization and that a blocked request
does not trigger derivation, provider egress, mutation or secret-bearing
audit. Recovery and restart cases must freshly reconstruct policy inputs.

The existing `scripts/security/attack-registry.json` entry
`ABUSE-ATTACK-001` is reused, and the implementation authority registered
`ABUSE-ATTACK-002` through `ABUSE-ATTACK-015` with static test references.
Registry validation and focused case execution are recorded separately. No
threshold telemetry, raw identities or secret-bearing evidence is included in
this public mapping.

## Public safety boundary

This mapping contains no tokens, client secrets, raw addresses, live provider
endpoints, account data, bucket identifiers or threshold telemetry. A public
projection may retain only the generic `RATE_LIMITED` contract and aggregate
architecture status.
