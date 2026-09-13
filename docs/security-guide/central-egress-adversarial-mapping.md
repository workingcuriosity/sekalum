---
title: Central Egress Adversarial Mapping
document_id: DOC-SECURITY-CENTRAL-EGRESS-ADVERSARIAL-MAPPING
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
  - docs/adr/ADR-030-Central-SSRF-and-Egress-Policy.md
  - docs/architecture/CENTRAL_EGRESS_PATH_MATRIX.md
  - docs/security-guide/index.md
  - docs/project/issue-execution/IEP-rc3.md
change_history:
  - version: 1.2.0
    date: 2026-09-03
    change: Records RC3-07 implementation and candidate-bound PASS evidence for SSRF-ATTACK-002 through SSRF-ATTACK-014; the executable registry now contains the authorized RC3-07 release-gate cases.
  - version: 1.1.0
    date: 2026-09-03
    change: Records Owner Review acceptance of the adversarial architecture mapping; SSRF-ATTACK-002 through SSRF-ATTACK-014 remain planned, unregistered, unexecuted and non-passing until separate implementation authorization.
  - version: 1.0.1
    date: 2026-09-03
    change: Clarifies SSRF-ATTACK-011 against the three permitted FTP/SFTP purposes and RFC1918/ULA-only exception scope; hard blocks and all OAuth/shared-HTTP paths remain non-overridable.
  - version: 1.0.0
    date: 2026-09-03
    change: Prepares the RC3-07 attack-to-invariant mapping for address classification, DNS rebinding, redirects, credential forwarding, ports, schemes, exceptions and resource bounds; cases 002–014 remain unimplemented and unregistered.
---

# Central Egress Adversarial Mapping

This is a public-safe implementation map for RC3-07. `SSRF-ATTACK-001` remains
the historical baseline; `SSRF-ATTACK-002` through `SSRF-ATTACK-014` are now
registered and executable under the separately authorized RC3-07
implementation. PASS means the exact Hacker runner test passed on the exact
candidate; it does not authorize release or deployment.

| Case | Attack chain | Invariant/control | Regression assertion | Status |
|---|---|---|---|---|
| `SSRF-ATTACK-001` | Existing connection-target input reaches local/private address | Existing `ConnectionTargetPolicy` baseline | Existing unit coverage rejects local/private targets by default. | `EXISTING_IMPLEMENTED / REGISTRY_UNCHANGED` |
| `SSRF-ATTACK-002` | IPv6 loopback, ULA or link-local literal/answer bypasses IPv4-only rules | `EGRESS-ADDRESS-001`, `EGRESS-DEFAULT-DENY-001` | Loopback/link-local always block; ULA follows only the bounded private exception. | `PASS` |
| `SSRF-ATTACK-003` | IPv4-mapped IPv6 spelling bypasses IPv4 policy | `EGRESS-ADDRESS-TRANSLATION-001` | `::ffff:private` and expanded mapped forms receive the embedded IPv4 decision. | `PASS` |
| `SSRF-ATTACK-004` | NAT64 or embedded private IPv4 bypasses address classification | `EGRESS-ADDRESS-TRANSLATION-001` | Well-known NAT64 applies IPv4 policy; unsupported translated forms block. | `PASS` |
| `SSRF-ATTACK-005` | Mixed DNS answers include public and blocked addresses; caller selects public answer | `EGRESS-DNS-PINNING-001` | Any blocked, unknown or unclassifiable answer blocks the whole hostname. | `PASS` |
| `SSRF-ATTACK-006` | DNS check resolves public address, connect re-resolves to private address | `EGRESS-DNS-REBIND-001` | Core-owned DNS result is pinned; transport cannot uncontrolled re-resolve. | `PASS` |
| `SSRF-ATTACK-007` | Admitted public target redirects to private or forbidden target | `EGRESS-REDIRECT-001` | Server-side redirect is denied; a future hop requires fresh admission. | `PASS` |
| `SSRF-ATTACK-008` | Redirect or origin change forwards bearer/client secret/body | `EGRESS-CREDENTIAL-FORWARDING-001` | Credential-bearing material is sent only after admission and never implicitly forwarded across a target change. | `PASS` |
| `SSRF-ATTACK-009` | Forbidden scheme, userinfo, encoded host or parser confusion reaches transport | `EGRESS-HOST-IDENTITY-001`, `EGRESS-SCHEME-001` | Structured parsing rejects ambiguous authority and non-admitted schemes before I/O. | `PASS` |
| `SSRF-ATTACK-010` | Non-default or alternate port bypasses host-only allowlist | `EGRESS-PORT-001` | Protocol-aware port policy evaluates host, admitted address, protocol and port together. | `PASS` |
| `SSRF-ATTACK-011` | Private exception for an FTP/SFTP operation escapes to OAuth/shared HTTP, an unapproved purpose or another CIDR/port | `EGRESS-EXCEPTION-001` | Exception is limited to FTP/SFTP purposes `CREDENTIAL_CONNECTION_TEST`, `PROVIDER_VALIDATION` and `PROVIDER_HEALTH_CHECK`, RFC1918/ULA and configured hostname/CIDR/port scope; hard blocks remain non-overridable. | `PASS` |
| `SSRF-ATTACK-012` | Provider, OAuth service, metadata path or future hook opens network without Core admission | `EGRESS-POLICY-001` | No product network attempt is possible without an `EgressRequestContext` and Core result. | `PASS` |
| `SSRF-ATTACK-013` | Provider returns oversized body and parser consumes it without a bound | `EGRESS-RESOURCE-BOUNDS-001` | Response is bounded before parsing and returns `EGRESS_RESPONSE_LIMIT_EXCEEDED`. | `PASS` |
| `SSRF-ATTACK-014` | Hidden retry repeats a blocked or rebinding attempt without re-admission | `EGRESS-RETRY-001` | Retry budget is finite; every attempt re-enters Core policy and no hidden unbounded loop exists. | `PASS` |

## Evidence boundary

This mapping is not an executable source. The registry at
`scripts/security/attack-registry.json`, the Hacker runner and tests provide
the executable evidence. Public output contains only aggregate status and
safe reason families; private resolver addresses, headers, tokens and bodies
remain excluded.

The baseline `SSRF-ATTACK-001` is existing and implemented. Cases
`SSRF-ATTACK-002` through `SSRF-ATTACK-014` are implemented and registered by
the RC3-07 authorization; all thirteen pass their exact test references on the
candidate reported by the IEP.

The Owner Review accepts this mapping as a non-executable architecture
projection; the acceptance record is
RC3-07 Owner Review and Architecture Institutionalization.
