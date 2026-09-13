---
title: Security Guide
document_id: DOC-SECURITY-GUIDE-INDEX
classification: PUBLIC
language: en
version: 1.22.0
status: Active
category: Security
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Betreiber
  - Entwickler
  - Auditoren
dependent_documents:
  - SECURITY.md
  - docs/api-reference/index.md
  - docs/configuration-reference/index.md
  - docs/adr/ADR-027-Authorization-Identifier-Canonicalization.md
  - docs/adr/ADR-028-Revoke-First-Decommissioning-and-Orphan-Safety.md
  - docs/adr/ADR-029-Restore-Anti-Rollback.md
  - docs/adr/ADR-030-Central-SSRF-and-Egress-Policy.md
  - docs/adr/ADR-031-OAuth-Context-Binding.md
  - docs/adr/ADR-032-Rate-Limit-Abuse-and-Harvesting-Baseline.md
  - docs/security-guide/oauth-context-binding-adversarial-mapping.md
  - docs/security-guide/rate-abuse-harvesting-adversarial-mapping.md
change_history:
  - version: 1.22.0
    date: 2026-09-13
    change: Adds the stable public Security Assurance Methodology and standards-alignment, risk-evaluation and audit-evidence boundaries for current and future assessments.
  - version: 1.21.1
    date: 2026-09-06
    change: Clarifies the deployment-unique Bootstrap proof contract: missing, shipped/example or documentation-placeholder values are invalid; runtime enforcement remains separately authorized.
  - version: 1.21.0
    date: 2026-09-06
    change: Adds the public-safe RC3-12 anti-framing response contract and derives phase-separated pre-auth, authenticated operational and containment admission capacity; runtime implementation remains separately unauthorized.
  - version: 1.20.0
    date: 2026-09-05
    change: Completes the RC3-10 Basic Consumer safe-use projection with an explicit Secret-sprawl destination list, logical credentialKey versus version/material guidance, rotation and revocation handling, and the external-runtime no-store boundary.
  - version: 1.19.0
    date: 2026-09-04
    change: Adds public-safe RC3-09 guidance for bounded process-local abuse admission, trusted source identity, weighted work, separate containment access, generic 429 responses and bounded Retry-After without threshold or identity disclosure.
  - version: 1.18.0
    date: 2026-09-04
    change: Adds public-safe RC3-08 OAuth Context Binding guidance for transaction, client, provider evidence, scope, Credential and refresh binding; planned adversarial cases remain unregistered and unexecuted.
  - version: 1.17.0
    date: 2026-09-03
    change: Records the implemented RC3-07 Core Egress runtime boundary, candidate-bound SSRF regressions and the unchanged public-safe/no-override contract.
  - version: 1.16.2
    date: 2026-09-03
    change: Records the RC3-07 Owner Review acceptance of the public-safe central Egress projection; ADR-030 remains the canonical policy owner and implementation remains separately unauthorized.
  - version: 1.16.1
    date: 2026-09-03
    change: Clarifies that the bounded RFC1918/ULA private exception applies to FTP/SFTP connection-test, validation and health purposes only; hard blocks, OAuth/shared HTTP and browser overrides remain excluded.
  - version: 1.16.0
    date: 2026-09-03
    change: Adds public-safe central Egress/SSRF guidance for DNS pinning, address classification, scheme/port/redirect/credential/resource bounds, private exceptions and future-hook fail-closed behavior; no runtime implementation is authorized.
  - version: 1.15.0
    date: 2026-09-03
    change: Records the implemented RC3-06 restore anti-rollback runtime boundary and candidate-bound adversarial verification while preserving the no-override and public-safe result contract.
  - version: 1.14.0
    date: 2026-09-03
    change: Adds public-safe restore anti-rollback guidance: current-state authority, terminal/tombstone and generation barriers, read-only preflight, final revalidation, atomicity and no Restore-anyway override; this guidance does not claim runtime implementation.
  - version: 1.13.0
    date: 2026-09-02
    change: Adds public-safe revoke-first decommissioning, zero-authority orphan handling, no-resurrection guidance and dependency-safe deletion from ADR-028; this guidance does not claim runtime implementation.
  - version: 1.12.0
    date: 2026-09-01
    change: Documents public-safe domain-aware authorization-identifier semantics and the canonical ADR-027 ownership boundary without authorizing implementation.
  - version: 1.11.0
    date: 2026-08-31
    change: Adds public Basic guidance for minimum Consumer scope, Secret-sprawl minimization and the external-runtime responsibility boundary.
  - version: 1.10.0
    date: 2026-08-31
    change: Documents the Core-derived Consumer Access Scope and Credential reverse projections, effective-Grant counting and secret-free preview boundary.
  - version: 1.9.0
    date: 2026-08-30
    change: Documents the public adversarial security-regression layer and its deterministic execution boundary.
  - version: 1.8.0
    date: 2026-08-27
    change: Defines bounded Credential transfer import admission and atomic batch persistence together with the combined 30-day UTC-instant Audit retention boundary, legacy convergence and fail-closed Resolve audit finalization.
  - version: 1.7.0
    date: 2026-08-27
    change: Defines fixed 24-hour Secret-Version retention, fail-closed rollback, and immediate terminal history invalidation.
  - version: 1.6.3
    date: 2026-08-26
    change: Defines the proof-of-possession and atomicity requirements for the one-time First Administrator Bootstrap boundary.
  - version: 1.6.2
    date: 2026-08-24
    change: Records explicit English as the current governed documentation language.
  - version: 1.6.1
    date: 2026-08-24
    change: Completes the canonical header metadata for the current documentation source.
  - version: 1.6.0
    date: 2026-08-04
    change: Adds neutral deployment security recommendations for publicly reachable Admin installations without changing the product security model.
  - version: 1.5.0
    date: 2026-08-01
    change: Consolidates the existing Consumer Trust Boundary and the security responsibility split between Sekalum and Consumer Runtime.
  - version: 1.4.0
    date: 2026-07-17
    change: Defines the declarative custom-provider onboarding security boundary.
---

# Security Guide

## Security Assurance Methodology and Standards Alignment

Sekalum applies relevant criteria and methods from internationally recognized
security standards, frameworks and methodologies within the defined assurance
scope. This methodology applies to current and future security assessments,
release candidates and releases unless the canonical Security Governance
standards basis is changed through normal governance.

The standards and method basis is:

| Standard, framework or methodology | Assurance use within scope |
|---|---|
| NIST SSDF SP 800-218 | Secure development and vulnerability-response process context |
| NIST SP 800-55 | Security measurement purpose, quality, provenance, timeliness and uncertainty |
| ISO/IEC 27005 | Risk evaluation, treatment, ownership and residual-risk review |
| OWASP Risk Rating Methodology | Application likelihood, impact and contextual risk factors |
| OWASP SAMM | Application-security process, verification, defect management and remediation |
| OWASP ASVS | Applicable verification scope and requirement-based assurance |
| MITRE CWE | Weakness classification |
| FIRST CVSS v4.0 | Technical vulnerability severity where applicable |
| FIRST EPSS | Exploitation-probability signal for applicable public CVEs only |
| CISA KEV | Known-exploitation signal for applicable public CVEs only |
| OWASP Benchmark / NIST SAMATE | Scanner-effectiveness measurement where applicable |
| OpenSSF Scorecard | Repository and supply-chain posture as a separate measurement dimension |

These sources have distinct purposes and are interpreted together within the
defined scope. CVSS is not a complete risk score; scanner severity is not a
complete risk score; EPSS is not a complete risk score; KEV is not a complete
risk score; and a security KPI is not an automatic release decision.

### Finding and risk evaluation

Finding evaluation is not based on scanner severity alone. The assessment
considers technical severity, likelihood, impact, exploitability where
evidenced, attack preconditions, reachability or exposure where evidenced,
compensating controls, control effectiveness, inherent risk, residual risk,
risk treatment and the required risk-owner decision. ISO/IEC 27005 provides
the risk-management basis, OWASP Risk Rating provides application
likelihood/impact context, and CVSS v4.0 provides technical severity context
where applicable. Public guidance does not disclose private finding records
or private risk-owner evidence.

### Audit and Certification Evidence Readiness

Sekalum security-assurance evidence is collected and maintained using
traceable, versioned and standards-aligned methods. Where applicable, the
evidence structure includes:

- assessment identity and scope;
- evidence provenance;
- vulnerability classification;
- technical severity;
- likelihood and impact;
- assumptions and uncertainty;
- risk treatment;
- residual risk;
- risk-owner decisions;
- review and revalidation state; and
- candidate or release binding.

This structure is intended to allow existing assurance evidence to be reused
as input to a future formal audit, assurance or certification program. Such a
program would still require the certification scheme's exact scope, control
mapping, gap assessment, organization and process evidence, and its
independent audit or certification procedure.

Sekalum currently claims standards-aligned methods. It does not claim ISO,
NIST or OWASP certification, formal full compliance, or third-party
certification. No certification or compliance status is implied by this
guide.

## Deployment Security Recommendations

Sekalum's Admin UI should not be exposed to the public Internet
without an additional operator-controlled protection layer. This section
documents deployment recommendations only; Sekalum does not implement
or configure these controls.

### Public Admin UI and reverse proxy

For a publicly reachable installation, place a reverse proxy in front of the
Admin UI and Management API. Use TLS for the public connection and route only
the intended public service paths. Preserve the configured `BASE_PATH` for the
Admin UI, health endpoint, REST API and OAuth callback. The [Installation
Guide](../installation-guide/index.md#base-path-and-reverse-proxy-deployment)
contains neutral path-preserving examples; it does not require a particular
proxy product.

Do not treat a reverse proxy as an application login. It is an operator-
controlled network and transport boundary in front of Sekalum.

### Application UI anti-framing boundary

Browser-rendered Sekalum application responses, including `/admin`,
application UI responses and management application responses, must not be
embedded by another origin. The application response contract is:

| Contract key | Required value |
|---|---|
| `APPLICATION_UI_FRAME_EMBEDDING` | `DENY` |
| `CONTENT_SECURITY_POLICY_FRAME_ANCESTORS` | `'none'` |
| `X_FRAME_OPTIONS` | `DENY` |

The separately authorized implementation must emit
`Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`
for those responses. A reverse proxy must preserve these protections and must
not relax them. This normative contract does not claim that the current runtime
has implemented the headers; implementation requires separate authority. The
control does not replace authentication, authorization, TLS or operator network
controls, and it does not alter Management Token storage or the authentication
model.

### VPN and network allow-lists

A VPN can restrict Admin access to an authenticated private network and may
be used to keep the Admin UI off the public Internet. An operator may also
limit Admin and Management API access to known source IP addresses through an
IP allow-list. The appropriate VPN, network, firewall or routing mechanism
depends on the deployment and is not defined by Sekalum.

### Identity-aware proxy

An identity-aware proxy can add an operator-managed identity and access layer
before requests reach Sekalum. Examples include Cloudflare Access,
Tailscale Funnel Access, Microsoft Entra Application Proxy and comparable
identity-aware proxy services. These are examples rather than product
recommendations; the operator remains responsible for selecting, configuring
and operating the control.

### HTTP Basic Authentication

A reverse proxy may require HTTP Basic Authentication as an additional
protection layer in front of `/admin` and the protected Management API paths.
Sekalum does not process that credential as an application login and
does not replace the proxy's access-control configuration. Protect the Basic
Authentication credential with the same care as other deployment secrets.

### Management Token boundary

The Management Token protects the application layer: after Bootstrap, the
Management API requires an authorized token sent as
`Authorization: Bearer <management-token>`. The token does not replace
network security, TLS, VPN access, source-IP restrictions or an
identity-aware proxy. Do not expose or transport it through URLs, source
control, screenshots or logs.

### First Administrator Bootstrap boundary

An empty persisted user collection is state, not identity. The one-time
`POST /api/v1/management/users` Bootstrap operation requires the configured
`ADMIN_BOOTSTRAP_TOKEN` proof in `X-Admin-Bootstrap-Token`. The value must be a
deployment-unique, operator-supplied high-entropy secret of at least 32 bytes.
Missing, shipped/example, documentation-placeholder, weak or incorrect proof
fails closed. The Bootstrap proof is not a Management Token, is not an API
token, is not derived from `TOKEN_ENCRYPTION_KEY`, and is never returned,
logged, audited or persisted as a token. Only one active `admin` First
Administrator may be created. The empty-state check and persistence are one
serialized security operation, and Bootstrap is permanently closed after the
first user is persisted. Normal management access then requires Bearer
authentication, scope validation and RBAC. Reverse-proxy and forwarding
headers do not replace this proof.

```text
ADMIN_BOOTSTRAP_TOKEN_DEPLOYMENT_UNIQUE: REQUIRED
KNOWN_EXAMPLE_BOOTSTRAP_TOKEN: INVALID
PLACEHOLDER_BOOTSTRAP_TOKEN: INVALID
MISSING_BOOTSTRAP_TOKEN: INVALID
```

Length or character-count compliance alone is insufficient. Bootstrap
admission requires a configured value that meets the existing strength
requirement, is not any shipped/example/documentation placeholder, and is
deployment-unique. Runtime admission rejects low-diversity, repeated-pattern
and monotonic values, and requires a minimum measured byte entropy in addition
to the 32-byte floor: at least 8 distinct UTF-8 bytes, at least 3.5 bits of
Shannon entropy per byte, no repeated pattern of period 16 bytes or less, and
no monotonic run of 8 bytes or more. Sekalum supplies no automatic default
Bootstrap token. This is the canonical Bootstrap contract.

### Deployment responsibility boundary

Sekalum defines application authentication, authorization and API
protection. The operator remains responsible for network segmentation,
firewalls, VPNs, reverse proxies, TLS termination, public routing and any
identity provider or identity-aware proxy used in front of the service.

For local trusted use, keep Bootstrap and the first Administrator setup
restricted to the local machine before exposing the service beyond that
boundary. For public deployment, apply the additional operator controls above
and verify the public Admin UI, Management API, health endpoint and OAuth
callback through the configured deployment path.

## Consumer Trust Boundary

The Consumer API is the security boundary between Sekalum and an
authenticated Consumer Runtime. This section consolidates the existing
responsibility split defined by ADR-020, the API Reference and the WP5.6 live
validation handover. It introduces no new API, security rule or architecture
decision.

### Sekalum responsibility

Sekalum is responsible for the security controls within its boundary:

- authenticating the Consumer request;
- authorizing access through the applicable Consumer Grant;
- checking that the requested Secret fields are explicitly permitted;
- checking Credential lifecycle and consumability;
- resolving only the controlled, authorized Secret selection; and
- enforcing the documented authenticated API boundary and secret-free audit
  evidence handling.

Sekalum returns only the authorized result through the existing
Consumer API contract. Discovery and Runtime-Public projection remain subject
to their existing grant, classification and projection rules. Resolve remains
the operation for explicitly requested Secret fields.

The Admin Consumer permissions page explains these existing boundaries for
administrators. Its labels and help text are informational only; they do not
change authorization, grants, Discovery, Resolve or Runtime-Public behavior.
The Grant Preview and Permission Summary are likewise read-only explanations:
they display selected and excluded field names without executing Discovery or
Resolve, exposing Secret values, or changing the server-side grant.

The Consumer Permissions page obtains current scope, create/edit deltas and
Credential reverse access from Core projections. Scope is calculated from the
authenticated Consumer identity, effective Grant bindings, Credential
lifecycle and provider field contract. The projection may show permitted
Secret field names and factual counts, but never Secret values, bearer tokens,
or management data. A preview is not an authorization decision and cannot be
replayed as proof for a later mutation.

### Basic Consumer scope and Secret-sprawl minimization

For Basic/Open Source use:

- use the smallest practical Consumer identity boundary for one application or workload trust domain;
- do not use one universal Consumer identity for unrelated workloads merely for convenience;
- grant only the Credentials and Secret fields required by that workload;
- revoke unused Consumers and Grants;
- resolve only the named Secret fields needed for the next operation and pass them directly to the target operation where practical;
- avoid copying resolved values into ordinary workflow or application state, static or pinned workflow data, Set/Edit Fields data, Code-node constants, logs, debug output, execution output, retry payloads, browser storage or other durable downstream state; and
- prefer provider-native short-lived credentials where available.

The safe-use sequence is:

```text
dedicated Consumer identity and token
  → minimum Grant and named Secret fields
  → Discovery
  → stable logical credentialKey
  → explicit Resolve fields
  → immediate target operation
  → runtime-owned disposal
```

Do not place resolved values in URLs or query strings, source control,
workflow exports, screenshots or recordings. A `credentialKey` is a stable
logical selection reference; it is distinct from a server-side Secret Version
and from Secret material. Rotation may replace material behind the same valid
logical reference without a workflow rewrite. Revocation, deactivation or
Grant removal blocks future Resolve and does not authorize a cached plaintext
fallback.

Sekalum controls authorization and delivery. Once an authorized external
runtime receives a long-lived Secret, Sekalum cannot guarantee that the runtime
forgets or does not persist it. `Cache-Control: no-store`, browser cleanup and
Grant revocation do not guarantee erasure from an external workflow, queue,
execution history or log. This is an honest responsibility boundary, not
permission to retain, log or transmit Secret values.

## Revoke-first and orphan safety

The ADR-028
architecture requires access containment before cleanup. Revocation or delete
therefore blocks Consumer authorization first; provider, Grant and Secret
history cleanup may complete later and may be retried idempotently. A pending
cleanup result is not a failed containment result.

Terminal, missing or stale Credentials and Grants have zero authority. Grant
bindings are exact to a Credential identity and generation; they are never
rebound by provider key, restore or re-import. A deletion tombstone preserves a
minimal identity barrier so a former identity cannot silently become usable.
Provider and Provider Configuration deletion must respect exact dependencies;
operators should resolve those dependencies explicitly rather than relying on
an implicit cascade. Management diagnostics may report safe status, counts and
stable error codes, but must not expose Secrets, bearer material or raw
provider errors.

These are public-safe architectural rules. They do not claim that the current
OSS runtime has implemented the RC3-05 decommissioning workflow; implementation
requires a separate authorization and its own terminal evidence.

## Restore anti-rollback

Historical restore and import input is not authoritative merely because it is
valid, complete or older. The current Core security state wins at final
revalidation. A revoked or deleted Credential, revoked API token, deleted
principal, tombstoned identity, stale generation or exact Grant-binding
mismatch remains blocked; a provider key or display name never creates an
implicit rebind.

Restore review is read-only. Core checks the complete candidate against current
identity lines, terminal barriers, opaque UUID generations, exact bindings and
the actor's current authority. A later mutation must repeat that check inside
the authority-bearing commit boundary. If state changes between review and
commit, the operation fails closed and requires a new review. A restore path
that cannot commit atomically must not make a partial authority change.

The public-safe result vocabulary is `CAN_RESTORE`, `CONFLICTS`, `BLOCKED` and
`NEEDS_RE_CHECK`. Non-terminal role/status/metadata differences may require an
explicit administrative resolution; terminal security barriers have no
override. No “Restore anyway” option is valid. See the [RC3-06 adversarial
mapping](restore-anti-rollback-adversarial-mapping.md) for the exact registered
regression cases and their candidate-bound status.

The current runtime implements this bounded contract across management backup
restore, Credential import, Secret-Version rollback and the legacy provider
token path. API-token and Grant restore remain fail-closed future hooks; no new
backup contents or routes are introduced. Terminal evidence is valid only for
the exact candidate reported by the IEP.

## Central Egress and SSRF boundary

All server-initiated provider, OAuth and Credential connection paths must use
one Core-owned Egress Policy. Core resolves DNS, inspects every answer and
binds the transport to the admitted address while preserving the original
hostname for protocol verification. A fixed provider hostname is not proof
that its resolved address is safe.

Loopback, link-local, cloud metadata, unspecified, multicast, reserved/special,
CGNAT and unclassifiable addresses are hard blocked. RFC1918 and IPv6 ULA are
denied by default and may be allowed only by a narrow operator/deployment
exception for the bounded FTP/SFTP connection-test, validation and health
purposes. The existing
`CONNECTION_TEST_ALLOW_PRIVATE_NETWORKS` setting is not a universal network
permission and is not a browser control. Mixed DNS answers fail closed;
IPv4-mapped IPv6 and well-known NAT64 apply the embedded IPv4 policy.

Provider HTTP uses HTTPS in its declared protocol class, denies redirects by
default and does not forward bearer values, client secrets or bodies to a
changed target. FTP and SFTP are separate connector classes. Ports are part of
destination identity. Connect/operation time, response bodies, retries and
cleanup are bounded, and every retry requires a new policy admission.

These rules are implemented by the RC3-07 Core Egress runtime. The
[RC3-07 adversarial mapping](central-egress-adversarial-mapping.md) records
the exact registered and candidate-bound regression cases. Release and
deployment authorization remain separate.

## Rate, Abuse and Harvesting boundary

The current server applies one bounded, process-local admission boundary to
protected management, Consumer, OAuth and provider-work paths. Trusted source
identity is derived from the server socket and configured framework proxy
semantics; raw client forwarding headers, bearer values and arbitrary request
content are not authority keys. Admission happens before JSON body parsing and
is followed by the existing authentication, authorization, validation and
Central Egress boundaries.

The implementation composes source, authenticated actor, Consumer, token and
provider dimensions where applicable. The separately authorized RC3-12
implementation must use a distinct pre-auth global budget that cannot debit
authenticated operational or reserved security-containment capacity. An
unauthenticated request to a containment path must remain a pre-auth failure;
only an authenticated, authorized containment operation may use the
independently reserved containment budget. This normative architecture does
not claim that the current runtime has implemented the separation. Batch and
other amplified operations pay bounded weighted cost, concurrency leases expire
locally, and state uses quotas, cleanup and overflow handling. Restart resets
process-local state and does not make a cluster-wide consistency claim.

When a protected request is denied, the existing surfaces receive only a
generic `429 RATE_LIMITED` result with a positive bounded `Retry-After` and
`Cache-Control: no-store`. The result does not disclose resource existence,
source identity, token material or limiter thresholds. The Admin and Consumer
clients show bounded retry guidance but do not automatically replay mutation
requests. The [RC3-09 adversarial mapping](rate-abuse-harvesting-adversarial-mapping.md)
records the registered cases; candidate-bound evidence remains separate from
this public guide.

## Adversarial security regression layer

Sekalum maintains a public, repository-native adversarial regression registry
for implemented security guarantees. The registry maps an attack chain to the
security invariant, trust boundary, implementation control and exact normal
test case that verifies it. It covers representative Consumer/Grant isolation,
lifecycle terminality, Secret-safe diagnostics and response projections,
authentication-plane separation, OAuth context handling and connection-target
egress restrictions.

The runner uses only validated, static test references and Node's normal test
runtime. It does not evaluate registry entries as code, execute a shell, load
remote code or accept arbitrary file paths. A release-gate execution emits a
candidate-bound JSON result with explicit pass/fail status. Deferred families
remain marked as not implemented and cannot be treated as passing controls.
The runner rejects a dirty Git worktree before execution so the reported
candidate SHA cannot silently differ from the tested source content.

## Authorization-identifier safety

Security-relevant identifiers and selectors have one authoritative domain
contract. Core validates that contract; it does not apply a global trim,
lowercase or Unicode repair pass. Search/display normalization is separate from
authorization identity, provider-owned references remain opaque, and transport
decoding occurs once before domain validation. Alternate representations that
are invalid, ambiguous or colliding are denied with an explainable result.

These public-safe rules are governed by
ADR-027.
The rule does not authorize automatic collision resolution, silent legacy
rewrites or browser-side authorization decisions.

## Credential materialization boundary

Credential metadata and Credential Secret values use separate projections. The
normal `metadata.custom` namespace is an explicit allowlist, and arbitrary or
nested custom values are rejected at write boundaries. Sensitive application
metadata belongs in the separate `sensitiveMetadata` namespace; it is retained
only for the authorized internal operation and is never included in any safe
metadata, Consumer, Runtime-Public, CLI, log or diagnostic projection.
following inventory is the canonical boundary for Credential reads:

| Path | Secret materialization | Justification |
| --- | --- | --- |
| `Credential.toMetadataJSON()` | No | Public list, status, presentation and discovery metadata only. |
| `Credential.toInternalMetadataJSON()` and `credential-metadata.json` | No | Encrypted routing/profile index; no secrets and no `sensitiveMetadata`. |
| `ManagementService.getCredentials()` | No | Management summary and lifecycle counts use metadata only. |
| `DashboardService.getDashboard()` | No | Dashboard status, provider counts and health summaries use metadata only. |
| `CredentialController.list()` / `get()` | No | Admin list/detail and secret inventory expose no Secret values. |
| `ConsumerCredentialService.discover()` | No | Discovery returns the existing public field contract and metadata. |
| `ConsumerCredentialService.resolve()` | Yes, exact Credential only | Authenticated Consumer Grant and requested Secret fields require values. |
| `ConsumerGrantService` validation | No | Grant validation checks metadata, method bindings and Secret field names. |
| `CredentialManager` lifecycle / validation / OAuth refresh | Yes, targeted Credential | The authorized provider operation requires the corresponding values. |
| Secret version, transfer, backup and restore services | Yes, explicit operation | Versioning, export/import and recovery are secret-bearing administrative operations. |
| Logging, audit, diagnostics and provider display lookup | No | These paths use safe diagnostics and public provider/credential metadata. |

Secret-Version history is bounded to a fixed 24-hour window from `createdAt`.
Only non-terminal Credentials may use an eligible historical version. Expiry,
malformed timestamps, terminal deletion, terminal revoke, and terminal
invalidation make historical values unavailable at the application boundary;
invalidation failures prevent the terminal operation from succeeding. Audit
records remain metadata-only. This does not provide physical secure erase or
retroactive cleanup of offline/legacy backups, which are separate retention
boundaries.

### Credential transfer import boundary

Credential transfer import is a secret-bearing administrative boundary and is
bounded before cryptographic admission. The input limit is `5242880` UTF-8
bytes and the record limit is `100`. PBKDF2-SHA256 remains fixed at `210000`
iterations for AES-256-GCM transfers, with no more than two concurrent import
KDF operations. Excess work is rejected immediately; imports do not queue or
retry automatically.

The importer validates all records before persistence and applies creates and
overwrites as one atomic batch. Overwrites preserve the target public identity
and use a version CAS check, so stale, deleted, revoked, or otherwise terminal
records fail closed without partial persistence. Secret-Version records and
the aggregate success audit are finalized only after the Credential batch
commit; a failure compensates the batch. The staging-worker resource and
restart proof remain deployment evidence and must be verified separately.

Audit persistence is a separate metadata-only retention boundary. At each
governed load or write, records with age less than 30 days at the current UTC
instant are eligible; records at or beyond 30 days expire. The newest 10,000
eligible records are retained and persisted oldest to newest. Legacy state
converges on first governed load/write, including malformed-record exclusion,
expiry, capping and canonical ordering. Malformed legacy records may produce
only a secret-free operational warning. New malformed audit records are
rejected. Consumer Resolve writes its success audit before Secret delivery and
fails closed if that write cannot be persisted.

The metadata index is encrypted separately from the secret-bearing Credential
collection. A metadata-only read therefore does not decrypt the collection and
cannot fail because an unrelated Credential payload is undecryptable. A missing
metadata index is a one-time compatibility migration; after migration, normal
metadata reads remain on the metadata projection path. Resolve and other
secret-bearing operations remain explicit and are not replaced by this rule.

Provider-profile-dependent Consumer Discovery, Resolve, Batch Resolve and
Runtime-Public paths require an exact current Provider Profile plus persisted
`migrationComplete=true` and `migrationVerified=true` state. Legacy,
profile-less, stale or ambiguous records fail closed using the normal
non-enumerating Consumer response. Provider operations apply the same gate
before invoking an adapter or transport.

### Consumer Runtime responsibility

After a successful Resolve, the received values are processed by the
Consumer Runtime. The Consumer Runtime is responsible for applying its own
security mechanisms to those values and for using and disposing of them in
accordance with its environment and integration.

Sekalum does not automatically control how a Consumer Runtime handles
values after delivery, including:

- storage within the Consumer system;
- logging within the Consumer system;
- UI presentation within the Consumer system; or
- onward transmission by Consumer applications.

This boundary does not grant permission to persist, log, display or transmit
Secret values. It identifies the existing responsibility boundary after the
Consumer API has returned an authorized result. Consumer integrations must
follow their applicable security controls while preserving the existing
least-privilege and transient-use expectations of the Consumer contract.

## OAuth Context Binding

OAuth security has three separate decisions: one-time state and browser
transaction admission, provider-token evidence admission, and Credential commit
authorization. A token that is valid for a provider is not necessarily valid for
the exact Sekalum actor, profile, method, client, redirect, scope and account
context that initiated the transaction. The public-safe architecture and path
decisions are in ADR-031 and the
[adversarial mapping](oauth-context-binding-adversarial-mapping.md).

Provider capabilities are explicit. Issuer, audience, client, profile and scope
claims are accepted only when a fixed provider response or transaction-bound
adapter proves them. Missing evidence remains `NOT_AVAILABLE` and blocks when
required; generic token decoding and browser overrides are not trust sources.
Tokens, codes, verifiers, secrets and raw provider responses remain transient
and must not enter logs, UI, audit records or durable PASS values.

## Declarative custom-provider onboarding

Creating a custom provider requires `providers:manage`. The onboarding API accepts a data-only schema: provider identity and display metadata, Credential Methods, public method bindings, and Credential Field schemas. It rejects OAuth settings, provider-configuration fields, credential values, executable adapters, code, hooks, scripts, and runtime-operation declarations.

Custom-provider definitions are stored separately from Credentials. A field marked `secret` describes the handling required for a future Credential value; the definition itself contains no secret value. Only the restricted declarative schema is persisted or returned through the Provider API. Public method bindings exclude runtime adapters, and public field schemas expose neither a secret value nor a secret default.

Nested schema input is allowlisted. UI-created definitions cannot store validation patterns, arbitrary defaults, options, CSV aliases, system-managed fields, or a `providerConfiguration` section. These restrictions keep the persisted metadata from changing server execution outside the declared declarative contract.
