---
title: Security Assurance Record
document_id: DOC-SECURITY-ASSURANCE-RECORD
classification: PUBLIC
language: en
version: 1.1.0
status: Active
category: Security Assurance
canonical: false
owner: Sekalum
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Users
  - Integrators
  - Security reviewers
dependent_documents:
  - docs/security-guide/index.md
  - docs/release-guide/index.md
change_history:
  - version: 1.1.0
    date: 2026-09-13
    change: Binds RC3 assurance reporting to the stable public standards-aligned methodology and timeless release-binding semantics.
  - version: 1.0.1
    date: 2026-09-13
    change: Binds the prepared RC3 Security Assurance Record to the planned v1.0.0-rc.3 tag without asserting that the tag or release exists.
  - version: 1.0.0
    date: 2026-09-12
    change: Prepares the public-safe RC3 Security Assurance Record from the candidate-bound release-closure evidence; release and publication remain separately authorized decisions.
---

# Security Assurance Record

This public-safe record summarizes aggregate RC3 assurance evidence without
exposing private scan artifacts, governance records, deployment details or
secrets. It is intended for the governed private-to-public projection and is
bound to the release identity and rule below; the record itself does not
authorize publication, release or deployment.

## Release identity and scope

| Field | Value |
|---|---|
| Release line | `RC3` |
| Record status | Candidate-bound assurance record |
| Candidate commit | `c826a3e08ff024fdd8b1445be5da5417ae930f51` |
| Candidate tree | `2f225b3cd3cf6cd0981dea60d8f8790f1c604248` |
| Release binding | `v1.0.0-rc.3` |
| Security closure | PASS for the candidate-bound assurance set |
| Critical findings | `0` |
| High findings | `0` |

| Release binding rule | Applies only when the tag resolves to the final integrated RC3 release commit |

The candidate and tree above identify the implementation assessed by the
current closure evidence. A later evidence or governance successor does not
become a new Product implementation candidate. The record applies to
`v1.0.0-rc.3` only when that tag resolves to the final integrated RC3 release
commit; it does not assert that the tag exists.

## Hacker Test assurance

The Sekalum Adversarial Hacker Test Framework uses the version-2 registry and
runner contract. The current registry validation reports version `2.0.0`,
with nine attack families. The candidate-bound release-gate result is:

| Dimension | Result |
|---|---:|
| Registered attacks | `73` |
| Implemented attacks | `73` |
| Release-gate attacks | `73` |
| Executed attacks | `73` |
| Passed attacks | `73` |
| Failed attacks | `0` |
| Planned or deferred attacks | `0` |
| Families covered | `9/9` |

The covered families are Consumer Grant Escape, Binding-Time Authorization
Bypass, Lifecycle Race, Canonicalization, OAuth Context Confusion, SSRF and
Egress, Secret Exfiltration, Abuse and Harvesting, and Plane Pivot. Registered
or implemented status is kept distinct from executed and passed status; no
unexecuted case is presented as passing.

## Other assurance gates

The current candidate-bound evidence set reports the following aggregate
results:

| Gate | Result |
|---|---|
| Product qualification | `1121/1121 PASS` |
| Architecture qualification | `16/16 PASS` |
| Public qualification | `898/898 PASS` |
| GOV3 qualification | `389/389 PASS` |
| Documentation contract | `PASS` |
| Documentation checks | `PASS` |
| Public verification | `PASS` |
| Public tests | `898/898 PASS` |
| Deep Security Scan coverage | `COMPLETE` |
| Additional Deep Security Scan required | `NO` |

The Deep Security Scan aggregate is complete for this candidate. No new scan
is required for this documentation-only release-closure preparation because
the Product and Runtime security implementation candidate is unchanged.

## Standards and Methodology Alignment

The RC3 assessment used the stable Security Assurance Methodology described
in the [Security Guide](index.md). The applicable basis includes NIST SSDF
SP 800-218, NIST SP 800-55, ISO/IEC 27005, OWASP Risk Rating, OWASP SAMM,
OWASP ASVS, MITRE CWE, FIRST CVSS v4.0 and, where applicable, FIRST EPSS,
CISA KEV, OWASP Benchmark / NIST SAMATE and OpenSSF Scorecard. Each source
retains its defined purpose; no individual severity, probability signal or KPI
is treated as a complete risk score or an automatic release decision.

## Audit and Certification Evidence Readiness

The RC3 evidence structure uses traceable, versioned and standards-aligned
methods and records assessment scope, provenance, classification, severity,
likelihood, impact, uncertainty, treatment, residual risk, risk-owner
decisions, review state and candidate/release binding where applicable. This
supports reuse as input to a future formal audit, assurance or certification
program, subject to that program's exact scope, control mapping, gap
assessment, organization/process evidence and independent procedure. This
record claims standards-aligned methods only; it does not claim certification
or formal full compliance.

## Limitations and publication boundary

This record does not disclose private scan identifiers, manifests, Gov3
evidence, Owner authorizations, private findings, local filesystem paths,
deployment credentials or exploit details. Aggregate counts are valid only
for the candidate identified above. Environment-specific deployment and
provider controls remain the operator's responsibility and are not claimed as
Product controls here. Release readiness, publication and deployment remain
separate governed decisions. If a `v1.0.0-rc.3` tag is created, it must point
exactly to the final integrated RC3 release commit; this record does not
create or authorize that tag.

## Public registry and runner

The public [adversarial test registry](../../scripts/security/attack-registry.json)
contains the registered cases and their implementation status. The public
[Hacker Test runner](../../scripts/hacker-test-runner.mjs) validates the
registry and executes the candidate-bound test references. Public output is
aggregate and safe by design.
