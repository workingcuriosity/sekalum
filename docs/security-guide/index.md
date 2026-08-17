---
title: Security Guide
version: 1.6.0
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
change_history:
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

## Declarative custom-provider onboarding

Creating a custom provider requires `providers:manage`. The onboarding API accepts a data-only schema: provider identity and display metadata, Credential Methods, public method bindings, and Credential Field schemas. It rejects OAuth settings, provider-configuration fields, credential values, executable adapters, code, hooks, scripts, and runtime-operation declarations.

Custom-provider definitions are stored separately from Credentials. A field marked `secret` describes the handling required for a future Credential value; the definition itself contains no secret value. Only the restricted declarative schema is persisted or returned through the Provider API. Public method bindings exclude runtime adapters, and public field schemas expose neither a secret value nor a secret default.

Nested schema input is allowlisted. UI-created definitions cannot store validation patterns, arbitrary defaults, options, CSV aliases, system-managed fields, or a `providerConfiguration` section. These restrictions keep the persisted metadata from changing server execution outside the declared declarative contract.
