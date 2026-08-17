---
title: Quick Start Guide
version: 1.0.6
status: Active
category: Quick Start
canonical: true
scope: Release 1.0 international onboarding baseline
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 Working Curiosity"
target_audience:
  - International users
  - Administrators
  - Operators
dependent_documents:
  - docs/installation-guide/index.md
  - docs/configuration-reference/index.md
  - docs/user-guide/index.md
  - docs/api-reference/index.md
  - docs/security-guide/index.md
  - docs/project/THIRD_PARTY_SOFTWARE.md
change_history:
  - version: 1.0.5
    date: 2026-08-02
    change: Adds the post-setup Consumer interface handoff and clarifies the separate Consumer context.
  - version: 1.0.6
    date: 2026-08-04
    change: Adds the consistent Beta-1 Bootstrap, First Administrator and Management Token onboarding path.
  - version: 1.0.4
    date: 2026-08-02
    change: Replaces the illustrative Consumer visual with real, sanitized Beta-1 Consumer Flow screenshots.
  - version: 1.0.3
    date: 2026-08-02
    change: Adds the public Beta-1 Consumer Flow quick start and a safe illustrative connection-state visual.
  - version: 1.0.2
    date: 2026-07-17
    change: Clarifies that OAuth redirect URIs are system-managed registration values, not Wizard input.
  - version: 1.0.1
    date: 2026-07-12
    change: Uses Wizard-managed encrypted OAuth application configuration as the primary onboarding path.
  - version: 1.0.0
    date: 2026-07-12
    change: Adds the mandatory English Release 1.0 onboarding path.
---

# Quick Start Guide

## Purpose

Sekalum manages the lifecycle of digital credentials, including provider credentials, OAuth connections, API tokens, encrypted import and export data, and lifecycle status. This guide is the English onboarding path for Release 1.0 Beta 1. It does not translate the complete product documentation.

## Prerequisites

- A supported Node.js runtime.
- A checkout of this repository with its lockfile.
- A 32-character encryption key for credential storage.
- OAuth application registration details only for the providers you intend to use.

## Install and configure

Install dependencies from the lockfile:

```bash
npm ci
```

Provide global runtime settings through the process environment. At a minimum, configure encryption before creating or changing stored credentials:

```env
TOKEN_ENCRYPTION_KEY=YOUR_32_CHARACTER_ENCRYPTION_KEY
```

`OAUTH_CALLBACK_PORT` defaults to `3000`. OAuth application credentials are normally entered in the Credential Wizard and stored encrypted by the backend. Provider-specific environment variables remain a compatibility fallback. The full precedence, settings, defaults, and encryption rotation rules are in the [Configuration Reference](../configuration-reference/index.md).

## Start the application

Run the repository checks and start the application:

```bash
npm run check
npm test
node src/index.js
```

If the application runs in a container, rebuild or restart that container after changing runtime files, static Admin UI files, or environment variables. The project does not prescribe a specific container platform or service manager.

## Open the Admin UI

With the default root deployment, open:

- Dashboard: `/admin/dashboard.html`
- Credential Wizard: `/admin/`
- Health endpoint: `/health`

To run below a public prefix, set `BASE_PATH` to a value such as `/credential-hub`. The corresponding paths become `/credential-hub/admin/`, `/credential-hub/admin/dashboard.html`, and `/credential-hub/health`. A reverse proxy must preserve the prefix rather than strip it.

## Bootstrap and Admin access

Beta 1 has no username/password login screen. On a new installation with an
empty persisted user collection, **Bootstrap** is active. Create the
**First Administrator** through the local Management API before exposing the
service beyond the local machine:

```bash
curl --request POST http://localhost:3000/api/v1/management/users \
  --header 'Content-Type: application/json' \
  --data '{"userId":"admin","displayName":"First Administrator","roleKey":"admin"}'
```

Bootstrap ends when the **First Administrator** is persisted. The Admin UI then opens
with a **Management Token** gate. Enter an authorized **Management Token**;
the Admin UI validates `Authorization: Bearer <management-token>` before it
reveals the Dashboard and Admin navigation. The Consumer API uses a separate
Consumer API token and does not use the Management Token.

The `x-credential-hub-user` header is not a production login mechanism. It is
retained only for `NODE_ENV=test` compatibility tests.

For the complete first-installation sequence, including health validation,
Credential preparation, Consumer Grant setup and the first Resolve, see the
[Installation Guide — Complete First Installation Workflow](../installation-guide/index.md#complete-first-installation-workflow).

## Create a first credential

1. Open the Credential Wizard.
2. Select an authentication method and a registered provider.
3. Enter only the user-configurable fields requested by the provider definition. For OAuth, this can include the application client ID, scopes, and client secret where required. The redirect URI is system-managed: copy the read-only technical value shown by Sekalum when registering the provider application; do not enter it as a Wizard field.
4. Complete authorization at the provider and ensure the registered callback URI includes the active `BASE_PATH` when one is configured. If authorization is cancelled or fails, use the retry action in the Wizard.
5. Review the summary and create the credential.

The Admin UI starts in English. Use the visible EN / DE switch to change the local browser preference. The setting is stored only in browser local storage under `credentialHub.language` and is shared by all Admin pages.

## Beta-1 product journey: real UI

The following redacted screenshots were captured from the running Beta-1 UI.
They show the real administrative setup before the Consumer Runtime begins.
No token plaintext, Secret value or password is included.

### 1. Administrator entry and setup

The Admin entry opens the Credential Wizard. The Wizard is the primary setup
surface for creating a Credential and preparing Consumer access.

![Real Credential Wizard entry](images/credential-hub-admin-wizard-entry.jpg)

*Real Beta-1 Admin entry: the Wizard is ready for the administrator without
exposing the saved Management Token.*

![Real Admin Dashboard](images/credential-hub-admin-dashboard.jpg)

*Real Beta-1 Dashboard: Credential status and management entry points are
visible without displaying Secret values.*

### 2. Credential and permission setup

The Credential list and detail view expose public metadata and lifecycle state;
Secret values are intentionally absent. Consumer access is then connected to a
specific Credential through a least-privilege grant.

![Real Credential management list](images/credential-hub-admin-credential-management.jpg)

*Real Beta-1 Credential management: public names, providers, types and status.*

![Real redacted Credential detail](images/credential-hub-admin-credential-detail.jpg)

*Real Beta-1 Credential detail: identifier, provider, status and metadata only.*

![Real Consumer Grant overview](images/credential-hub-admin-consumer-grants.jpg)

*Real Beta-1 Consumer Grant overview: consumer, Credential, provider and named
granted fields; Secret values are not shown.*

![Real Consumer Grant permission form](images/credential-hub-admin-grant-form.jpg)

*Real Beta-1 Grant form: the administrator selects named Secret fields without
entering or viewing their values.*

Before saving, the Grant form provides a read-only Permission Summary. It
separates selected Resolve Secret fields from excluded fields and explains
that Discovery and Runtime-Public remain the existing public projections. The
preview makes no API call, exposes no Secret values and does not change the
grant.

The Consumer permissions page explains this least-privilege selection in
business terms. Discovery exposes only active Credentials with a matching
grant and their public field contract. Resolve returns only explicitly
requested Secret fields permitted for that Credential and Consumer; it never
provides wildcard access or provider internals. A Consumer API Token is used
by the Consumer Runtime, while a Management Token is reserved for
administration.

### 3. Consumer token and handoff

The API Token form makes the dedicated Consumer token and its
`credentials:consume` scope an explicit administrative prerequisite. The
plaintext token is not shown in this documentation capture.

![Real API Token setup form](images/credential-hub-admin-token-form.jpg)

*Real Beta-1 API Token form: token identity, optional expiry and scopes; no
plaintext token is visible.*

![Real Consumer entry surface](images/credential-hub-consumer-entry.jpg)

*Real Beta-1 Consumer entry: the separate Consumer context waits for a
dedicated Consumer API token and keeps it in page memory only.*

The existing Consumer screenshots below continue the story through Discovery,
Credential selection, Field Contract, Resolve and secure result display.

## Create an API token

Open **API Tokens** from the Dashboard. Create a token with a technical name, user ID, and optional expiration or scopes. Copy the plaintext token immediately; it is not shown again after the dialog is closed. RBAC permissions still control what the token can access.

## Using the Consumer Interface (Advanced Integration Flow)

This is the Beta-1-supported Advanced Integration Flow for applications that need to consume an already configured credential. It is technically complete and usable, but it is not the primary Consumer-first onboarding flow.

![Consumer integration overview from setup to secure disposal](../developer-guide/images/consumer-integration-overview.svg)

*The Consumer Runtime uses the public Discovery and `credentialKey` selection
path after an administrator has prepared the grant.*

**Prerequisites:** An administrator has already created and activated the credential, created a dedicated Consumer API token with the `credentials:consume` scope, and granted the Consumer access to the credential and the specific secret fields it may resolve. A Management Token is not a Consumer token.

Consumer-first onboarding improvements are planned outside Beta 1 under Issue #141.

1. After a successful Consumer Grant setup and Resolve verification in the Credential Wizard, choose **Open Consumer interface**. You can also open the Consumer view directly at `/consumer/`. The link opens a separate Consumer context and does not transfer a Management Token. Enter the dedicated Consumer API token there and treat it as sensitive: use it only for the current session and do not put it in screenshots, logs, source code, or browser persistence.

   ![Consumer access with an empty Consumer API token field](images/consumer-access.jpg)

   *Actual Beta-1 Consumer access view. The token field is intentionally empty.*

2. Choose **Test connection** to start Discovery. The Consumer sees only active credentials for which it has a valid grant. Discovery provides public selection metadata, an opaque `credentialKey`, and the permitted field contract; it does not expose provider internals, CredentialMethod details, internal identifiers, or secret values.

   ![Successful Consumer Discovery showing available credentials](images/consumer-discovery.jpg)

   *Actual Beta-1 Discovery result. It shows only public credential-selection metadata and field names.*

3. Select a credential using the public information and its `credentialKey`. Provide only the inputs described by the field contract. When an authorized Runtime-Public input is available, it is shown as a restricted, non-secret input; when it is absent, do not infer or substitute a value.

   ![Selected credential identified by its public credentialKey](images/credential-selection.jpg)

   *Actual Beta-1 credential selection. The selected credential is identified through its public `credentialKey`.*

4. Select only the secret field names required for the current operation and choose **Resolve**. Sekalum returns only explicitly requested, authorized fields. The Consumer cannot use wildcard selection or bypass the configured grant.

   ![Field contract and permitted secret field selection](images/field-contract.jpg)

   *Actual Beta-1 field contract. This selected credential has no Runtime-Public input; only declared field names and the permitted secret-field choice are shown.*

5. Review the result in the secure result display. Values are masked by default, revealed one at a time, automatically masked after five seconds, and cleared when the selection, request, or session changes. Do not save, log, transmit, or display resolved secrets beyond the protected Consumer workflow.

   ![Successful Resolve result with the secret value masked](images/secure-resolve-result.jpg)

   *Actual Beta-1 Resolve result. The resolved value remains masked until an explicit, time-limited reveal action.*

Sekalum enforces authentication, authorization, grants, credential lifecycle, and controlled resolution. Once a value is delivered to the Consumer, the Consumer is responsible for its own storage, logging, display, and transmission controls. For endpoint and field-contract details, see the [API Reference](../api-reference/index.md) and [Security Guide](../security-guide/index.md).

Developers integrating an external JavaScript or Python service can use the [Node.js Consumer Runtime example](../developer-guide/index.md#nodejs-consumer-runtime-example) or [Python Consumer Runtime example](../developer-guide/index.md#python-consumer-runtime-example) for the same Discovery → `credentialKey` → Resolve sequence without adding a product-specific library. n8n users should follow the [n8n Consumer Runtime guidance](../developer-guide/index.md#n8n-and-other-runtimes); n8n uses the same generic HTTP Consumer API path and has no privileged integration.

## Basic troubleshooting

- Check the health endpoint first.
- Confirm that `TOKEN_ENCRYPTION_KEY` is present and exactly 32 characters long.
- Confirm that OAuth redirect URIs match the public URL and configured `BASE_PATH`.
- Confirm that the reverse proxy preserves the prefix.
- Use the safe, localized Admin UI error message as the user-facing result; inspect server logs separately for operator diagnostics.

## Further reading

- [Installation Guide](../installation-guide/index.md)
- [Configuration Reference](../configuration-reference/index.md)
- [User Guide](../user-guide/index.md)
- [API Reference](../api-reference/index.md)
- [Security Guide](../security-guide/index.md)
- [Third-Party Software](../project/THIRD_PARTY_SOFTWARE.md)

## Need Help?

- Join the official [Sekalum Discord community](https://discord.gg/exTu3Dy2UW) for technical support, discussion, and feature ideas.
- Use the documentation sources listed above for product and configuration guidance.
- Submit reproducible bugs through [GitHub Issues](https://github.com/workingcuriosity/sekalum/issues).
- Report security vulnerabilities only through the process in the [Security Guide](../security-guide/index.md), never through Discord.
