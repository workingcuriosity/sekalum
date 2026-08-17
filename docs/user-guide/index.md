---
title: User Guide
version: 1.8.0
status: Active
category: User Guide
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 Working Curiosity"
target_audience:
  - Administrators
  - Authorized users
dependent_documents:
  - docs/providers/README.md
  - docs/data-model-reference/index.md
  - docs/security-guide/index.md
change_history:
  - version: 1.8.0
    date: 2026-08-09
    change: Migrates the active User Guide to English as the sole canonical documentation language and synchronizes the Beta-1 lifecycle, Integration Health and Consumer flow.
  - version: 1.7.0
    date: 2026-08-09
    change: Documents the Issue #77 Integration Health dashboard projection and its secret-free status model.
  - version: 1.4.0
    date: 2026-07-28
    change: Documents the complete Consumer flow, least-privilege Consumer Grants and ADR-020 Secure Result Rendering.
  - version: 1.5.0
    date: 2026-08-01
    change: Synchronizes the Beta-1 Consumer journey, optional Runtime-Public discovery values and the completed Admin UX boundary.
  - version: 1.6.0
    date: 2026-08-04
    change: Documents the Beta-1 Bootstrap, First Administrator and Management Token gate and distinguishes production Bearer Authentication from test compatibility.
  - version: 1.3.0
    date: 2026-07-13
    change: Documents capability-gated draft and stored Credential connection tests and their secret-safe limits.
  - version: 1.2.0
    date: 2026-07-13
    change: Adds the Credential management workflow, deliberate secret replacement and destructive-delete confirmation.
  - version: 1.1.0
    date: 2026-07-13
    change: Documents credential-creation success, recoverable failure, encrypted persistence and Dashboard visibility.
  - version: 1.0.0
    date: 2026-07-12
    change: Establishes the English-default Admin UI, EN / DE preference and safe localized error fallback.
---

# User Guide

## Purpose and scope

This guide describes the current Sekalum user workflows. It is for
administrators and authorized users who manage Credentials, authorize
Providers, configure Consumer access, transfer Credentials or create
technical API access. It describes the Admin UI at `/admin/`; exact HTTP
contracts, permissions and error behavior are defined by the [API
Reference](../api-reference/index.md), while Provider prerequisites are
listed in the [Provider overview](../providers/README.md).

## Access and permissions

When authorization is enabled, `/api/v1` first authenticates the identity and
then evaluates its RBAC permissions. Reading Credentials requires
`credentials:read`; creating, changing, deleting, validating, refreshing,
revoking, importing and exporting require `credentials:manage`. The complete
mapping is defined in the [API Reference](../api-reference/index.md#authorization-and-errors).

### Bootstrap and the First Administrator

When the persisted user store is empty, Bootstrap permits the one-time
`POST /api/v1/management/users` request for the First Administrator without an
existing user authentication. Once that user is stored, Bootstrap ends and
subsequent management requests are protected.

Beta 1 does not use username/password authentication for normal operation.
The Admin UI starts with a Management Token gate, validates the token through
the protected management boundary and sends it as
`Authorization: Bearer <management-token>`. The Management Token is for the
Admin context only; the separate Consumer API token belongs to the Consumer
API and cannot replace Admin access. `x-credential-hub-user` is test-only
compatibility for repository tests and is not a production authentication
method.

The complete new-installation path, from Health and Bootstrap through the
first Consumer Resolve, is in the [Installation Guide](../installation-guide/index.md#complete-first-installation-workflow).

## Using the Admin UI

### Admin UI language

The Admin UI starts in English. If no preference is stored, a browser language
with the `de` prefix selects German; all other browser languages select
English. The visible EN / DE switch is available on the Wizard, Dashboard,
API-token and Credential-transfer pages. The preference remains in the
browser under `credentialHub.language` and applies to all Admin pages.

Backend errors are not displayed raw. Known error codes may be localized;
unknown or technical errors use a safe general message without changing server
logs or API contracts.

### Opening the Credential Wizard

The `/admin/` entry point opens the Credential Wizard:

1. Select an available authentication type.
2. Select or search for a Provider.
3. Enter the Provider's required Credential data.
4. Authorize the Provider when using OAuth.
5. Review the summary and create the Credential.

Provider cards and fields come from current Provider metadata. A new
Credential starts with lifecycle state `registered`.

### Creating and authorizing Credentials

OAuth Providers request the application data for the Provider registration,
such as Client ID, optional Client Secret and scopes. The redirect URI is
system-managed metadata, not a user decision. Sekalum derives it from
the configured public base URL or validated request origin, `BASE_PATH` and
Provider key. The Wizard displays the URI, authorization endpoint, callback
path and scopes as read-only technical details.

After validation, the Wizard opens the OAuth authorization window. Callback
results use neutral status codes and never expose raw Provider errors or
Secrets. State, PKCE and nonce requirements are applied by the Provider
definition and shared OAuth security service.

For API-key and Connection Providers, enter the requested fields, review the
summary and choose **Create Credential**. Successful encrypted persistence
shows a completion state and links to the Dashboard. Validation, encryption or
persistence failures retain the form data and show a stable safe error.

### Testing a connection

Providers with the `validation` capability expose **Test connection**. The
test sends the current values to the backend, creates no Credential and does
not change an existing Credential. Editing a field invalidates the previous
result. Secrets are absent from results and errors. OAuth and declarative
Custom Providers do not expose a pre-save connection test; that is an
intentional capability boundary.

## Dashboard and Integration Health

The Dashboard at `/admin/dashboard.html` summarizes Credentials, Providers,
expired and soon-to-expire Credentials, lifecycle data, Provider capabilities
and scheduler information.

The **Integration Health** section derives a secret-free status per Credential
from existing lifecycle, Consumer Grant, OAuth, token, refresh and Resolve
availability. The aggregate status is **Healthy**, **Warning**, **Error** or
**Unknown**. The view reads the existing Dashboard endpoint; it does not probe,
refresh or repair integrations and never displays Secrets or token values.

Warnings from the management endpoint should be reviewed promptly. Relevant
lifecycle states are `registered`, `validated`, `active`, `expiring`,
`expired`, `revoked` and `deleted`. For an active OAuth Credential, a due
refresh runs through the existing Provider refresh function before an
authorized Consumer Resolve. The Consumer keeps the same Resolve contract;
rotated values are stored only on the server.

## Managing Credentials

The **Credentials** page at `/admin/credentials.html` lists display name,
Provider, type, lifecycle status, update time and a technical Credential ID;
it never lists Secret values.

### Edit

Choose **Edit**, change only displayed user-configurable fields and save.
Credential ID, Provider key, creation time, lifecycle state, derived metadata,
system-managed values and OAuth redirect URI are not editable. Secret fields
are never prefilled. Leaving a Secret field empty preserves the encrypted
value; entering a new value replaces only that Secret.

### Validate and delete

For a Provider with `validation`, **Test connection** uses the stored
encrypted Credential and refreshes the visible lifecycle state only after a
confirmed backend response. OpenAI validation is supported by the active
Release-1.0 container; FTP and SFTP expose the safe validation contract but do
not imply that a production transport adapter is present.

Choose **Delete** and confirm the display name and Provider. Deletion is
irreversible. The UI removes the row only after the confirmed `204` response;
on Provider, storage or network errors the row remains visible.

## Credential Export and Import

Open **Credential Export / Import** at `/admin/credential-transfer.html`.
For export, select Credentials, set an export password of at least eight
characters, generate the encrypted file and keep the file and password
separate. For import, choose a Sekalum export or CSV, provide the
required password or content, select a conflict strategy, review the preview
and execute the import only after a successful preview. CSV imports require
`providerKey`, `externalReference` and at least one Secret column. Preview
shows mappings and conflicts without Secret values.

## Managing API Tokens

The **API Tokens** page at `/admin/api-tokens.html` shows name, status, prefix,
scopes, creation time, optional expiry and last use. It never shows token
plaintext or hashes in the list.

To create a token, provide its internal name, authenticated user ID, optional
expiry and scopes. Copy the plaintext immediately to a secure location: it is
shown only once. RBAC remains authoritative; scopes do not replace the
user-permission check. To revoke a token, choose **Revoke** and confirm. The
token is immediately rejected and cannot be restored.

## Consumer access

The Consumer flow is a separate, technically complete Advanced Integration
Flow. It requires prior Admin setup and is not a Consumer-first onboarding
flow. Its path is:

```text
Consumer API Token -> Discovery -> Credential Selection -> Secret Selection -> Resolve -> Secure Result Rendering
```

An administrator must provide an active Bearer Consumer API token with scope
`credentials:consume`, grant the same permission to its owner and configure a
matching Consumer Grant for the Credential, Provider and required Secret
fields. Management and Consumer tokens are separate; the Consumer token is
held only in page memory.

At `/consumer/`, enter the Consumer token and choose **Test connection**.
Discovery lists only active granted Credentials, public metadata and the public
`credentialKey`. Internal Credential IDs, CredentialMethod IDs and
ProviderMethodBinding data are not shown. Optional Runtime-Public values may
be shown when they are bound to that Credential and Consumer.

After selecting a Credential, choose visible public Secret field names. The
existing Resolve route,
`POST /api/v1/consumer/credentials/:credentialKey/resolve`, receives only
`secretNames`. Grant checks, Credential status and field authorization remain
server-side.

Successful results appear in **Resolved secrets**, initially masked. **Reveal**
shows one value after explicit user action and automatically remasks it after
five seconds. Results and reveal state are cleared on Credential or token
change, Discovery refresh, reset and errors. Values are not persisted in
browser storage, cookies, URLs, logs or telemetry, and there is no clipboard
or copy function.

Common safe messages include:

| Situation | Consumer message |
|---|---|
| Missing token | `Enter a Consumer API token to continue.` |
| Discovery `401` | `Connection failed. Check the Consumer API token and try again.` |
| Discovery `403` | `Connection failed. This token is not authorized for Consumer Discovery.` |
| Discovery `500` | `Credential Discovery is temporarily unavailable. Try again.` |
| Resolve `400` | `Resolve request could not be completed. Check the selected secret fields and try again.` |
| Network error | `Network error. Check the connection and try again.` |

## Consumer Grants for administrators

A Consumer Grant binds a Consumer token to one Credential, Provider and
explicit Secret field names. The **Consumer Grants** page requires a
Management Token with `consumer-grants:manage`. It shows only field names,
never Secret values, and follows least privilege: no wildcards, implicit
defaults or cross-Credential reuse.

The permission summary is read-only and shows selected and excluded fields.
It does not call the API or change permissions. Store the grant only after
reviewing the Credential, Provider and allowed Secret field names. A successful
Resolve still requires an active Consumer token, the consume scope and
permission, an active Credential and a matching grant.

## Safe operation and support

Do not share Secrets, export passwords or token plaintext in tickets, chats or
source code. Review Provider, selection and conflict strategy before imports;
use named technical tokens and revoke unused tokens; respond to Dashboard
warnings and verify Provider prerequisites before reauthorizing.

The [Security Guide](../security-guide/index.md) covers encryption,
authorization and OAuth protection. Report vulnerabilities only through
`SECURITY.md`. Admin navigation and the common footer remain `BASE_PATH`-safe
and link to legal, third-party and security sources without depending on a
Git branch or GitHub session.

## Boundary

This guide describes user workflows. It does not replace the API, Provider,
configuration, installation, operations or data-model references. Deployment
and infrastructure decisions remain outside this guide.
