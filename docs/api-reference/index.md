---
title: API Reference
version: 2.2.0
classification: Public
status: Active
category: API
canonical: true
owner: Sekalum
approved_by: pending
maintainer: cyphre-san productions
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 cyphre-san productions"
target_audience:
  - Entwickler
  - Integratoren
  - Administratoren
dependent_documents:
  - docs/api/REST_API.md
  - docs/api/OAuth_API.md
  - docs/api/Health_API.md
  - docs/adr/ADR-020-Credential-Consumer-API.md
  - docs/adr/ADR-021-Generic-Credential-Method-Model.md
  - docs/data-model-reference/index.md
  - docs/architecture/Gesamtarchitektur.md
  - docs/architecture/C4_ARCHITECTURE.md
  - docs/architecture/glossary/GLOSSARY.md
  - docs/security-guide/index.md
  - docs/developer-guide/index.md
  - docs/project/PROVIDER_METADATA_GUIDELINE.md
  - docs/architecture/ARCHITECTURE_DEPENDENCY_MATRIX.md
  - docs/architecture/governance/audits/ADR-020_ISSUE-136_GOVERNANCE_REVIEW_RECORD.md
  - docs/architecture/governance/audits/ADR-020_ISSUE-136_INDEPENDENT_SECURITY_ARCHITECTURE_AUDIT.md
  - docs/architecture/governance/audits/ADR-020_ISSUE-136_GOVERNANCE_AUTHORITY_DECISION.md
  - docs/architecture/governance/audits/ADR-020_ISSUE-136_FINAL_BASELINE_REVIEW_RECORD.md
change_history:
  - version: 2.2.0
    date: 2026-08-09
    change: Documents the existing dashboard endpoint's secret-free Integration Health projection for Issue #77 without adding a health API or changing management permissions.
  - version: 2.0.0
    date: 2026-07-30
    change: Synchronizes the normative Consumer API reference with ADR-020 v1.3.0 and documents the optional, credential-bound Runtime-Public Discovery projection and its security boundaries.
  - version: 2.1.0
    date: 2026-08-04
    change: Documents the one-time Bootstrap exception for First Administrator creation and the subsequent Management Token boundary.
  - version: 1.9.0
    date: 2026-07-30
    change: Documents the canonical platform-independent Consumer Integration Algorithm and the Beta-1 transient integration workaround.
  - version: 1.8.0
    date: 2026-07-26
    change: Documents the canonical public Consumer Discovery and credential selection contract from ADR-020.
  - version: 1.7.0
    date: 2026-07-26
    change: Harmonizes public management and Consumer API boundaries with ADR-020 and the CredentialMethod data contract with ADR-021.
  - version: 1.6.0
    date: 2026-07-16
    change: Documents the active method-aware Credential, Provider metadata, lifecycle, and Consumer API contracts from R5.
  - version: 1.5.1
    date: 2026-07-16
    change: Documents administrator-only Consumer Grant provisioning for the isolated Credential Consumer API.
  - version: 1.4.0
    date: 2026-07-13
    change: Documents the authorized, non-persistent Credential connection-test contract and public error boundary.
  - version: 1.3.0
    date: 2026-07-13
    change: Defines the secret-safe public Credential update patch contract used by Credential management.
  - version: 1.2.0
    date: 2026-07-13
    change: Adds the compensated initial Secret-Version failure contract for Credential creation.
  - version: 1.1.0
    date: 2026-07-13
    change: Defines the hardened credential-creation contract, stable failure codes, and secret-free response shape.
  - version: 1.0.2
    date: 2026-07-13
    change: Documents system-managed field metadata and server-derived OAuth redirect URIs.
  - version: 1.0.1
    date: 2026-07-12
    change: Adds the authorized OAuth-start route, public provider-configuration metadata, and stable OAuth result codes.
  - version: 1.0.0
    date: 2026-07-11
    change: CP-004 verifiziert die REST-, OAuth- und Health-Routen gegen den Callback-Server, Controller und Integrationstests.
---

# API Reference

## Scope

This is the canonical reference for the active HTTP API. It covers routes registered by `OAuthCallbackServer`, their authorization boundary, and the route groups implemented by the current controllers. Provider-specific credentials and configuration remain separate concerns.

The public API has two distinct responsibilities:

- the Management API administers Credentials, Providers, lifecycle operations,
  transfers, tokens and Consumer Grants;
- the Consumer API resolves explicitly authorized Secret fields for runtime
  Consumers and does not expose management metadata or management operations.

ADR-020 owns the Consumer API decision and authorization boundary. ADR-021 owns
the CredentialMethod and ProviderMethodBinding contract used by management
validation and by the Consumer API only to determine whether a requested field
is an eligible Secret. This reference owns the externally observable HTTP
payloads, routes, permissions and error contracts.

## Authorization and errors

All `/api/v1` routes pass through the authorization wrapper. When authorization is active, callers authenticate with `Authorization: Bearer <api-token>`; management routes fail closed when it is absent or invalid. Authentication is followed by RBAC authorization for the permission shown below.

### Bootstrap and First Administrator

When the persisted user collection is empty, Bootstrap is active. The **First
Administrator** may then be created through:

```text
POST /api/v1/management/users
```

This one-time creation request is the only management exception to the normal
authentication boundary. Bootstrap ends as soon as the **First Administrator**
is persisted. From that point onward, management routes require an
authorized API token sent as `Authorization: Bearer <api-token>`; the Admin UI
labels the authorized token used for this purpose as the **Management Token**.
There is no username/password login flow in Beta 1. The Admin UI validates the
Management Token before exposing the Dashboard and Admin navigation.

The `x-credential-hub-user` header is not a production authentication method.
It is accepted only by the `NODE_ENV=test` compatibility path used by
repository tests. Production clients must use Bearer Authentication.

Successful JSON responses normally use `success: true`; controller responses may additionally include `data`, `meta`, or `pagination`. Errors use:

```json
{
  "success": false,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "..."
  }
}
```

Authentication failures return `401`; denied permissions return `403`. Controller validation, missing resources, and internal failures use their respective `400`, `404`, or `500` status codes.

## Public routes

| Method | Route | Result |
|---|---|---|
| GET | `/` | Redirects to `/admin/`. |
| GET | `/health` | Returns `200` with `{ "status": "UP" }`. |
| GET | `/oauth/:provider/login` | Starts the provider OAuth flow and redirects to its authorization URL. |
| GET | `/oauth/:provider/callback` | Processes `code` and optional `state`; returns a branded result page and a safe same-origin browser outcome message. |

The callback accepts provider `error` and `error_description` parameters as failure input. The result page exposes only a stable outcome code and explicit next actions. Detailed failure data remains in the server log.

## Credential routes

| Method | Route | Permission | Purpose |
|---|---|---|---|
| GET | `/api/v1/credentials` | `credentials:read` | Lists credentials with pagination, filtering, and sorting metadata. |
| POST | `/api/v1/credentials` | `credentials:manage` | Creates a credential from the request body. |
| POST | `/api/v1/credentials/bulk` | `credentials:manage` | Runs a bulk action for supplied credential IDs. |
| POST | `/api/v1/credentials/export` | `credentials:manage` | Exports credentials through the transfer service. |
| POST | `/api/v1/credentials/import/preview` | `credentials:manage` | Previews transfer or CSV import input. |
| POST | `/api/v1/credentials/import` | `credentials:manage` | Imports transfer or CSV input. |
| POST | `/api/v1/credentials/test-connection` | `credentials:manage` | Tests draft Credential input without persistence. |
| GET | `/api/v1/credentials/meta` | `credentials:read` | Returns UI-facing list, filter, and bulk-operation metadata. |
| GET | `/api/v1/credentials/:credentialId` | `credentials:read` | Returns a credential detail view. |
| PUT | `/api/v1/credentials/:credentialId` | `credentials:manage` | Updates a credential. |
| DELETE | `/api/v1/credentials/:credentialId` | `credentials:manage` | Deletes a credential and returns `204` on success. |
| POST | `/api/v1/credentials/:credentialId/validate` | `credentials:manage` | Runs validation. |
| POST | `/api/v1/credentials/:credentialId/refresh` | `credentials:manage` | Runs refresh. |
| POST | `/api/v1/credentials/:credentialId/revoke` | `credentials:manage` | Runs revocation. |
| POST | `/api/v1/credentials/:credentialId/health-check` | `credentials:manage` | Runs a provider health check. |

### Credential creation

`POST /api/v1/credentials` verifies the registered Provider and its required user-configurable field mapping before encrypted persistence. For a Provider that publishes `credentialMethods` and `providerMethodBindings`, the request must contain a `credentialMethodKey` for an available binding; the selected CredentialMethod field schema is the only source for validation, Secret classification and CSV aliases. Providers without method bindings retain the documented legacy Provider-level compatibility contract. The successful `201` response contains public Credential details and a masked `secretInventory`; it never returns Secret values. The created Credential is immediately available through the list endpoint used by the Dashboard.

Creation failures use a stable envelope with top-level and nested `code` and `messageKey` values. Supported creation codes include `CREDENTIAL_METHOD_REQUIRED`, `CREDENTIAL_METHOD_UNAVAILABLE`, `CREDENTIAL_SECRET_MISSING`, `CREDENTIAL_FIELD_MISSING`, `CREDENTIAL_FIELD_INVALID`, `CREDENTIAL_PROVIDER_UNKNOWN`, `CREDENTIAL_ENCRYPTION_FAILED`, `CREDENTIAL_PERSISTENCE_FAILED`, `CREDENTIAL_SECRET_VERSIONING_FAILED`, `CREDENTIAL_CREATE_INVALID`, and `CREDENTIAL_CREATE_FAILED`. Internal exception text is not returned for unclassified failures.

`CREDENTIAL_SECRET_VERSIONING_FAILED` means that encrypted persistence succeeded temporarily, initial Secret-Version recording failed, and the newly written Credential was removed again. The response therefore does not represent a Credential that remains visible in the Dashboard.

### Draft connection test

`POST /api/v1/credentials/test-connection` accepts the provider key, public metadata, and deliberately supplied secret fields collected by the Wizard. It validates the registered provider and field contract, then calls the existing Provider validation chain without creating a Credential, writing a secret version, or changing lifecycle state. A successful response contains only `providerKey`, `status`, `messageKey`, and `checkedAt`.

The response never returns submitted secrets, raw provider payloads, resolved target addresses, or internal exception text. Connection failures use the normal error envelope and stable public `CREDENTIAL_CONNECTION_*` codes, including target-blocked, DNS, authentication, permission, timeout, TLS, host-key, unsupported-provider, unavailable-provider, invalid-input, and generic-failure outcomes.

The test route is not a replacement for creation. A caller may save a Credential without a successful test; it remains `registered`. Stored validation continues to use `POST /api/v1/credentials/:credentialId/validate` and activates a Credential only after provider success.

### Credential update

`PUT /api/v1/credentials/:credentialId` is the only Credential-management update route. It accepts a patch containing optional `credentialMethodKey`, public `metadata`, and deliberately supplied `secrets`. When a method-aware Credential changes its method key, all submitted fields are revalidated against the newly selected, bound CredentialMethod. The server rejects edits to the Credential ID, Provider key, lifecycle state, creation time, system-managed metadata, OAuth redirect URI, and any field not marked as visible and user-configurable by the active CredentialMethod or legacy Provider compatibility contract.

The detail response and successful update response contain public data plus a `secretInventory` with presence information only. They never return secret values. Secret patches are merged by secret name: an omitted or empty secret does not change the encrypted stored value; a non-empty replacement value updates only the named secret and records a new secret version. Internal transfer and rollback workflows explicitly use their existing trusted replacement semantics.

Invalid provider fields, unknown providers, encryption failures, persistence failures, and secret-versioning failures use the standard error envelope. Clients must treat unknown response shapes as failures and must not surface raw exception text.

The list route supports `limit` or `pageSize`, `offset` or `page`, plus `search`, `provider`, `type`, `state`, `sort`, and `order`. Pagination values must be positive where applicable. The transfer routes accept transfer input as `transfer`, `payload`, or `content`; CSV processing is selected with `sourceFormat` or `format` set to `csv`.

## Consumer API

The Consumer API is a separate data-plane boundary for runtime applications. It is not a Credential-management route and does not use the compatibility `x-credential-hub-user` header. It exposes Discovery for public selection and Resolve for explicitly authorized Secret fields:

The identifier responsibilities are deliberately distinct: the Consumer API
uses the public opaque `credentialKey` for Discovery and Resolve, while the
Management API continues to use the internal-management `credentialId` for
credential administration and Consumer Grant provisioning. These identifiers
serve different boundaries and must not be substituted for one another.

| Method | Route | Authentication | Purpose |
|---|---|---|---|
| GET | `/api/v1/consumer/credentials` | Bearer API token | Discovers active, granted Credentials and their public selection metadata. |
| POST | `/api/v1/consumer/credentials/:credentialKey/resolve` | Bearer API token | Resolves explicitly requested, granted Credential secret fields for an active Credential. |

### Discover Credentials

`GET /api/v1/consumer/credentials` accepts no request body. It requires a
valid, active Bearer API token with the `credentials:consume` scope and an
owning user authorized for `credentials:consume`.

The response contains only active Credentials granted to the authenticated
Consumer. Each item contains an opaque public `credentialKey`, public display
metadata and the applicable public Field Contract. The projection never
contains Secret values, `credentialMethodKey`, ProviderMethodBinding,
Provider Adapter identity, internal database identifiers or runtime objects.
Provider selection and method routing remain internal.

Successful response (`200`):

```json
{
  "success": true,
  "meta": { "apiVersion": "v1" },
  "data": {
    "credentials": [
      {
        "credentialKey": "credential-public-key",
        "metadata": {
          "displayName": "Production API"
        },
        "fields": [
          {
            "name": "apiKey",
            "label": "API key",
            "inputType": "password",
            "required": true,
            "secret": true,
            "visible": true,
            "userConfigurable": false,
            "systemManaged": false
          }
        ]
      }
    ]
  }
}
```

An authenticated Consumer with no matching active grants receives `200` with
an empty `credentials` array. Invalid authentication returns `401`; missing
scope or denied Consumer authorization returns `403`. The response uses
`Cache-Control: no-store` because visibility is grant-specific. The
`credentialKey` is the only public selection identifier; it is not a Provider,
CredentialMethod or database identifier.

### Runtime-Public Discovery projection

In accordance with ADR-020 v1.3.0, Discovery may include an optional
Runtime-Public projection for an active Credential. The projection is a
normative, generic Consumer API capability and is not a separate endpoint or
consumer-specific configuration mechanism.

The projection is visible only when all of the following apply:

- the authenticated Consumer has a matching grant for the selected Credential;
- the Credential is active and consumable;
- the value originates from the Provider Configuration associated with that
  exact Credential; and
- the value is individually classified as Runtime-Public by the normative
  Provider-Configuration metadata contract.

Runtime-Public means both non-secret and explicitly allowlisted for Consumer
Runtime use. A value being non-secret is not sufficient for publication. The
projection is deny-by-default, credential- and Consumer-bound, and excludes
Secrets, internal identifiers, `credentialMethodKey`, ProviderMethodBinding
data, adapters, routing data and complete Provider Configuration.

Consumers cannot choose arbitrary fields, access another Credential's
Provider Configuration, or obtain provider-wide values. If the associated
Provider Configuration is missing or a permitted projection cannot be
generated, Discovery omits the projection and uses no fallback value,
Consumer configuration or environment variable. Existing Consumers must
tolerate the absence of the optional projection.

The projection retains the existing `Cache-Control: no-store` requirement and
must not be written to URLs, logs, error details, telemetry or unredacted
execution data. Resolve remains the sole Consumer operation for explicitly
requested and authorized Secret fields; this projection does not alter the
Resolve contract or Secret grants.

### Canonical Consumer Integration Algorithm

The following algorithm is the canonical Release 1.0 / Beta-1 integration
boundary for every runtime Consumer. It is language- and platform-independent.
The same sequence applies to an HTTP client, a script, an application service,
or a direct REST integration.

#### 1. Discovery

Call the public Consumer Discovery route:

```http
GET /api/v1/consumer/credentials
```

Treat a non-success response or an unexpected response shape as a failure. The
successful response contains only public Credential metadata and the public
Field Contract and, where authorized and available, the optional Runtime-Public
projection; it contains no Secret values.

#### 2. Runtime-Public projection

Use an available Runtime-Public value only when the target operation requires
it. Treat the value as optional public runtime input bound to the selected
Credential. Do not substitute a Consumer-specific configuration value or an
environment variable when the projection is absent.

#### 3. Credential Selection

Select exactly one Credential using configured business criteria over public
metadata. A selection implementation may use public display metadata and the
public Field Contract. The selection configuration distinguishes two sets of
field names:

- **Required Public Fields** must exist in the public Field Contract. They may
  have either `secret == false` or `secret == true` because this check validates
  only the public contract. Examples include `clientId`, `displayName` and
  `scopes`.
- **Required Secret Fields** must exist in the public Field Contract and must
  have `secret == true`. These are the only fields eligible to be requested
  later through Resolve. Examples include `clientSecret`, `apiKey`,
  `accessToken` and `refreshToken`.

Business criteria are Consumer-defined configuration values such as display
name, environment, tags, category or other public metadata. They must never
rely on Secrets, internal identifiers or implementation details.

The selection rules are:

- use public metadata and business criteria only;
- require every Required Public Field name to exist in the public Field
  Contract, regardless of its `secret` classification;
- require every Required Secret Field name to exist in the public Field
  Contract with `secret == true`;
- request only Required Secret Fields in the subsequent Resolve;
- do not use `visible` as a permission or Secret-eligibility test;
- do not use internal Credential IDs, ProviderMethodBinding data or
  `credentialMethodKey`;
- reject zero matches and reject multiple matches; and
- use the selected public `credentialKey` only for the subsequent Resolve.

`visible` remains presentation metadata for interfaces that render fields. It
does not replace the public Secret classification or the server-side grant
check. The Consumer API remains authoritative for whether a requested field
may actually be resolved.

#### 4. Resolve

Request only the Required Secret Fields needed by the target operation:

```http
POST /api/v1/consumer/credentials/{credentialKey}/resolve
Content-Type: application/json

{"secretNames":["<required-secret-field-name>"]}
```

Validate the response shape, lifecycle state and returned field set. Do not
broaden the field list after an error and do not retry with a Management Token.

#### 5. Target API

Use the resolved values only transiently to construct the target request. Do
not place them in source control, configuration committed to the application,
workflow notes, URLs, query parameters or diagnostic messages.

#### 6. Secure Disposal

After the target request has been constructed or completed, discard the
resolved values from the Consumer context as far as the runtime permits. Do
not persist them, log them, cache them, include them in retry payloads or
return them in complete node or execution output. Pass on only a minimal,
non-sensitive result. Honor `Cache-Control: no-store` and treat failed calls
as failures without automatic broadening or replay of Secret data.

#### Beta-1 workaround

Until future convenience features such as server-side Discovery filters or
native platform integrations are introduced through a separate decision, the
official Beta-1 workaround is a generic HTTP-client flow:

```text
HTTP Client
  → Discovery
  → Canonical Consumer Selection
  → Resolve
  → Target API
  → Secure Disposal
```

The workaround adds no endpoint, credential model or provider-specific API. It
is an integration procedure for the existing public Consumer contract. Every
runtime must apply the same selection, transient-use and disposal rules.

### Resolve a Credential

`POST /api/v1/consumer/credentials/:credentialKey/resolve` accepts a non-empty `secretNames` array. A request needs a valid, active Bearer API token with the `credentials:consume` scope, an owning user authorized for `credentials:consume`, and a matching Consumer Grant for the API-token identity, Credential, provider, and every requested secret field. Wildcard grants are not supported. The path segment is the opaque public `credentialKey`; existing credential-ID values may remain accepted there for backward compatibility, but internal database identifiers are not the canonical selection contract.

Administrators provision those grants through `POST /api/v1/management/consumer-grants`, which requires a **Management Token** with the `consumer-grants:manage` permission. The request body contains `consumerId` (the API-token ID), `credentialId`, `providerKey`, and a non-empty `secretNames` array. Provisioning is audit logged with the identity, Credential, provider, and field count, never with secret values or names. Management routes do not accept an identity header.

The Admin Consumer permissions page presents this existing contract without
changing it: Discovery is the public metadata and field-contract view, while
Resolve is the explicitly requested and authorized Secret-field operation.
The Consumer API Token authenticates the Consumer; the Management Token is
only for administration.

The Admin Grant form may show a read-only preview before a grant is saved. It
is a presentation of the selected Credential, existing Discovery and
Runtime-Public projections, selected Resolve Secret fields and excluded
fields; it does not execute an API request or create a grant. The server-side
grant and Resolve rules remain authoritative.

The Admin Wizard lists consumers with `GET /api/v1/management/api-tokens`, can create a dedicated consumer token with `POST /api/v1/management/api-tokens`, and uses `POST /api/v1/management/consumer-grants/diagnose` to test the selected grant without resolving a secret. The one-time plaintext consumer token and the Management Token are held only in browser memory; neither is written to browser storage.

Example grant request (replace placeholders in a secure shell or secret manager; do not commit tokens):

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer <management-api-token>" \
  -H "Content-Type: application/json" \
  -X POST "https://hub.example/api/v1/management/consumer-grants" \
  --data '{"consumerId":"consumer-token-id","credentialId":"credential-id","providerKey":"openai","secretNames":["apiKey"]}'
```

Only Credentials in lifecycle state `active` are consumable. Each requested name must be a Secret field in the selected CredentialMethod contract and must exist on the Credential. Credentials without a method key are not eligible for Consumer resolution. Before returning an authorized OAuth result, Sekalum may use the existing provider `refresh` capability to refresh an active credential whose access token is within the configured refresh window; the Consumer request and response contract remain unchanged. The Consumer API does not select, interpret or branch on a CredentialMethod; it uses the selected method contract only for Secret-field eligibility. The endpoint returns only the public `credentialKey`, lifecycle state and the requested, authorized name/value pairs. It responds with `Cache-Control: no-store` on both success and failure.

Request:

```json
{
  "secretNames": ["apiKey"]
}
```

Successful response (`200`):

```json
{
  "success": true,
  "meta": { "apiVersion": "v1" },
  "data": {
    "credentialKey": "credential-public-key",
    "providerKey": "openai",
    "lifecycleState": "active",
    "secrets": {
      "apiKey": "<resolved-secret>"
    }
  }
}
```

Errors use the standard envelope. `INVALID_SECRET_REQUEST` returns `400`; `API_TOKEN_AUTH_FAILED` returns `401`; `CONSUMER_SCOPE_MISSING` and `CONSUMER_ACCESS_DENIED` return `403`; `CREDENTIAL_NOT_FOUND` returns `404`; and `CREDENTIAL_NOT_CONSUMABLE` returns `409`. Other consumer access and grant failures use `RESOLVE_NOT_AVAILABLE` with `403`. Consumers must treat all other response shapes as failures and must not log or cache resolved values.

Each attempt is audit logged without secret names, values, bearer tokens, request bodies, or hashes. Audit data is limited to the consumer/API-token ID, safely known Credential ID, provider key, result, stable reason, and the requested secret-field count.

## Provider and dashboard routes

| Method | Route | Permission | Purpose |
|---|---|---|---|
| GET | `/api/v1/providers` | `providers:read` | Lists public provider metadata. |
| POST | `/api/v1/providers` | `providers:manage` | Creates and persists a declarative custom provider. |
| GET | `/api/v1/providers/:providerKey` | `providers:read` | Returns public metadata for one provider. |
| GET | `/api/v1/providers/:providerKey/capabilities` | `providers:read` | Returns provider capabilities. |
| POST | `/api/v1/providers/:providerKey/oauth/start` | `providers:manage` | Validates and encrypts Wizard-supplied OAuth application configuration, then returns the provider authorization URL. |
| GET | `/api/v1/dashboard` | `management:read` | Returns the administration dashboard. |

`/api/v1/dashboard` accepts `expiringWithinDays`; it must be a positive integer.
The response also contains `integrationHealth`, an administrator-facing
projection derived from existing Credential, Consumer Grant, Provider
capability, expiration, rotation, history and Resolve-boundary state. It
contains only statuses, counts, provider keys and non-secret display metadata;
it never returns Secret or Token values and does not perform health probes,
refreshes or repairs.

### Provider metadata response

Provider list and detail responses contain only public metadata. In addition to `key`, `displayName`, `description`, `category`, `customProvider`, and `capabilities`, the response may include `credentialFields`, `providerConfigurationFields`, `authType`, `defaultScopes`, `oauthSecurity`, and `oauthTechnical`. `customProvider` is `true` for declarative user-created providers and `false` for integrated providers. Every response contains `credentialMethods` and `providerMethodBindings` as arrays (possibly empty). A credential method supplies its declarative field schema and declared operation capabilities; a binding makes that method available for the provider and supplies public display metadata. Neither array serializes operation adapters, Provider instances, API clients, secrets, or other runtime objects. For OAuth providers, `oauthTechnical` contains the public authorization endpoint plus the runtime-derived `callbackPath` and `redirectUri`. Field definitions describe UI handling through `visible`, `userConfigurable`, `systemManaged`, and `readonly`; fields marked as secrets never expose a secret value. System-managed fields remain part of the backend contract but are not rendered as Wizard inputs.

### Create declarative custom provider

`POST /api/v1/providers` accepts only a data-only custom-provider definition: `key`, `displayName`, `category`, optional `description`, non-empty `credentialMethods`, matching `providerMethodBindings`, and matching root-level `credentialFields`. Each method declares its own field schema; the root field list must contain exactly those method fields. A successful request returns `201` and the same public provider summary used by the list and detail routes. The provider is registered immediately and therefore appears in the next Credential Wizard provider request.

The endpoint rejects provider-configuration fields, OAuth configuration, runtime operations, executable code, hooks, scripts, Provider/API-client objects, and secret-value containers. A field may be marked `secret` to describe how a future credential value is handled, but no secret value belongs in a provider definition. Invalid definitions return `400 PROVIDER_DEFINITION_INVALID`; a key that is already registered returns `409 PROVIDER_ALREADY_EXISTS`.

The OAuth-start request body contains user-configurable `providerConfiguration` and optional `scopes`. Any client-supplied `redirectUri` is ignored and replaced with the callback URI derived from `PUBLIC_BASE_URL` or the validated request origin, active `BASE_PATH`, and provider key. A successful response returns the authorization URL, redirect URI, callback path, effective scopes, and an opaque provider-configuration ID. It never echoes provider configuration values. Validation and startup failures return stable codes such as `PROVIDER_CONFIGURATION_MISSING` or `OAUTH_START_FAILED` through the standard error envelope.

The browser callback result uses the stable outcome codes `OAUTH_CALLBACK_FAILED`, `OAUTH_STATE_INVALID`, `OAUTH_PROVIDER_REJECTED`, and `OAUTH_REDIRECT_URI_MISMATCH`. The mismatch result may include the non-secret redirect URI used by Sekalum; the HTML result page does not expose raw provider or backend messages.

## Management routes

| Method | Route | Permission | Purpose |
|---|---|---|---|
| GET | `/api/v1/management/status` | `management:read` | Aggregated management status. |
| GET | `/api/v1/management/providers` | `providers:read` | Provider management overview. |
| POST | `/api/v1/management/providers/:providerKey/health-check` | `providers:manage` | Runs a provider health check. |
| GET | `/api/v1/management/scheduler` | `scheduler:read` | Scheduler status. |
| POST | `/api/v1/management/scheduler/start` | `scheduler:manage` | Starts the scheduler. |
| POST | `/api/v1/management/scheduler/stop` | `scheduler:manage` | Stops the scheduler. |
| POST | `/api/v1/management/scheduler/run-once` | `scheduler:manage` | Runs the scheduler once. |
| GET | `/api/v1/management/credentials` | `credentials:read` | Credential management overview. |
| GET | `/api/v1/management/users` | `users:read` | Lists users. |
| POST | `/api/v1/management/users` | `users:manage` | Creates a user. |
| PUT | `/api/v1/management/users/:userId` | `users:manage` | Updates a user. |
| DELETE | `/api/v1/management/users/:userId` | `users:manage` | Deletes a user and returns `204` on success. |
| GET | `/api/v1/management/roles` | `users:read` | Lists available roles. |
| GET | `/api/v1/management/audit-log` | `audit:read` | Lists audit entries. |
| GET | `/api/v1/management/audit-log/:entryId` | `audit:read` | Returns one audit entry. |
| GET | `/api/v1/management/api-tokens` | `api-tokens:read` | Lists API-token metadata. |
| POST | `/api/v1/management/api-tokens` | `api-tokens:manage` | Creates an API token; its plaintext value is returned only at creation. |
| GET | `/api/v1/management/api-tokens/:tokenId` | `api-tokens:read` | Returns API-token metadata. |
| DELETE | `/api/v1/management/api-tokens/:tokenId` | `api-tokens:manage` | Revokes an API token. |
| POST | `/api/v1/management/consumer-grants` | `consumer-grants:manage` | Creates a least-privilege Consumer Grant. |
| POST | `/api/v1/management/consumer-grants/diagnose` | `consumer-grants:manage` | Diagnoses a proposed or stored Consumer Grant without returning secrets. |
| GET | `/api/v1/management/exports` | `export:read` | Lists exportable resources. |
| GET | `/api/v1/management/exports/:resource` | `export:read` | Returns an export in the controller-selected format. |
| GET | `/api/v1/management/metrics` | `metrics:read` | Returns operating metrics. |
| GET | `/api/v1/management/backups` | `backup:read` | Lists management backups. |
| POST | `/api/v1/management/backups` | `backup:manage` | Creates a management backup. |
| GET | `/api/v1/management/backups/:backupId` | `backup:read` | Returns a management backup. |
| POST | `/api/v1/management/backups/:backupId/restore` | `backup:manage` | Restores a management backup. |

## Verification boundary

This reference was checked against `src/oauth/oauth-callback-server.js`, all controllers under `src/controllers/`, and the API integration tests. It does not define provider fields, runtime configuration, deployment endpoints, or historical API behavior.

The former [REST notes](../api/REST_API.md), [OAuth notes](../api/OAuth_API.md), and [Health notes](../api/Health_API.md) remain supporting pointers to this canonical source.
