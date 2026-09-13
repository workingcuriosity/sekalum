---
title: Configuration Reference
document_id: DOC-CONFIGURATION-REFERENCE-INDEX
classification: PUBLIC
language: en
version: 1.0.9
status: Active
category: Configuration
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Administratoren
  - Betreiber
  - Entwickler
dependent_documents:
  - docs/api-reference/index.md
  - docs/providers/README.md
  - docs/adr/ADR-031-OAuth-Context-Binding.md
change_history:
  - version: 1.0.9
    date: 2026-09-06
    change: Derives the canonical deployment-unique Bootstrap proof contract: missing, shipped/example and documentation-placeholder values are invalid; runtime enforcement remains separately authorized.
  - version: 1.0.8
    date: 2026-09-06
    change: Documents the RC3-12 Slice B enforced exact private-network exception configuration.
  - version: 1.0.7
    date: 2026-09-06
    change: Derives the RC3-12 Slice B production public-origin and trusted-proxy configuration guidance from ADR-031 without claiming runtime enforcement.
  - version: 1.0.6
    date: 2026-08-26
    change: Adds the high-entropy ADMIN_BOOTSTRAP_TOKEN configuration and fail-closed Bootstrap semantics.
  - version: 1.0.5
    date: 2026-08-24
    change: Records explicit English as the current governed documentation language.
  - version: 1.0.4
    date: 2026-08-24
    change: Completes the canonical header metadata for the current documentation source.
  - version: 1.0.3
    date: 2026-07-13
    change: Classifies OAuth redirect URIs as system-managed values derived from request origin, BASE_PATH, and provider metadata.
  - version: 1.0.2
    date: 2026-07-12
    change: Documents Wizard-managed encrypted OAuth application configuration and environment fallback precedence.
  - version: 1.0.1
    date: 2026-07-12
    change: Documents the BASE_PATH contract for reverse-proxy deployments.
  - version: 1.0.0
    date: 2026-07-11
    change: CP-005 verifiziert die aktive globale Konfiguration gegen Config, Container, OAuth-Services und Persistenztests.
---

# Configuration Reference

## Scope

The active application creates `Config` from the process environment in `ApplicationServiceProvider`. A missing value requested through `Config.require()` stops the dependent operation with `Missing required config value: <KEY>`.

This reference contains only global runtime configuration. FTP, SFTP, and OpenAI connection data belongs to individual credentials and is not configured as a global environment variable. `src/config/env.js` is not part of the current bootstrap path and is not an active configuration contract.

## Runtime and scheduling

| Key | Required | Default | Purpose |
|---|---|---:|---|
| `OAUTH_CALLBACK_PORT` | No | `3000` | HTTP port for the callback and REST server. |
| `OAUTH_WIZARD_INTENT_TTL_MS` | No | `600000` | Existing governed lifetime for OAuth state, browser wizard intent, and flow-owned cleanup. |
| `BASE_PATH` | No | `/` | Public path prefix for the admin interface, REST API, health endpoint, and OAuth callbacks. |
| `CHECK_INTERVAL_HOURS` | No | `12` | Interval for refresh and rotation scheduler jobs. |
| `REFRESH_BEFORE_DAYS` | No | `14` | Threshold used by credential lifecycle refresh logic. |
| `ADMIN_BOOTSTRAP_TOKEN` | Required for first setup | None | Deployment-unique, high-entropy proof of at least 32 bytes for the one-time First Administrator Bootstrap; shipped/example and documentation-placeholder values are invalid. |

## Bounded private FTP/SFTP connection targets

Private RFC1918 or IPv6 ULA targets remain denied by default. The legacy
`CONNECTION_TEST_ALLOW_PRIVATE_NETWORKS=true` compatibility input has no effect
by itself. A deployment that must test one private FTP or SFTP target must also
set `CONNECTION_TEST_PRIVATE_EXCEPTION` to a JSON object containing all of
`protocol`, `purpose`, `hostname`, `cidr` (or `cidrs`) and `port`. The
separate compatibility input must be set to the literal string `true`.

The exception object has this schema (replace every angle-bracketed value with
the one bounded deployment target):

```json
{
  "protocol": "<ftp-or-sftp>",
  "purpose": "<bounded-connection-purpose>",
  "hostname": "<normalized-hostname>",
  "cidr": "<resolved-address-cidr>",
  "port": "<destination-port>"
}
```

The runtime normalizes the hostname and requires an exact protocol, purpose,
hostname, resolved-address/CIDR and port match. Only `ftp` or `sftp` with
`CREDENTIAL_CONNECTION_TEST`, `PROVIDER_VALIDATION`, or
`PROVIDER_HEALTH_CHECK` can use this exception. It never permits loopback,
link-local, metadata, unspecified, multicast, reserved/special or CGNAT
targets, and it is not an OAuth or general egress control. Rotate or remove the
exception when the bounded operational need ends.

## Encryption at rest

Use either the single-key form or the versioned-key form. Keys must contain exactly 32 characters. Do not commit real values.

```env
TOKEN_ENCRYPTION_KEY=YOUR_32_CHARACTER_ENCRYPTION_KEY
ADMIN_BOOTSTRAP_TOKEN=YOUR_HIGH_ENTROPY_BOOTSTRAP_TOKEN
```

```env
# TOKEN_ENCRYPTION_KEYS: JSON object with versioned 32-character keys
# TOKEN_ENCRYPTION_KEY_VERSION: numeric version for new writes
```

`TOKEN_ENCRYPTION_KEYS` must be a non-empty JSON object with numeric versions. `TOKEN_ENCRYPTION_KEY_VERSION` selects the key used for new writes; old versions must remain available while payloads still reference them. The Storage Developer Guide defines the persistence and rotation behavior.

### Bootstrap configuration

`ADMIN_BOOTSTRAP_TOKEN` is the explicit proof-of-possession secret for the
one-time First Administrator operation. It must be a high-entropy value of at
least 32 bytes and be deployment-unique and operator supplied. A missing,
shipped/example, documentation-placeholder, weak or invalidly supplied value
fails closed; the empty user collection is not an authorization grant. The
Bootstrap token is
distinct from `TOKEN_ENCRYPTION_KEY`, a Management Token and an API token. It
is never persisted as an API token, returned, logged, audited or serialized in
application output. After the first active administrator is durably persisted,
the Bootstrap operation is closed and normal management requests require
Bearer authentication, scope validation and RBAC. A value is not admissible
solely because it meets the length requirement; runtime admission rejects
low-diversity, repeated-pattern and monotonic values and requires a minimum
measured byte entropy in addition to the 32-byte floor: at least 8 distinct
UTF-8 bytes, at least 3.5 bits of Shannon entropy per byte, no repeated pattern
of period 16 bytes or less, and no monotonic run of 8 bytes or more. Sekalum
provides no Bootstrap default. The [Security Guide](../security-guide/index.md#first-administrator-bootstrap-boundary)
owns this contract.

## OAuth provider application configuration

Release 1.0 uses **Wizard-managed provider application configuration** as the normal OAuth path. The Wizard requests the provider's client ID, client secret where required, and scopes from public provider metadata. The redirect URI is system-managed metadata (`visible: false`, `userConfigurable: false`, `systemManaged: true`) and is never accepted as a user decision. The OAuth-start route derives it from `PUBLIC_BASE_URL` when configured, otherwise from the validated request origin, plus `BASE_PATH` and the provider key. The Wizard exposes the resulting redirect URI, authorization endpoint, callback path, and scopes as read-only technical details. These values are application credentials for the provider integration; they are distinct from the user credential created by a successful OAuth callback.

Provider application secrets are never returned by the Provider API, OAuth-start response, callback result page, or browser message. The browser stores neither client IDs nor client secrets in local storage. The encrypted record is referenced by an internal configuration ID so refresh operations can reuse the same application configuration.

The browser callback is bound to the initiating authenticated actor with a short-lived, state-specific HttpOnly/SameSite cookie; the callback does not accept an actor supplied by query string, header, or form input. OAuth state and the wizard intent are one-shot and use the same governed `OAUTH_WIZARD_INTENT_TTL_MS` lifetime. Expired flow state is purged without extending its lifetime. The record becomes durable only as part of a successfully imported OAuth credential. Sekalum removes flow-owned records after OAuth-start failure, provider cancellation, callback or token-exchange failure, credential-import failure, or expiry. On restart, only provider-configuration records unreferenced by persisted Credentials are removed; referenced durable configuration is preserved.

Environment variables remain a compatibility fallback for existing deployments and the legacy `GET /oauth/:provider/login` entry point. Resolution order is:

1. complete Wizard-supplied provider configuration;
2. provider-specific environment variables;
3. a stable `PROVIDER_CONFIGURATION_MISSING` error without the missing value or secret.

Configure only providers that are used.

| Provider | Required keys |
|---|---|
| Threads | `THREADS_CLIENT_ID`, `THREADS_CLIENT_SECRET`, `THREADS_REDIRECT_URI` |
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` |
| Twitch | `TWITCH_CLIENT_ID`, `TWITCH_CLIENT_SECRET`, `TWITCH_REDIRECT_URI` |
| Kick | `KICK_CLIENT_ID`, `KICK_CLIENT_SECRET`, `KICK_REDIRECT_URI` |
| Discord | `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `DISCORD_REDIRECT_URI` |
| X | `X_CLIENT_ID`, `X_REDIRECT_URI`; `X_CLIENT_SECRET` is optional. |
| Facebook | `FACEBOOK_CLIENT_ID`, `FACEBOOK_CLIENT_SECRET`, `FACEBOOK_REDIRECT_URI` |
| Instagram | `INSTAGRAM_CLIENT_ID`, `INSTAGRAM_CLIENT_SECRET`, `INSTAGRAM_REDIRECT_URI` |

Use neutral placeholders when preparing an environment file:

```env
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI=YOUR_GOOGLE_REDIRECT_URI
```

The derived redirect URI must match the registration of the respective OAuth provider. Administrators register the deployed public callback URI with the provider, but do not enter it in the Wizard. When `BASE_PATH` is configured, include it in the provider registration, for example `https://sekalum.example.com/credential-hub/oauth/google/callback`. The X client secret is optional; all other built-in OAuth providers require it. Provider-specific fields and capabilities are defined by provider metadata.

## Base path and reverse proxies

`BASE_PATH` is either `/` or a slash-prefixed path made of path segments such as `/credential-hub`. Leading and trailing slashes are normalized. Empty values use `/`. Query strings, fragments, whitespace, and empty path segments are rejected at startup.

```env
BASE_PATH=<YOUR_BASE_PATH>
```

For deployments behind a reverse proxy, configure the public origin separately
so OAuth never derives an internal host or protocol:

```env
PUBLIC_BASE_URL=<YOUR_PUBLIC_ORIGIN>
```

`PUBLIC_BASE_URL` is optional for direct deployments. In production, when set,
it must be an absolute HTTPS origin without credentials, path, query, or
fragment. A direct production origin is HTTPS as well. HTTP is allowed only in
an explicitly non-production development or test deployment. The Wizard and
OAuth-start route use the same value and report `OAUTH_REDIRECT_URI_MISMATCH`
with the actually used, non-secret redirect URI if the displayed and generated
values diverge.

For a TLS-terminating production reverse proxy, configure the proxy explicitly
with `TRUSTED_PROXY`. Its value is an explicit `loopback`, `linklocal`, or
`uniquelocal` boundary, or one or more explicit IP/CIDR values; broad `/0`
values are invalid. Forwarded host or protocol headers from all other peers are
untrusted and cannot establish or override the public origin. The exact
security rule, including the requirement for a Secure OAuth browser-binding
cookie in production, is owned by
ADR-031.

For example, set `BASE_PATH=/credential-hub` when the public service is hosted below that prefix; `PUBLIC_BASE_URL` remains the external origin such as `https://sekalum.example.com`.

With this configuration, the public routes are prefixed consistently:

- Admin UI: `/credential-hub/admin/`
- Health endpoint: `/credential-hub/health`
- REST API: `/credential-hub/api/v1/...`
- OAuth callback: `/credential-hub/oauth/<provider>/callback`

The reverse proxy must forward the complete prefixed path unchanged. Do not configure a proxy rule that strips `/credential-hub` before forwarding the request.

## Admin UI language

The Admin UI language is not server configuration. It is resolved in the browser from a valid local `credentialHub.language` preference, otherwise from a browser language beginning with `de`, and otherwise from English. Do not add this preference to credential data, provider metadata, logs, or environment variables.

## Validation and ownership

- `Config.get()` supplies defaults where the active code defines them.
- `Config.require()` validates presence for the code path that uses the value.
- `EncryptedJsonStore` validates encryption key structure, numeric key versions, and 32-character key length.
- The callback server converts `OAUTH_CALLBACK_PORT` to a number and validates `BASE_PATH` before it mounts the HTTP routes.

## Declarative custom providers

`CUSTOM_PROVIDER_DEFINITIONS` remains an optional, deployment-managed JSON configuration source for metadata-only custom providers. It must be a JSON array. Existing entries supply a lowercase kebab-case name, display name, supported authentication type, and one or more credential fields.

```json
[
  {
    "name": "example-api",
    "displayName": "Example API",
    "authType": "api-key",
    "credentialFields": [
      { "key": "displayName", "label": "Display name", "required": true },
      { "key": "apiKey", "label": "API key", "type": "api-key", "required": true, "secret": true, "csvAliases": ["api_key"] }
    ]
  }
]
```

Administrators can instead create a new declarative provider through **Custom providers** in the Admin UI. This persists the validated definition in the application storage area and hydrates it on the next start; no change to `CUSTOM_PROVIDER_DEFINITIONS`, an environment file, or a project file is required. UI-created providers accept identity, category, display metadata, credential methods, credential fields, and method bindings only. Provider-configuration fields, OAuth configuration, runtime operations, executable code, hooks, scripts, and definition secrets are rejected. Invalid UI definitions are rejected without registration.

Custom provider definitions cannot contain executable code, modules, OAuth endpoints, or runtime operations. Supported legacy configuration authentication types are `api-key`, `username-password`, `connection`, and `manual`. Invalid legacy configuration definitions fail registration during startup. See the Provider Metadata Guideline for the complete contract.

## Verification boundary

CP-005 verified this document against `src/config/config.js`, `src/container/application-service-provider.js`, `src/oauth/`, `src/api/`, `src/scheduler/scheduler-service.js`, `src/storage/encrypted-json-store.js`, and the encryption and OAuth tests. It does not define provider credential payloads, installation, operations, or private deployment values.
