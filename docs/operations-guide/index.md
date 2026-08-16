---
title: Operations Guide
version: 1.3.0
status: Active
category: Operations
canonical: true
maintainer: cyphre-san productions
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 cyphre-san productions"
target_audience:
  - Betreiber
  - Administratoren
dependent_documents:
  - docs/security-guide/index.md
  - docs/project/Storage.md
  - docs/api-reference/index.md
change_history:
  - version: 1.3.0
    date: 2026-08-09
    change: Documents operational interpretation of the Issue #77 secret-free Integration Health dashboard projection.
  - version: 1.2.1
    date: 2026-08-04
    change: Links the neutral deployment security recommendations without duplicating them.
  - version: 1.1.1
    date: 2026-07-17
    change: Adds BASE_PATH and reverse-proxy troubleshooting with deployment-evidence limits.
  - version: 1.2.0
    date: 2026-08-04
    change: Clarifies the operator-controlled provisioning boundary for the first Management Token.
  - version: 1.1.0
    date: 2026-07-13
    change: Adds versioned-image and Credential-management operational verification.
  - version: 1.0.1
    date: 2026-07-12
    change: Adds operational checks for BASE_PATH and reverse-proxy forwarding.
  - version: 1.0.0
    date: 2026-07-12
    change: CP-008B erstellt eine neutrale Betriebsreferenz ohne private Infrastrukturwerte.
---

# Operations Guide

## Management Token provisioning boundary

Beta 1 does not define an in-application process for creating the first
Management Token. After the First Administrator is created during Bootstrap,
the operator provisions an authorized API token through the existing
operator-controlled deployment and secret-management process and supplies it
to the administrator through the approved operational channel.

Sekalum consumes that already provisioned token as
`Authorization: Bearer <management-token>` for protected Admin requests. This
Operations Guide does not prescribe a host, secret manager, token-generation
command or infrastructure product; those remain deployment decisions. Never
place a token in the repository, `.env` committed to source control, URLs,
screenshots or logs. The Admin UI and API Reference remain the canonical
sources for token use and authorization behavior.

## Health and monitoring

`GET /health` returns application liveness when `BASE_PATH` is `/`. With a configured base path, monitor `GET <BASE_PATH>/health`, for example `GET /credential-hub/health`. The authenticated management and metrics routes are defined in the [API Reference](../api-reference/index.md). Scheduler status and provider health checks require the corresponding API permissions.

When operating behind a reverse proxy, verify that the public Admin UI, health endpoint, REST API, and OAuth callback retain the same `BASE_PATH`. A 404 response for an unprefixed route is expected when a non-root base path is configured. A proxy that strips the prefix is a deployment error.

## BASE_PATH and reverse-proxy troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| Admin UI works but API returns `404` | A browser request or proxy route lost the base path. | Compare the requested API route with `<BASE_PATH>/api/v1/...`; a correctly loaded Admin asset does not make an unprefixed API route valid. |
| Root works but the subpath does not | The external proxy route does not forward the complete prefix, or it differs from `BASE_PATH`. | Check the public route and the configured `BASE_PATH` together. |
| The prefix appears twice | `PUBLIC_BASE_URL`, the proxy target, or a rewrite already contains the prefix. | Keep `PUBLIC_BASE_URL` origin-only and apply `BASE_PATH` once. |
| The proxy removes the prefix | The app receives a route that does not match its mounted router. | Remove prefix stripping; it can cause `404`, incorrect redirects, and a missing OAuth callback. |
| OAuth shows an internal host/protocol or `OAUTH_REDIRECT_URI_MISMATCH` | `PUBLIC_BASE_URL` is absent or incorrect, or the provider registration differs. | Check public origin, `BASE_PATH`, the displayed redirect URI, and the provider registration exactly. |
| Admin works but OAuth does not | The callback registration or proxy path differs from the active prefix. | Confirm the exact public callback URI and that no proxy rewrite strips its prefix. |
| An unprefixed health route returns `404` | A non-root base path is active. | Use `<BASE_PATH>/health`; the unprefixed route is expected to be absent. |

The application is designed for path-preserving reverse-proxy deployment, and the Installation Guide provides neutral examples. Product-specific proxy behavior and public OAuth end-to-end verification remain deployment checks; this guide does not claim them as completed tests.

## Backups and restore

The active application exposes authenticated management backup routes for listing, creating, reading, and restoring management backups. Persisted backup data follows the encrypted storage path documented in the Storage Developer Guide.

Before a restore, verify authorization, backup identity, and the operational impact. This guide does not prescribe a host-specific storage location or service command.

## Maintenance

Run the repository checks after application changes:

```bash
npm run check
npm test
```

After an Admin UI or Credential-management update, rebuild the declared versioned image without cache and verify the dashboard and `/admin/credentials.html` in a browser. Repeat this check through the configured `BASE_PATH` when applicable. Confirm that secrets are absent from list, edit, error, and response views, and that the Dashboard refreshes the persisted count after navigation.

The Dashboard Integration Health view is observational only. It derives
Healthy, Warning, Error and Unknown states from existing credential lifecycle,
grant, provider capability, expiration, rotation, history and Resolve-boundary
data. It does not call providers, refresh tokens, alter grants or repair
integrations. Treat an Error or Unknown state as a prompt to inspect the
existing Credential, Provider, Grant or scheduler views; never copy token or
Secret values into an operational report.

### OAuth token rotation

The scheduler checks active OAuth Credentials against their stored expiration
metadata and the configured `REFRESH_BEFORE_DAYS` window. A Consumer Resolve
request also performs the same due check before returning an authorized Secret
result. When the selected Provider and CredentialMethod declare the existing
`refresh` capability, the Provider refresh operation runs and the new access
token, optional refresh token, expiration and metadata are persisted through
the canonical encrypted Credential store and Secret-Version path. Providers
without refresh support are not refreshed. Refresh failures do not replace the
stored Credential and are reported through the existing safe Resolve failure
handling. Operators must not inspect or retain token values in logs,
screenshots or deployment evidence.

Review encryption-key rotation through the [Configuration Reference](../configuration-reference/index.md) before removing historical keys. Automatic bulk re-encryption is not part of the active storage path.

When `CUSTOM_PROVIDER_DEFINITIONS` is configured, treat it as controlled runtime configuration. Review changes with the same care as other credential configuration: invalid definitions block provider registration, and declarative providers do not add runtime validation, refresh, revoke, or OAuth behavior.

## Scope boundary

No specific domain, certificate, host path, container name, or platform service manager is required by this guide. Reverse proxies must preserve the configured base path; the [Installation Guide](../installation-guide/index.md) provides neutral examples. For public Admin deployments, see the [Deployment Security Recommendations](../security-guide/index.md#deployment-security-recommendations). Historical deployment and infrastructure notes are not current operations instructions.
