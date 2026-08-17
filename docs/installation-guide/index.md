---
title: Installation Guide
version: 1.4.0
status: Active
category: Installation
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Administratoren
  - Betreiber
dependent_documents:
  - docs/configuration-reference/index.md
  - docs/security-guide/index.md
  - docs/operations-guide/index.md
change_history:
  - version: 1.2.0
    date: 2026-07-16
    change: Defines the self-contained Public Beta Compose startup path.
  - version: 1.3.0
    date: 2026-08-04
    change: Documents the Beta-1 Bootstrap, First Administrator creation and Management Token access gate.
  - version: 1.4.0
    date: 2026-08-04
    change: Adds the complete Beta-1 first-installation workflow from health check through Consumer Resolve and common first-installation problems.
  - version: 1.1.0
    date: 2026-07-13
    change: Documents the explicit versioned Docker image contract.
  - version: 1.0.1
    date: 2026-07-12
    change: Adds base-path and reverse-proxy installation guidance.
  - version: 1.0.0
    date: 2026-07-12
    change: CP-008B erstellt eine neutrale Installationsreferenz ohne private Infrastrukturwerte.
---

# Installation Guide

## Prerequisites

For local development, use a supported Node.js runtime and install the repository dependencies from the lockfile:

```bash
npm ci
```

For the Public Beta Docker path, install Docker Desktop or Docker Engine with the Compose plugin instead.

## Configuration

Create a local environment file from the public template before starting Compose:

```bash
cp .env.example .env
```

The template contains safe development defaults. Replace `TOKEN_ENCRYPTION_KEY` with a unique 32-character secret before storing real credentials, and never commit `.env`. Follow the [Configuration Reference](../configuration-reference/index.md) for encryption, OAuth, scheduler, and callback settings.

If declarative custom providers are required, validate `CUSTOM_PROVIDER_DEFINITIONS` as JSON before startup. Invalid custom-provider definitions stop registration and must be corrected before the application can start.

## First start and Bootstrap

Beta 1 does not provide a username/password login. When the persisted user
collection is empty, the service is in **Bootstrap** mode. Create the
**First Administrator** through the local Management API while the service is
still restricted to the local machine:

```bash
curl --request POST http://localhost:3000/api/v1/management/users \
  --header 'Content-Type: application/json' \
  --data '{"userId":"admin","displayName":"First Administrator","roleKey":"admin"}'
```

Bootstrap ends immediately after the **First Administrator** is persisted. The
Admin UI then requires an authorized **Management Token**. Its login gate
validates the token against the protected management API and uses
`Authorization: Bearer <management-token>` for subsequent Admin UI requests.
The Dashboard and Admin navigation remain hidden until validation succeeds.

The `x-credential-hub-user` header is not part of the production
authentication model. It is retained only for `NODE_ENV=test` compatibility
tests and must not be used in a deployed installation.

## Complete First Installation Workflow

The following sequence is the canonical Beta-1 first-installation path. Use
either the local Node.js start or the Docker Compose start above; do not expose
the service publicly before the First Administrator and Management Token gate
are in place.

### 1. Install, start and check health

Install the locked dependencies for a local start with `npm ci`, or start the
self-contained Compose deployment with `docker compose up --build`. With the
default root deployment, verify the service before continuing:

```bash
curl --fail http://localhost:3000/health
```

The expected result is HTTP `200` with a response containing
`{ "status": "UP" }`. If a `BASE_PATH` is configured, use
`GET <BASE_PATH>/health` instead.

### 2. Bootstrap the First Administrator

When the persisted user collection is empty, Bootstrap is active. While the
service is still restricted to the local machine, create exactly one First
Administrator through the local Management API using the command above.

The expected result is a successful creation response. The user is persisted
and Bootstrap ends immediately; subsequent management requests require normal
authentication. Do not repeat the creation request as a way to create a
second bootstrap administrator.

### 3. Enter the Management Token

Obtain an authorized Management Token through the configured operational
mechanism. Beta 1 has no integrated password-login or first-token creation
dialog; the Admin UI accepts an already provisioned token. Open `/admin/` and
enter the token in the Administrator access form.

The first Management Token is therefore provisioned outside Sekalum
through the existing operator-controlled [Management Token provisioning
boundary](../operations-guide/index.md#management-token-provisioning-boundary).
Sekalum does not define a separate first-token creation workflow.

The Admin UI validates the token against `/api/v1/dashboard` and then sends it
as `Authorization: Bearer <management-token>`. The expected result is that the
login gate disappears and the Dashboard, Admin navigation and Credential
Wizard become visible. A Management Token is an Admin credential; it is not a
Consumer API token.

### 4. Create and prepare the first Credential

Open the Credential Wizard, select an authentication method and Provider, and
enter only the fields requested by the Provider metadata. For OAuth, complete
the Provider authorization using the system-managed redirect URI shown by the
Wizard. Review the summary and choose **Credential anlegen**.

The expected result is a Credential visible in the Dashboard with its public
metadata and lifecycle state. Validate or activate it through the available
Provider workflow before using it from a Consumer; the API contract never
returns Secret values.

### 5. Create the Consumer token, Grant and first Resolve

1. In **API Tokens**, create a dedicated Consumer API token for the Consumer's
   user identity with the `credentials:consume` scope. Copy its plaintext only
   at creation time; it is not shown again.
2. In the Wizard's Consumer setup or **Consumer Grants** page, create a Grant
   for that Consumer token, the prepared Credential and Provider, and only the
   required Secret field names. Use the Management Token for this
   administrator-only operation.
3. Choose **Open Consumer interface** after the setup, or open `/consumer/`
   directly. Enter the dedicated Consumer API token; the Management Token and
   Admin context are not transferred.
4. Choose **Test connection** for Discovery, select the returned Credential,
   select only the permitted Secret fields, and choose **Resolve selected
   secrets**.

The expected result is a successful Resolve response in the protected result
area. Values are masked by default and must not be copied into logs,
screenshots or source code. The canonical API contract is in the [API
Reference](../api-reference/index.md#canonical-consumer-integration-algorithm).

### 6. First-installation completion criteria

The first installation is complete when all of the following are true:

- the health endpoint returns HTTP `200` and `status: UP`;
- the First Administrator exists and Bootstrap is no longer active;
- the Admin UI accepts the authorized Management Token and shows the Dashboard;
- at least one prepared Credential is visible and usable for the selected flow;
- a dedicated Consumer API token and matching least-privilege Grant exist; and
- the Consumer completes Discovery and a successful Resolve for an authorized
  Secret field.

The completion criteria describe the operational handover state. They do not
create a new API, security rule or architecture decision.

## Typical First Installation Problems

- **Bootstrap is not active:** The persisted user collection is not empty.
  Use an existing authorized Management Token; do not delete storage to force
  Bootstrap in a deployed installation.
- **Management Token is invalid:** Re-enter the authorized Bearer token and
  confirm that it belongs to a user with the required management permissions.
  `x-credential-hub-user` is test-only and is not a production login method.
- **Dashboard remains locked:** The token has not passed the dashboard
  validation, or the Admin request path does not match `BASE_PATH`. Check the
  health endpoint and reload the Admin UI.
- **Health endpoint is unreachable:** Confirm that the service is running,
  port `3000` is available, and the configured base path is included in the
  request.
- **Resolve fails:** Confirm that the Credential is active, the Consumer token
  has `credentials:consume`, the token owner is authorized, and the Grant
  covers the exact Credential, Provider and requested Secret field names.

## Local start and validation

```bash
npm run check
npm test
node src/index.js
```

## Docker start

Start a fresh clone with the canonical command:

```bash
docker compose up --build
```

The Compose configuration is self-contained: it builds the explicit `credential-hub:1.0.0-beta.1` image tag from the current package version, creates its own network, and uses repository-relative persistent directories. It does not require a pre-existing Docker network or local user paths. Stop the foreground process with `Ctrl+C`; use `docker compose down` to remove the container and network.

For a new release, update the canonical package version and the Compose image/build argument together, then verify the rendered Compose configuration before deployment:

```bash
docker compose config
```

The HTTP callback and REST server uses `OAUTH_CALLBACK_PORT`, defaulting to `3000`. With the default `BASE_PATH=/`, verify the local health endpoint with `GET /health`.

## Base path and reverse proxy deployment

For a deployment below a path prefix, configure the application before starting it:

```env
BASE_PATH=<YOUR_BASE_PATH>
PUBLIC_BASE_URL=<YOUR_PUBLIC_ORIGIN>
```

For example, set `BASE_PATH=/credential-hub` and set `PUBLIC_BASE_URL` to the external origin such as `https://sekalum.example.com`.

`PUBLIC_BASE_URL` must be the external HTTP(S) origin without a path, query, or fragment. It prevents an internal proxy host or protocol from becoming part of an OAuth redirect URI. The application then serves the Admin UI at `/credential-hub/admin/`, health at `/credential-hub/health`, and the REST and OAuth routes below `/credential-hub/`. Configure every OAuth provider with the exact redirect URI shown in the Wizard; it includes the same prefix.

The reverse proxy must preserve the request path. The following neutral examples forward a local service without stripping `/credential-hub`.

### Nginx

```nginx
location /credential-hub/ {
    proxy_pass http://localhost:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Caddy

```caddy
sekalum.example.com {
    reverse_proxy /credential-hub/* localhost:3000
}
```

### Traefik

Route the service with a `PathPrefix(`/credential-hub`)` rule and do not add a strip-prefix middleware.

### Apache HTTP Server

```apache
ProxyPass        /credential-hub/ http://localhost:3000/credential-hub/
ProxyPassReverse /credential-hub/ http://localhost:3000/credential-hub/
```

Verify the prefixed health endpoint through the public proxy before registering OAuth callbacks:

```text
GET /credential-hub/health
```

## Scope boundary

Certificates, domains, host paths, container images, and platform-specific service management remain deployment decisions. The examples above define only the path-preservation requirement; historical deployment and infrastructure notes are not current installation instructions.
