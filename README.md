<img width="1231" height="1541" alt="Bildschirmfoto 2026-08-10 um 09 08 05" src="https://github.com/user-attachments/assets/a23efb7d-9cf3-49eb-b27a-9344b1857e26" />



# Credential HUB

Credential HUB is an open-source platform for managing the lifecycle of digital credentials. It provides an Admin UI for creating and managing provider credentials, OAuth connections, API tokens, encrypted imports and exports, and lifecycle status.

The current public release is [Credential HUB v1.0.0-rc.1](https://github.com/luiscyphre404-cmd/credential-hub/releases/tag/v1.0.0-rc.1), a release candidate for non-production evaluation ahead of the final 1.0.0 release.

## Release Candidate 1

RC1 extends the Public Beta foundation with:

- OAuth refresh lifecycle support, including Resolve-triggered refresh.
- Secret-free Integration Health visibility in the Admin dashboard.
- Clearer bootstrap and Management Token onboarding boundaries.
- Consumer Grant setup and diagnosis for least-privilege Consumer access.
- UI polish and responsive improvements across the Admin and Consumer surfaces.
- Updated public API, installation, security, provider and English reference documentation.

The public documentation has been migrated to the current guide structure and is the canonical reference for RC1 setup and operation.

## Architecture at a glance

- A Node.js and Express service serves the Admin UI, REST API, OAuth callbacks, and health endpoint.
- Provider integrations are registered through a shared provider boundary; OAuth application settings are normally entered in the Wizard and encrypted by the backend.
- Credentials and operational records use encrypted JSON storage in the persisted `storage/` directory.

The public [Developer Guide](docs/developer-guide/index.md) and [Configuration Reference](docs/configuration-reference/index.md) describe these boundaries in detail.

## Current RC1 Limitations

Credential HUB Release Candidate 1 focuses on the core credential platform and its documented HTTP interfaces. The following boundaries are intentional and remain part of the current 1.0.0 scope:

- There are no native integrations for n8n or other workflow and automation platforms. Runtimes use the generic Consumer API; the repository provides public n8n examples as HTTP-client workflows.
- The Consumer interface is a supported Advanced Integration Flow, but it is not a Consumer-first onboarding flow. An administrator must first prepare the Credential, a dedicated Consumer API token, and an explicit grant for the permitted Secret fields.
- Admin access uses a Management Token; Credential HUB does not provide username/password authentication. Initial administrator bootstrap is performed through the local Management API.
- Custom providers are declarative only. They can define provider metadata, methods, bindings, and field schemas, but they do not add OAuth configuration, executable adapters, runtime operations, hooks, scripts, or provider secrets.
- The standard Release-1.0 image does not provide a production FTP or SFTP transport adapter. It must not be represented as providing live FTP/SFTP validation, file transfer, TLS verification, or SSH host-key verification.
- Configure an operator-controlled protection layer before exposing the Admin UI publicly.

No future capability is implied by the limitations listed here.

## RC1 quick start

### Prerequisites

- Docker Desktop or Docker Engine with the Compose plugin.
- Git.
- A local port `3000` that is not already in use.

### Start with Docker

Clone the repository, create your local environment file, and start the application:

```bash
git clone https://github.com/luiscyphre404-cmd/credential-hub.git
cd credential-hub
cp .env.example .env
docker compose up --build
```

The Compose configuration is self-contained: it builds the versioned application image and creates its own network and local runtime directories. Stop the foreground process with `Ctrl+C`; use `docker compose down` to remove the container and network.

### Configure `.env`

`.env.example` contains safe development defaults. Before storing real credentials, replace `TOKEN_ENCRYPTION_KEY` with a unique 32-character secret and keep `.env` private. Do not commit `.env`, OAuth client secrets, API keys, or exported credential data.

Optional deployment settings, including `BASE_PATH`, `PUBLIC_BASE_URL`, and encryption-key rotation, are documented in the [Configuration Reference](docs/configuration-reference/index.md).

### Open the application

After the container reports that it is listening, open:

- Admin UI and Credential Wizard: [http://localhost:3000/admin/](http://localhost:3000/admin/)
- Dashboard: [http://localhost:3000/admin/dashboard.html](http://localhost:3000/admin/dashboard.html)
- Consumer interface: [http://localhost:3000/consumer/](http://localhost:3000/consumer/)
- Health endpoint: [http://localhost:3000/health](http://localhost:3000/health)

### Initial access and first administrator

Credential HUB does not provide username/password authentication. A new `storage/` directory starts in bootstrap mode so the first administrator can be created through the local Management API:

```bash
curl --request POST http://localhost:3000/api/v1/management/users \
  --header 'Content-Type: application/json' \
  --data '{"userId":"admin","displayName":"First Administrator","roleKey":"admin"}'
```

Create this administrator before exposing the service beyond the local machine. Once users exist, API access requires an API token or the documented `x-credential-hub-user` compatibility header and role permissions. See the [API Reference](docs/api-reference/index.md#authorization-and-errors) for the authorization contract.

### Create a first credential

1. Open the Credential Wizard.
2. Choose a provider and authentication method.
3. Enter only the fields requested by that provider, then review the summary and create the credential.
4. For OAuth providers, register the redirect URI shown by the Wizard with the provider and complete its authorization flow.

For detailed provider, API-token, and credential-management guidance, see the [User Guide](docs/user-guide/index.md).

### Open the Consumer interface (Advanced Integration Flow)

After an administrator has activated a Credential, created a dedicated Consumer API token, and granted the required secret fields, open the Consumer interface at [http://localhost:3000/consumer/](http://localhost:3000/consumer/). This is a supported Advanced Integration Flow: a separate runtime surface for Discovery and Resolve, not the primary Consumer-first onboarding path. It does not receive or use a Management Token. Enter the dedicated Consumer API token directly in the Consumer interface.

### Troubleshooting

- If the container does not start, confirm that `.env` exists and that port `3000` is free.
- If storing credentials fails, confirm that `TOKEN_ENCRYPTION_KEY` is present and exactly 32 characters long.
- If an OAuth callback fails, verify the redirect URI, `PUBLIC_BASE_URL`, and `BASE_PATH`.
- Check [http://localhost:3000/health](http://localhost:3000/health) first, then inspect `docker compose logs` for operator diagnostics.

## Local development and validation

To run outside Docker, install dependencies from the lockfile and execute the checks:

```bash
npm ci
npm run check
```

Set the required runtime environment before starting `node src/index.js`; the [Installation Guide](docs/installation-guide/index.md) describes both local and Compose operation.

## Examples

Official n8n example workflows are available in the [examples/n8n/](examples/n8n/) directory and documented in the [n8n examples guide](examples/n8n/README.md).

## Documentation

- [Installation Guide](docs/installation-guide/index.md)
- [Configuration Reference](docs/configuration-reference/index.md)
- [English Quick Start](docs/quick-start-guide/index.md)
- [User Guide](docs/user-guide/index.md)
- [API Reference](docs/api-reference/index.md)
- [Security Guide](docs/security-guide/index.md)
- [Developer Guide](docs/developer-guide/index.md)
- [Provider Documentation](docs/providers/README.md)
- [Handbook](docs/index.md)

## Contributing and security

- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

Report security vulnerabilities only as described in [SECURITY.md](SECURITY.md), never through public issues or Discord.

## License and third-party software

Credential HUB is licensed under the [GNU Affero General Public License v3.0 only](LICENSE). See [NOTICE](NOTICE).

## Community & support

Join the official [Credential HUB Discord community](https://discord.gg/exTu3Dy2UW) for technical support, discussion, and feature ideas. Submit reproducible bugs through [GitHub Issues](https://github.com/luiscyphre404-cmd/credential-hub/issues).
