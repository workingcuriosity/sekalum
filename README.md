# Sekalum

![Sekalum Beta-1 overview](https://github.com/user-attachments/assets/66985fe9-6bae-4261-981e-c3280d666855)

*Promotional overview of the Sekalum Public Beta. The documented feature scope and current limitations below are authoritative.*

Sekalum is an open-source platform for managing the lifecycle of digital credentials. It provides an Admin UI for creating and managing provider credentials, OAuth connections, API tokens, encrypted imports and exports, and lifecycle status.

## Architecture at a glance

- A Node.js and Express service serves the Admin UI, REST API, OAuth callbacks, and health endpoint.
- Provider integrations are registered through a shared provider boundary; OAuth application settings are normally entered in the Wizard and encrypted by the backend.
- Credentials and operational records use encrypted JSON storage in the persisted `storage/` directory.

The Architecture Guide and Storage Guide describe these boundaries in detail.

## Current Beta-1 Limitations

Sekalum Public Beta 1 focuses on the core credential platform and its documented HTTP interfaces. The following boundaries are intentional and part of the current Beta-1 scope:

- The Sekalum n8n community node is an optional Consumer API integration. It
  uses the same public Consumer API boundary as other runtimes and does not
  receive a privileged integration path.
- The Consumer interface is a supported Advanced Integration Flow, but it is not a Consumer-first onboarding flow. An administrator must first prepare the Credential, a dedicated Consumer API token, and an explicit grant for the permitted Secret fields.
- Public Beta 1 does not provide an interactive username/password login screen. Initial administrator bootstrap is performed through the local Management API.
- Custom providers are declarative only. They can define provider metadata, methods, bindings, and field schemas, but they do not add OAuth configuration, executable adapters, runtime operations, hooks, scripts, or provider secrets.
- The standard Release-1.0 image does not provide a production FTP or SFTP transport adapter. It must not be represented as providing live FTP/SFTP validation, file transfer, TLS verification, or SSH host-key verification.

Known improvements are tracked separately from this README. No future capability is implied by the limitations listed here.

## Public Beta quick start

### Prerequisites

- Docker Desktop or Docker Engine with the Compose plugin.
- Git.
- A local port `3000` that is not already in use.

### Start with Docker

Clone the repository, create your local environment file, and start the application:

```bash
git clone https://github.com/workingcuriosity/sekalum.git
cd sekalum
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

### Bootstrap and First Administrator

This Public Beta does not provide an interactive username/password login
screen. When the persisted user collection is empty, the application is in
**Bootstrap** mode. Bootstrap permits creation of exactly the **First
Administrator** through the local Management API:

```bash
curl --request POST http://localhost:3000/api/v1/management/users \
  --header 'Content-Type: application/json' \
  --data '{"userId":"admin","displayName":"First Administrator","roleKey":"admin"}'
```

Create the **First Administrator** before exposing the service beyond the
local machine. Bootstrap ends as soon as that administrator is persisted;
subsequent management requests are no longer unauthenticated. The Admin UI
then requires an authorized **Management Token**, sent as
`Authorization: Bearer <management-token>`. The Admin UI opens with a
Management Token gate; the Dashboard and Admin navigation become available
only after the token is validated.

The header `x-credential-hub-user` is not a production authentication method.
It exists only for the repository's `NODE_ENV=test` compatibility tests and
must not be used for normal operation. See the [API Reference](docs/api-reference/index.md#authorization-and-errors) for the authorization contract.

For the complete first-installation sequence from health check through the
first Consumer Resolve, see the [Installation Guide — Complete First
Installation Workflow](docs/installation-guide/index.md#complete-first-installation-workflow).

### Create a first credential

1. Open the Credential Wizard.
2. Choose a provider and authentication method.
3. Enter only the fields requested by that provider, then review the summary and create the credential.
4. For OAuth providers, register the redirect URI shown by the Wizard with the provider and complete its authorization flow.

For detailed provider, API-token, and credential-management guidance, see the [User Guide](docs/user-guide/index.md).

### Open the Consumer interface (Beta-1 Advanced Integration Flow)

After an administrator has activated a Credential, created a dedicated Consumer API token, and granted the required secret fields, open the Consumer interface at [http://localhost:3000/consumer/](http://localhost:3000/consumer/). This is the Beta-1-supported Advanced Integration Flow: a technically complete, separate runtime surface for Discovery and Resolve, not the primary Consumer-first onboarding path. It does not receive or use a Management Token. Enter the dedicated Consumer API token directly in the Consumer interface. Consumer-first onboarding improvements remain future work under Issue #141.

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
npm test
```

Set the required runtime environment before starting `node src/index.js`; the [Installation Guide](docs/installation-guide/index.md) describes both local and Compose operation.

## Sekalum for n8n

Sekalum for n8n is maintained as a separate integration project. This
repository retains the Consumer API boundary and the historical Issue #131
handover and evidence record; the standalone node source and its workflow
deliverables are maintained outside this product repository.

## Examples

Official platform-level n8n templates remain available in [examples/n8n/](examples/n8n/).

## Documentation

- [Installation Guide](docs/installation-guide/index.md)
- [Configuration Reference](docs/configuration-reference/index.md)
- [English Quick Start](docs/quick-start-guide/index.md)
- [User Guide](docs/user-guide/index.md)
- [Security Guide](docs/security-guide/index.md)
- [Handbook](docs/index.md)
- Architecture guide
- ADR index
- [Changelog index](docs/changelog/README.md)

## Contributing and security

- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

Report security vulnerabilities only as described in [SECURITY.md](SECURITY.md), never through public issues or Discord.

## License and third-party software

Sekalum is licensed under the [GNU Affero General Public License v3.0 only](LICENSE). See [NOTICE](NOTICE), [Legal information](docs/project/LEGAL.md), and [Third-Party Software](docs/project/THIRD_PARTY_SOFTWARE.md).

## Community & support

Join the official [Sekalum Discord community](https://discord.gg/exTu3Dy2UW) for technical support, discussion, and feature ideas. Submit reproducible bugs through [GitHub Issues](https://github.com/workingcuriosity/sekalum/issues).
