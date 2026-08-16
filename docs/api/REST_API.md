# REST API Notes

The canonical, code-verified REST route reference is [API Reference](../api-reference/index.md).

This former topic page remains as a supporting entry point. It must not be used to infer routes, permissions, or response contracts that are not listed in the canonical reference.

## Boundary and terminology

The Management API owns administrative Credential, Provider, lifecycle,
transfer, token and Consumer Grant operations. The separate Consumer API owns
runtime resolution of explicitly authorized Secret fields for active
Credentials. Consumer routes do not list Credentials, expose management
metadata or accept the legacy `x-credential-hub-user` identity header.

For method-aware Providers, `credentialMethodKey` selects an available
`ProviderMethodBinding`; the selected `CredentialMethod` owns the field and
Secret contract. These terms describe the existing ADR-021 model and do not
add routes or change API behavior. The canonical [API Reference](../api-reference/index.md)
owns all public endpoints, payloads, permissions and errors.

## Admin Authentication

Die Admin-Oberfläche übergibt für Management-Endpunkte ausschließlich `Authorization: Bearer <management-token>`. Der gemeinsame Client in `public/admin/auth.js` liest den Token aus dem zentralen, sitzungsgebundenen Store und baut die Header. Endpunkte dürfen aus Admin-Seiten nicht mit `x-credential-hub-user`, Basic Authentication oder selbst erzeugten Authorization-Headern aufgerufen werden.
