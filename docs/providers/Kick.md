# Kick Provider

MS9 F3.1: implementiert als nativer Kick OAuth 2.1 Provider mit verpflichtendem PKCE.

## Provider Key

```text
kick
```

## Business-Ziel

Der Sekalum verwaltet Kick OAuth Credentials zentral, damit Stream-Automatisierungen, Chat-Bridge, n8n-Workflows und spätere Tools sicher auf die Kick Public API zugreifen können.

## Konfiguration

Der Provider erwartet folgende Umgebungsvariablen:

```env
KICK_CLIENT_ID=
KICK_CLIENT_SECRET=
KICK_REDIRECT_URI=
```

Die Redirect URI muss im Kick Developer Portal exakt so hinterlegt sein, wie sie im Sekalum konfiguriert ist.

## OAuth-Endpunkte

| Zweck | Endpoint |
|---|---|
| Authorization | `https://id.kick.com/oauth/authorize` |
| Token Exchange | `https://id.kick.com/oauth/token` |
| Refresh | `https://id.kick.com/oauth/token` |
| Token Introspection | `https://id.kick.com/oauth/token/introspect` |
| User Info | `https://api.kick.com/public/v1/users` |

## OAuth Security Requirements

Kick verwendet OAuth 2.1 mit verpflichtendem PKCE.

```text
state = required
pkce = required
nonce = disabled
```

Der `KickProvider` erzeugt keine PKCE-Daten selbst. Die Sicherheitsanforderungen werden in der `ProviderDefinition` deklariert und vom generischen `OAuthSecurityService` umgesetzt.

## Default-Scopes

```text
user:read channel:read
```

Weitere Kick-Scopes können beim OAuth-Start explizit übergeben werden. Leere Scope-Listen werden durch den Command nicht an den Provider weitergegeben, damit der Provider seine Default-Scopes verwenden kann.

## CLI-Beispiel

```bash
node src/cli/run-oauth.js kick
```

Der Befehl erzeugt eine Kick-Authorization-URL mit `state`, `code_challenge` und `code_challenge_method=S256`.

## Capabilities

| Capability | Status |
|---|---|
| OAuth Start | unterstützt |
| OAuth Callback | unterstützt |
| Refresh | unterstützt |
| Health Check | unterstützt |
| Revoke | nicht Bestandteil von MS9 F3.1 |

## Architekturgrenzen

Der Kick Provider folgt dem bestehenden Provider-Contract:

```text
StartOAuthCommand
↓
ProviderManager
↓
OAuthSecurityService
↓
KickProvider
↓
KickOAuthService
↓
KickApiClient
```

Der Provider enthält ausschließlich Kick-Plattformlogik. Commands, REST, CredentialStore, Verschlüsselung, State-Handling und PKCE bleiben außerhalb des Providers.

## Speicherung

Access Token, Refresh Token, Ablaufzeit, Scopes und Metadaten werden als Credential gespeichert. Die aktive Persistenz erfolgt über den CredentialStore und den verschlüsselten JsonStore-Pfad.

## Tests

MS9 F3.1 ergänzt Tests für:

- Provider-Registrierung und öffentliche Metadaten
- OAuth Security Requirements mit verpflichtendem PKCE
- Authorization URL mit `code_challenge` und `code_challenge_method=S256`
- Token Exchange mit `code_verifier`
- Refresh ohne neuen Refresh Token
- Health-Check über Token Introspection
- Provider-Fehler bei fehlendem Code, Access Token oder Refresh Token
- CLI OAuth Start für Kick
- HTTP OAuth Login Redirect für Kick

## Validation

```text
tests 141
pass 141
fail 0
```
