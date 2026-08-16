# Facebook OAuth2 Provider

## Zweck

Der Facebook Provider verwaltet Facebook OAuth2 User Credentials für spätere Facebook Graph API Funktionen wie Seitenzugriff, Posting, Insights oder Webhooks.

MS9 F6.1 umfasst ausschließlich den Credential-Lifecycle. Graph-spezifische Business-Funktionen sind nicht Bestandteil dieses Pakets.

## Provider Key

```text
facebook
```

## Konfiguration

Der Provider benötigt folgende Umgebungsvariablen:

```env
FACEBOOK_CLIENT_ID=
FACEBOOK_CLIENT_SECRET=
FACEBOOK_REDIRECT_URI=
```

Die Redirect URI muss in der Meta/Facebook Developer App exakt so hinterlegt sein, wie sie im Sekalum konfiguriert ist.

## OAuth-Endpunkte

| Zweck | Endpoint |
|---|---|
| Authorization | `https://www.facebook.com/v20.0/dialog/oauth` |
| Token Exchange | `https://graph.facebook.com/v20.0/oauth/access_token` |
| User Info | `https://graph.facebook.com/v20.0/me` |

## Default Scopes

```text
public_profile,email
```

Diese Scopes reichen für die erste User-Identifikation und den Credential Health Check. Erweiterte Berechtigungen wie Page- oder Posting-Scopes werden erst mit entsprechenden Business-Funktionen ergänzt.

## OAuth Security Requirements

```json
{
  "state": "required",
  "pkce": "disabled",
  "nonce": "disabled"
}
```

Der OAuth-State wird generisch über den `OAuthSecurityService` erzeugt und validiert. Der FacebookProvider enthält keine Framework- oder Security-Sonderlogik.

## CLI

```bash
node src/cli/run-oauth.js facebook
```

## HTTP

```text
GET /oauth/facebook/login
GET /oauth/facebook/callback
```

## Architekturgrenzen

- `FacebookProvider` enthält nur Provider-Delegation und fachliche Provider-Validierung.
- `FacebookOAuthService` enthält Facebook-spezifischen OAuth-Flow und Ergebnisaufbereitung.
- `FacebookApiClient` enthält ausschließlich HTTP-Kommunikation mit Facebook/Graph API.
- Credential-Speicherung erfolgt weiterhin über `CredentialManager`, `CredentialStore` und `EncryptedJsonStore`.
- Facebook ist Teil der Meta-Provider-Familie, bleibt aber fachlich ein eigener Provider.

## Nicht Bestandteil von MS9 F6.1

- Facebook Pages API
- Posting
- Insights
- Messenger
- Webhooks
- Marketing API
- gemeinsame Meta-Basis-Refactorings
