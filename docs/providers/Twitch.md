# Twitch Provider

MS9 F2: implementiert als nativer OAuth2 Provider.

## Provider Key

```text
twitch
```

## Business-Ziel

Der Sekalum verwaltet Twitch OAuth2 Credentials zentral, damit Stream-Automatisierungen, Chat-Bridge, n8n-Workflows und spätere Tools sicher auf die Twitch Helix API zugreifen können.

## Konfiguration

Der Provider erwartet folgende Umgebungsvariablen:

```env
TWITCH_CLIENT_ID=
TWITCH_CLIENT_SECRET=
TWITCH_REDIRECT_URI=
```

Die Redirect URI muss in der Twitch Developer Console exakt so hinterlegt sein, wie sie im Sekalum konfiguriert ist.

## OAuth-Endpunkte

| Zweck | Endpoint |
|---|---|
| Authorization | `https://id.twitch.tv/oauth2/authorize` |
| Token Exchange | `https://id.twitch.tv/oauth2/token` |
| Token Validation | `https://id.twitch.tv/oauth2/validate` |
| User Info | `https://api.twitch.tv/helix/users` |

## Default-Scopes

```text
user:read:email
```

Weitere Twitch-Scopes können beim OAuth-Start explizit übergeben werden. Leere Scope-Listen werden durch den Command nicht an den Provider weitergegeben, damit der Provider seine Default-Scopes verwenden kann.

## CLI-Beispiel

```bash
node src/cli/run-oauth.js twitch
```

Der Befehl erzeugt eine Twitch-Authorization-URL. Nach erfolgreichem Login liefert Twitch den OAuth-Code an die konfigurierte Callback-URL zurück.

## Capabilities

| Capability | Status |
|---|---|
| OAuth Start | unterstützt |
| OAuth Callback | unterstützt |
| Refresh | unterstützt |
| Health Check | unterstützt |
| Revoke | nicht Bestandteil von MS9 F2 |

## Architekturgrenzen

Der Twitch Provider folgt dem bestehenden Provider-Contract:

```text
StartOAuthCommand
↓
ProviderManager
↓
TwitchProvider
↓
TwitchOAuthService
↓
TwitchApiClient
```

Der Provider enthält ausschließlich Twitch-Plattformlogik. Commands, REST, CredentialStore und Verschlüsselung bleiben außerhalb des Providers.

## Speicherung

Access Token, Refresh Token, Ablaufzeit, Scopes und Metadaten werden als Credential gespeichert. Die aktive Persistenz erfolgt über den CredentialStore und den verschlüsselten JsonStore-Pfad.

## Tests

MS9 F2 ergänzt Tests für:

- Provider-Registrierung und öffentliche Metadaten
- Authorization URL
- Token Exchange
- Refresh ohne neuen Refresh Token
- Health-Check-Fehlerpfad
- Provider-Fehler bei fehlendem Code, Access Token oder Refresh Token
- CLI OAuth Start für Twitch
