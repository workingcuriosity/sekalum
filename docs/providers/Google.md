# Google Provider

## Status

MS9 F1: implementiert als nativer OAuth2 Provider.

## Zweck

Der Google Provider verwaltet Google OAuth2 Credentials als ersten nativen OAuth-Provider des Sekalum.

Er dient als Referenz für weitere OAuth2-basierte Provider, ohne das bestehende OAuth-Framework umzubauen.

## Provider Key

```text
google
```

## Öffentliche Metadaten

| Feld | Wert |
|---|---|
| Display Name | Google OAuth2 |
| Beschreibung | Google OAuth2 provider for Google account credentials |
| Auth Type | oauth2 |
| Default Scopes | `openid`, `email`, `profile` |

## Capabilities

| Capability | Status |
|---|---|
| OAuth | unterstützt |
| Refresh | unterstützt |
| Health Check | unterstützt |
| Revoke | nicht Bestandteil von MS9 F1 |
| Validation | nicht Bestandteil von MS9 F1 |

## Konfiguration

Der Provider erwartet folgende Umgebungsvariablen:

| Variable | Beschreibung |
|---|---|
| `GOOGLE_CLIENT_ID` | OAuth Client ID aus der Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | OAuth Client Secret aus der Google Cloud Console |
| `GOOGLE_REDIRECT_URI` | Callback-URL des Sekalum |

## OAuth Flow

Der Provider verwendet den klassischen Authorization Code Flow mit Offline-Zugriff:

```text
REST / CLI
  ↓
ProviderManager.startOAuth("google")
  ↓
GoogleProvider
  ↓
GoogleOAuthService
  ↓
Google Authorization URL
```

Die Authorization URL enthält:

- `response_type=code`
- `scope=openid email profile`
- `access_type=offline`
- `prompt=consent`
- optional `state`

## Token Exchange

Nach dem Callback tauscht der `GoogleOAuthService` den Authorization Code über den `GoogleApiClient` gegen Token aus und liest anschließend die Google UserInfo.

Das Ergebnis wird als `OAuthResult` mit öffentlicher Credential-Terminologie zurückgegeben.

## Refresh

Google Refresh verwendet den gespeicherten `refreshToken`. Gibt Google beim Refresh keinen neuen Refresh Token zurück, wird der vorhandene Refresh Token beibehalten.

## Architekturgrenzen

- `GoogleProvider` enthält nur Google-spezifische Providerlogik und delegiert an den OAuthService.
- `GoogleOAuthService` enthält OAuth-Ablauflogik und Ergebnisaufbereitung.
- `GoogleApiClient` enthält ausschließlich HTTP-Kommunikation mit Google.
- Provider speichern keine Credentials direkt.
- Provider erzeugen keine Framework-Logs.
- Provider verwenden keine HTTP-Bibliotheken direkt.


## Praktische Einrichtung

### 1. Google OAuth Client anlegen

Die Redirect URI muss mit der beim Provider registrierten Callback-URI uebereinstimmen. Neutrale Konfigurationsbeispiele und die aktive globale Konfiguration stehen in der [Configuration Reference](../configuration-reference/index.md).

### 2. Umgebungsvariablen eintragen

```env
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI=YOUR_GOOGLE_REDIRECT_URI
```

### 3. OAuth starten

Per CLI:

```bash
node src/cli/run-oauth.js google
```

Der CLI-Befehl gibt die Google Authorization URL aus. Diese URL wird im Browser geöffnet.

### 4. Credential speichern

Nach erfolgreicher Anmeldung ruft Google den Callback des Sekalum auf. Der Sekalum importiert das Ergebnis als Credential.

Gespeichert werden fachlich:

- Provider `google`
- Google Account ID
- Account Name / E-Mail
- Access Token
- Refresh Token
- Ablaufzeit
- Scopes
- öffentliche Metadaten

## Nicht Bestandteil von MS9 F1

- PKCE
- Device Flow
- Google-Dienstprofile wie YouTube, Gmail oder Drive
- generisches Provider-Profile-Framework
- Revoke-Flow
