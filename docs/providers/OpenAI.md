# OpenAI Provider

## Status

Eingeführt in MS9 F7.4.

## Typ

API Key Provider.

## Zweck

Der OpenAI Provider verwaltet API-Key-basierte Credentials für OpenAI- und ChatGPT-API-Zugriffe.

Der Provider stellt Validierungs- und Health-Check-Funktionen bereit und integriert sich vollständig in den Sekalum Credential Lifecycle.

## Authentifizierungsmodell

OpenAI verwendet API-Key-basierte Authentifizierung (Bearer Token).

Nicht unterstützt:

- OAuth
- Callback
- Refresh
- Revoke
- PKCE

## Credential-Felder

Pflicht:

- apiKey

Optional vorbereitet:

- organizationId
- projectId

## Capabilities

Unterstützt:

- VALIDATE
- HEALTH_CHECK

Nicht unterstützt:

- OAuth
- Refresh
- Callback
- PKCE

## Architektur

```text
ProviderManager
    ↓
OpenAIProvider
    ↓
OpenAIConnectionService
    ↓
OpenAIClient
    ↓
OpenAI REST API
```

Der Provider enthält ausschließlich die fachliche Providerlogik.

Der Connection Service orchestriert Validierung und Health Checks.

Der OpenAIClient kapselt sämtliche technische Kommunikation mit der OpenAI API.

## Validierung

Die Validierung überprüft:

- Vorhandensein eines API-Keys
- korrekte Provider-Konfiguration
- gültige Credential-Struktur

## Health Check

Der Health Check verwendet einen einfachen API-Aufruf (`GET /v1/models`), um zu prüfen:

- Erreichbarkeit der OpenAI API
- Gültigkeit des API-Keys
- erfolgreiche Authentifizierung

## Fehlerbehandlung

- Fehlende API-Keys werden als ProviderResult Failure zurückgegeben.
- Provider- und Netzwerkfehler werden auf definierte ProviderResult-Zustände normalisiert.
- Der Provider schreibt keine Framework-Logs.
- Persistenz erfolgt ausschließlich über den CredentialStore.

## Sicherheit

Alle Secrets werden verschlüsselt über den CredentialStore gespeichert.

## Scope

Enthalten in MS9 F7.4:

- API-Key Credential Management
- Validation
- Health Check

Nicht Bestandteil:

- Chat Completions
- Responses API
- Assistants API
- Images API
- Audio API
- Embeddings
- Fine-Tuning
- Batch API

Diese Funktionen gehören in spätere Business-Module und nicht in den Credential Lifecycle.
