# MS9 F7.4 – OpenAI Provider

## Inhalt

- OpenAI API-Key Provider ergänzt
- OpenAI ConnectionService ergänzt
- OpenAI Client ergänzt
- Provider-Registrierung ergänzt
- Validate-/Health-Check-Capabilities ergänzt
- Tests für OpenAI Client, ConnectionService, Provider und Provider-Registrierung ergänzt
- Dokumentation ergänzt

## Architektur

OpenAI ist kein OAuth-Provider. Die Integration nutzt daher die Connection-/API-Key-Laufkette:

```text
Provider
  ↓
ConnectionService
  ↓
Client
```

Damit wird nach OAuth und File Transfer ein dritter Credential-Typ validiert: API-Key-basierte Credentials.

## Sicherheit

Der API-Key wird als Credential Secret gespeichert und durch den bestehenden verschlüsselten CredentialStore persistiert.

## Nicht enthalten

Keine OpenAI-Businessfunktionen wie Chat, Responses, Assistants, Images, Audio oder Embeddings. Das Paket umfasst ausschließlich Credential Lifecycle, Validate und Health Check.
