# Architekturregel: Core-Unabhängigkeit

## Core kennt keine Credential-Typen

Der Core kennt niemals einen konkreten Credential-Typ.

Er arbeitet ausschließlich mit einem generischen Credential-Modell und delegiert typspezifisches Verhalten vollständig an Provider bzw. Plugins.

Folgen:
- keine Typabfragen im Core
- keine Plattformlogik im Core
- Open/Closed Principle
- neue Credential-Typen ohne Core-Anpassung


# MS14 Security-Architektur: Encryption at Rest

## Grundsatz

Kryptologie ist im Sekalum ausschliesslich Aufgabe der Storage-Schicht. Fachliche Services, Provider, Commands und REST-Endpunkte duerfen keine eigene Verschluesselungslogik enthalten.

## Schichten

```text
Application / Services
        |
CredentialManager und fachliche Services
        |
JsonStore-Fassade
        |
EncryptedJsonStore
        |
Filesystem
```

## Verantwortlichkeiten

- `EncryptedJsonStore` verschluesselt und entschluesselt persistierte JSON-Daten.
- `EncryptedJsonStore` validiert Payload-Struktur, Algorithmus, Payload-Version, Key-Version, IV, Auth-Tag und Ciphertext.
- `EncryptedJsonStore` stellt Diagnoseinformationen bereit, ohne Daten zu veraendern.
- `CredentialManager` bleibt fachlicher Einstiegspunkt fuer Credential-Aenderungen und kennt keine Kryptodetails.
- Provider enthalten weiterhin nur Plattformlogik und keine Storage- oder Kryptologik.

## Key-Versionierung

Neue verschluesselte Dateien enthalten eine `keyVersion`. Bestehende Payloads ohne `keyVersion` bleiben kompatibel und werden als Version 1 behandelt. Mehrere Keys werden ueber `TOKEN_ENCRYPTION_KEYS` verwaltet; neue Verschluesselungen verwenden `TOKEN_ENCRYPTION_KEY_VERSION`.

## Re-Encryption

Re-Encryption ist ein kontrollierter Wartungsvorgang. Dateien werden nicht automatisch beim Lesen migriert. Alte Keys duerfen erst entfernt werden, wenn alle betroffenen Dateien mit der aktuellen Key-Version neu verschluesselt wurden.

## MS14 / F8.2 - API Token Management

API Tokens dienen der technischen Authentifizierung gegen die Sekalum REST-API. Sie ersetzen nicht RBAC, sondern liefern den authentifizierten `userId`, der anschliessend wie bisher ueber `AccessManagementService` autorisiert wird.

```text
HTTP Request
  | Authorization: Bearer <api-token>
  v
REST Auth Resolver
  v
ApiTokenService.authenticate()
  v
AccessManagementService.authorize(userId, permission)
  v
REST Controller
  v
ApiTokenService / fachlicher Service
```

Schichtengrenzen:

- `ApiTokenService`: Token-Erzeugung, Hashing, Authentifizierung, Revocation, Ablaufpruefung, Audit.
- `ApiTokenStore`: Persistenz der Token-Metadaten und Hashes.
- `EncryptedJsonStore`: Encryption at Rest fuer persistierte API-Token-Daten.
- Admin-UI: ausschliesslich Darstellung und REST-Aufrufe, keine Businesslogik.

Security-Entscheidungen:

- Klartext-Tokens werden nur bei Erstellung einmalig angezeigt.
- Persistiert wird ausschliesslich ein SHA-256-Hash.
- `tokenHash` wird nie an REST-Clients oder Frontend ausgegeben.
- Widerruf ist Soft Delete; widerrufene Tokens bleiben fuer Audit und Nachvollziehbarkeit sichtbar.
- Kein automatisches Loeschen von API-Tokens in Release 1.0.

## Gemeinsame Admin-Authentifizierung

Alle Admin-Seiten verwenden `public/admin/auth.js` als gemeinsame Grenze für Management-Authentifizierung und HTTP-Aufrufe. `ManagementTokenStore` normalisiert und hält den Management Token in `sessionStorage`; wenn dieser Speicher nicht verfügbar ist, wird er nur für die laufende Seite im Speicher gehalten. Der Token wird beim Ausloggen explizit entfernt und nie in URL, Local Storage oder Seitencode dupliziert.

`AdminApiClient` erzeugt die Request-Header zentral und setzt ausschließlich `Authorization: Bearer <management-token>`. Aufrufer dürfen weder einen eigenen `Authorization`-Header noch den entfernten Legacy-Header `x-credential-hub-user` übergeben. Requests ohne Management Token werden vor dem Netzwerkzugriff abgewiesen. Die Admin-Shell stellt das gemeinsame Token-Eingabefeld bereit, damit Dashboard, Wizard, Credentials, Provider, Consumer Grants, API Tokens und Credential Transfer denselben Token-Lifecycle verwenden.

Der separate `ConsumerApiClient` ist ausschließlich für Flows bestimmt, die fachlich einen Consumer-Token benötigen. Auch dort wird der Bearer-Header zentral aufgebaut; Seitenmodule implementieren keine Header- oder Tokenlogik.

### Beta-1-Admin-Einstieg und Erstanmeldung

Die Weboberfläche ist ausschließlich eine Administratoroberfläche. Der Browser zeigt den Credential Wizard, das Dashboard und weitere Admin-Workflows erst nach erfolgreicher Prüfung eines Management Tokens über einen bestehenden geschützten Management-Endpunkt. Ohne gültigen Token wird eine dedizierte Administrator-Anmeldeseite angezeigt; Consumer melden sich dort nicht an und verwenden ausschließlich API-Tokens.

Beta 1 besitzt keinen integrierten Initialisierungs- oder Passwortänderungsdialog für den ersten Management Token. Die Bereitstellung beziehungsweise Erzeugung des initialen Management Tokens bleibt damit beim vorhandenen Betriebsmechanismus und wird durch diese UI-Änderung nicht neu definiert. Die Admin-Oberfläche übernimmt nur einen bereits bereitgestellten Token und speichert ihn ausschließlich lokal für die Browser-Sitzung. **Gespeicherten Management Token entfernen** entfernt daher nur diesen lokalen Browserwert; es ändert oder widerruft keinen serverseitigen Token.

Eine vorgeschaltete NGINX Basic Auth kann zusätzlich eingesetzt werden, ist aber nicht Bestandteil des Sekalum und wird von der Anwendung nicht als Admin-Anmeldung verarbeitet.
