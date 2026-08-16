# SFTP Provider

## Status

Eingeführt in MS9 F7.1.

## Typ

Connection Provider.

## Zweck

Der SFTP Provider verwaltet Zugangsdaten für sichere Dateiübertragungen über SFTP.

Typische Einsatzbereiche:

- VPS-Hosts
- NAS-Systeme
- Webserver
- Backup-Ziele
- Deployment-Ziele

## Provider Key

```text
sftp
```

## Authentifizierungsmodell

SFTP verwendet in der aktuellen Implementierung Benutzername-/Passwort-basierte Zugangsdaten.

Nicht unterstützt:

- OAuth
- Callback
- Refresh
- Revoke
- PKCE

## Credential-Felder

Pflicht:

- host
- username
- password

Optional:

- port (Standard: 22)

Vorbereitet für spätere Erweiterungen:

- privateKey
- passphrase
- knownHost / fingerprint

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
SftpProvider
    ↓
SftpConnectionService
    ↓
SftpClient
```

Der Provider erfüllt den fachlichen Provider Contract.

Der Connection Service orchestriert Validierung und Health Checks.

Der SftpClient kapselt den technischen SFTP-Transport.

## Transport Adapter

Die aktuelle Implementierung führt die SFTP-Architektur und eine testbare Transportgrenze ein.

Für echte Netzwerkverbindungen benötigt der Runtime Client einen konfigurierten SFTP Transport Adapter.

Tests verwenden Fake Connectoren, um externe Serverabhängigkeiten zu vermeiden.

## Health Check

Der Health Check prüft:

- Erreichbarkeit des Servers
- erfolgreiche Anmeldung
- ordnungsgemäßes Schließen der Verbindung

## Sicherheit

Gespeicherte Zugangsdaten verwenden den verschlüsselten CredentialStore.

## Scope

Enthalten in F7.1:

- SFTP Provider Registration
- SFTP Metadata
- Validation Capability
- Health Check Capability
- Unit-, Component- und Integrationstests

Nicht enthalten in F7.1:

- SSH Private Key Authentication
- Known Host / Fingerprint Pinning
- reale SFTP Library Dependency
- Dateiübertragungen
- Upload
- Download
- Synchronisation
