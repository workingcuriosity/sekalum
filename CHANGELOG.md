# R2 – Public Beta & Release Hardening

## Added

- Public-Beta onboarding in the repository README, including Docker start, environment guidance, Admin UI and Dashboard URLs, first credential creation, troubleshooting, and documentation links.
- A self-contained Compose installation path based on `.env.example` and `docker compose up --build`.

## Changed

- The Installation Guide now identifies the Public Beta release as `1.0.0-beta.1` and documents the self-contained Compose contract.

# MS15 F9.1C - Configurable Base Path and Reverse Proxy

## Added
- Configurable `BASE_PATH` for root and subpath deployments.
- Prefix-aware Admin UI, health, REST API, OAuth callbacks, and credential metadata.
- Reverse-proxy guidance with neutral examples.
- Unit and integration coverage for `/` and `/credential-hub/` deployments.

## Compatibility
- `BASE_PATH` defaults to `/`; existing root deployments need no configuration change.
- A reverse proxy must preserve the configured base path.

# MS15 F9.1B – CSV Credential Import

## Added
- CSV-Migrationsimport im `CredentialTransferService`.
- CSV-Parser ohne zusätzliche Paketabhängigkeit.
- Pflichtfeldvalidierung für `providerKey`, `externalReference` und mindestens eine Secret-Spalte.
- Unterstützung dynamischer Secret-Spalten über `secret.<name>`.
- Unterstützung direkter Secret-Komfortspalten: `username`, `password`, `apiKey`, `token`, `accessToken`, `refreshToken`, `clientId`, `clientSecret`.
- CSV-Preview über bestehende Import-Preview- und Konfliktlogik.
- CSV-Import über bestehende Konfliktstrategien `skip`, `overwrite`, `rename`.
- REST-Unterstützung für `sourceFormat: "csv"` in Import-Preview und Import.
- Admin-UI-Auswahl zwischen Credential-HUB-Exportdatei und CSV-Migrationsimport.
- Tests für CSV-Parsing, Validierung, Import, REST und Admin-UI.

## Validation
- `npm test` erfolgreich.
- Ergebnis lokal: 395/395 Tests erfolgreich.

## Runtime impact
- Änderungen in `src/` und `public/`.
- Container-Rebuild nach Einspielen prüfen und durchführen.
