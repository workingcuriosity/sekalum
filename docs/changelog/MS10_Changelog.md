## F4.2.1 – Dashboard Aggregation Service

### Added
- Neuer `DashboardService` als zentrale Aggregationsschicht für Dashboard-Live-Daten.
- Dashboard-Logik aus dem `DashboardController` ausgelagert.
- Registrierung des `DashboardService` im DI-Container.

### Changed
- `DashboardController` übernimmt ausschließlich HTTP-/REST-Aufgaben.
- Businesslogik wird vollständig über den `DashboardService` bereitgestellt.

### Quality
- Unit- und Integrationstests erweitert.
- Teststatus: 244/244 erfolgreich.
- Deployment erfolgreich durch Docker-Rebuild verifiziert.

---

## F4.2.2 – Provider KPI

### Added
- Provider-KPI für das Dashboard erweitert.
- Übersicht über Provider mit und ohne Credentials.
- Capability-Auswertung (`oauth`, `refresh`, `validation`, `health-check`, `revoke`).
- Erweiterte Providerübersicht für Dashboard-Live-Daten.

### Changed
- DashboardService aggregiert Providerdaten ausschließlich über öffentliche Schnittstellen.
- Keine aktiven Health-Checks oder Provider-Aufrufe während einer Dashboard-Anfrage.

### Quality
- Unit- und Integrationstests erweitert.
- Teststatus: 244/244 erfolgreich.
- Docker-Deployment erfolgreich verifiziert.
