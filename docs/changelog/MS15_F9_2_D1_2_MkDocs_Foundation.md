# MS15 F9.2 D1.2 – MkDocs Foundation

Datum: 2026-07-09  
Status: umgesetzt  

## Änderungen

- `mkdocs.yml` als zentrale Dokumentationsplattform-Konfiguration ergänzt.
- MkDocs Material, Suche, Mermaid und PDF-Build konzeptionell vorbereitet.
- `requirements-docs.txt` für den reproduzierbaren lokalen Dokumentationsbuild ergänzt.
- Dokumentations-Buildartefakte in `.gitignore` ausgeschlossen.
- ADR-018 zur Internationalisierungsstrategie ergänzt.
- ADR-019 zur Dokumentations-Build-Strategie ergänzt.
- ADR-Index auf die neuen Architekturentscheidungen erweitert.
- Vorbereitung für spätere englische Dokumentation unter `docs/future/i18n/` ergänzt.
- Kurze Build-Dokumentation unter `docs/documentation-platform/index.md` ergänzt.

## Architekturentscheidungen

- Release 1.0 bleibt vollständig deutsch.
- Englische Dokumentation folgt erst gemeinsam mit Produkt-i18n in einem späteren Release.
- Markdown bleibt Canonical Source.
- PDFs werden als Build-Artefakte erzeugt und nicht als primäre Quelldateien versioniert.

## Runtime-Auswirkung

Keine.

Es wurden ausschließlich Dokumentations- und Build-Konfigurationsdateien geändert. Kein Container-Rebuild erforderlich.
