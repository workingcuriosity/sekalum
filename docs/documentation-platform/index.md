# Documentation Platform

Version: 1.0.0-draft  
Release: Sekalum Release 1.0
Status: Draft  
Zielgruppe: Entwickler, Dokumentationsverantwortliche  
Canonical Source: Dokumentationsplattform  
Abhängige Dokumente: Developer Guide, Release Guide, ADR Index  
Autor: Sekalum Projekt
Letzte Aktualisierung: 2026-07-09  
Gültig ab: Release 1.0  

## Zweck

Dieses Dokument beschreibt die Dokumentationsplattform von Sekalum.

Die Markdown-Dateien im Verzeichnis `docs/` sind die führende Quelle der Dokumentation. HTML und PDF werden daraus reproduzierbar erzeugt.

## Build-Kommandos

Lokale HTML-Dokumentation:

```bash
python -m pip install -r requirements-docs.txt
mkdocs serve
```

Statischer Build:

```bash
mkdocs build
```

PDF-Build:

```bash
mkdocs build
```

Für den PDF-Build `ENABLE_PDF_EXPORT` auf `1` setzen.

## Release-1.0-Sprachen

Release 1.0 ist vollständig deutsch. Die englische Dokumentation wird gemeinsam mit der Produkt-Internationalisierung in Release 1.1 aktiviert.

## Änderungsverlauf

| Version | Datum | Änderung |
|---|---|---|
| 1.0.0-draft | 2026-07-09 | MkDocs Foundation und Build-Regeln ergänzt. |
