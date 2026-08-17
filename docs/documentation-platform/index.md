# Documentation Platform

Version: 1.1.0
Release: Sekalum Release 1.0
Status: Active
Zielgruppe: Entwickler, Dokumentationsverantwortliche  
Canonical Source: Dokumentationsplattform  
Abhängige Dokumente: Developer Guide, Release Guide, ADR Index  
Autor: Sekalum Projekt
Letzte Aktualisierung: 2026-08-17
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

Der öffentliche Dokumentationsstand enthält einen englischen Quick Start und geprüfte englische Kernhandbücher. Weitere Übersetzungen werden erst veröffentlicht, wenn sie als reviewed content vorliegen.

## Änderungsverlauf

| Version | Datum | Änderung |
|---|---|---|
| 1.1.0 | 2026-08-17 | Öffentlichen Dokumentationsbuild und den geprüften Sekalum-Dokumentationsstand synchronisiert. |
| 1.0.0-draft | 2026-07-09 | MkDocs Foundation und Build-Regeln ergänzt. |
