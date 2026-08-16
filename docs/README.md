# Sekalum Documentation

## Structure

- `project/` – project vision, roadmap, changelog, rules and development workflow
- `architecture/` – current system architecture, data flow and boundaries
- `adr/` – architecture decision records
- `api/` – REST, OAuth and health APIs
- `providers/` – provider-specific documentation
- `deployment/` – installation, operation, backup and restore
- `infrastructure/` – Docker, ports, domains, reverse proxy and volumes
- `testing/` – test strategy and architecture checks
- `history/` – archived milestones, work packages, reviews, planning material and project transitions
- `backlog/` – architecture and feature backlog
- `troubleshooting/` – known issues and operational fixes
- `inventory/` – infrastructure and software inventory

- MS14 F8.2 API Token Management

## Documentation Platform Build

Die Release-1.0-Dokumentation wird über MkDocs gebaut.

```bash
python -m pip install -r requirements-docs.txt
mkdocs serve
mkdocs build
```

Für den PDF-Build `ENABLE_PDF_EXPORT` auf `1` setzen und anschließend `mkdocs build` ausführen.

Markdown ist die Canonical Source. Generierte HTML-/PDF-Artefakte werden nicht als primäre Quellen gepflegt.
