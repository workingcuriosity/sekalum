---
title: Documentation Platform
document_id: DOC-DOCUMENTATION-PLATFORM
classification: PUBLIC
language: en
version: 1.1.1
category: Documentation
status: Active
owner: Sekalum
canonical: false
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Contributors
  - Documentation maintainers
change_history:
  - version: 1.1.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.1.0
    date: 2026-08-24
    change: Replaces the obsolete mixed-language platform note with the current English build and source rules.
---

# Documentation Platform

Markdown is the canonical documentation source. MkDocs builds the current
documentation site from the approved public projection.

## Local build

```bash
python -m pip install -r requirements-docs.txt
mkdocs serve
mkdocs build
```

Set `ENABLE_PDF_EXPORT=1` when a PDF export is required. Generated HTML and
PDF files are build outputs, not primary documentation sources.

Current documentation is maintained in English. Historical evidence is kept
privately under `docs/history/` and is excluded from the public site.
