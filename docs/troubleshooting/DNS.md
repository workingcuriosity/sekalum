---
title: DNS Troubleshooting
document_id: DOC-TROUBLESHOOTING-DNS
classification: PUBLIC
language: en
version: 1.1.1
category: Troubleshooting
status: Active
owner: Sekalum
canonical: false
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Operators
  - Integrators
change_history:
  - version: 1.1.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.1.0
    date: 2026-08-24
    change: Replaces the obsolete placeholder with an English, environment-neutral troubleshooting checklist.
---

# DNS Troubleshooting

Verify that the configured public hostname resolves to the intended service,
that the callback origin uses the same hostname, and that the reverse proxy
forwards the expected scheme and path.

Use example domains in documentation and test environments. Never publish
private hostnames, local addresses or production-specific infrastructure
details.
