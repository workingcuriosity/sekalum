---
title: Changelog Index
version: 1.0
status: Active
category: Release
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Projektverantwortliche
  - Entwickler
  - Betreiber
dependent_documents:
  - docs/release-guide/index.md
change_history:
  - version: 1.0.0
    date: 2026-07-11
    change: DR-005 establishes docs/changelog as the canonical namespace for release notes.
---

# Changelog Index

## Zweck

`docs/changelog/` is the canonical namespace for current and future Credential
HUB release notes.

New changelog entries are created in this directory. Existing entries remain
according to their subject matter; DR-005 does not mass-migrate or materially
consolidate historical release notes.

## Aktuelle Eintraege

| Bereich | Dokument |
|---|---|
| MS9 Provider | `MS9_F7_1_SFTP.md`, `MS9_F7_2_FTP.md`, `MS9_F7_4_OpenAI.md` |
| MS10 Dashboard | `MS10_Changelog.md` |
| MS15 Dokumentationsplattform | `MS15_F9_2_D1_1_Documentation_Platform_Foundation.md`, `MS15_F9_2_D1_2_MkDocs_Foundation.md` |
| MS15 Provider Metadata | `MS15_F9_1B_Provider_Metadata_Dynamic_Wizard.md` |
| MS15 Base Path and Reverse Proxy | `MS15_F9_1C_Base_Path_Reverse_Proxy.md` |
| Release 1.0 Internationalization Baseline | `MS15_Release_1_0_Internationalization_Baseline.md` |
| Release 1.0 OAuth and Admin UI Completion | `MS15_Release_1_0_OAuth_Admin_UI_Completion.md` |
| MS15 Credential Management and Versioned Docker Image | `MS15_Credential_Management_Docker_Image.md` |
| MS15 Credential Connection Tests | `MS15_Credential_Connection_Tests.md` |
| MS16 Provider API and Custom Onboarding | `MS16_Provider_API_and_Custom_Onboarding.md` |

## Historische Release-Notizen

`docs/history/milestones/legacy-changelog/` is a historical archive. Its files
preserve original release notes and milestone evidence.

Historical files are neither deleted nor silently replaced by files with the
same name in `docs/changelog/`. When names overlap, `docs/changelog/` is the
canonical source for future maintenance and the archived copy remains
historical evidence.

## Verwandte Dokumente

- `docs/release-guide/index.md` beschreibt den Release-Kontext.
- Historical release context remains in this public changelog.
