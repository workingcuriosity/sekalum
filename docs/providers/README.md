---
title: Provider Documentation
document_id: DOC-PROVIDER-INDEX
classification: PUBLIC
language: en
version: 1.2.2
category: Providers
status: Active
owner: Sekalum
canonical: true
maintainer: Working Curiosity
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
target_audience:
  - Users
  - Integrators
  - Developers
change_history:
  - version: 1.2.2
    date: 2026-08-27
    change: Adds the shared provider secret-transport and redacted-diagnostics policy.
  - version: 1.2.1
    date: 2026-08-24
    change: Declares English as the current governed documentation language.
  - version: 1.2.0
    date: 2026-08-24
    change: Replaces the obsolete mixed-language provider index and establishes English provider pages as the current public provider documentation.
  - version: 1.1.0
    date: 2026-08-09
    change: Records the active provider metadata and capability boundary.
---

# Provider Documentation

Provider pages describe public capabilities only. Provider-specific secrets,
private configuration and runtime diagnostics remain inside the application
and storage boundaries. Provider access tokens and client secrets use form
bodies or authorization headers whenever the provider contract supports them.
Any provider-required secret-bearing query is an explicit, narrow
`QUERY_EXCEPTION`; its raw value is transiently sent to the provider only and
is never retained in `HttpError`, logs, diagnostics, telemetry or persisted
data. Known sensitive query keys are redacted case-insensitively, while safe
path and query context may remain for diagnosis.

| Provider or capability | Documentation |
|---|---|
| Discord | [Discord](Discord.md) |
| Facebook | [Facebook](Facebook.md) |
| Google | [Google](Google.md) |
| Instagram | [Instagram](Instagram.md) |
| Kick | [Kick](Kick.md) |
| OpenAI | [OpenAI](OpenAI.md) |
| SFTP | [SFTP](SFTP.md) |
| FTP | [FTP](FTP.md) |
| Threads | [Threads](Threads.md) |
| Twitch | [Twitch](Twitch.md) |
| X | [X](X.md) |
| YouTube capability | [YouTube](YouTube.md) |
