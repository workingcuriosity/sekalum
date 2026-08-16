---
title: Third-Party Software
version: 1.0.0
status: Active
category: Project
canonical: true
maintainer: cyphre-san productions
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 cyphre-san productions"
target_audience:
  - Developers
  - Administrators
  - Auditors
dependent_documents:
  - LICENSE
  - NOTICE
  - DISCLAIMER.md
  - package.json
  - package-lock.json
change_history:
  - version: 1.0.0
    date: 2026-07-12
    change: CP-012A records the resolved production dependency set from package-lock.json and installed package metadata.
---

# Third-Party Software

## Purpose

Sekalum uses open-source npm packages. This document records the resolved production dependency set, its package versions, and the licenses declared by the installed package metadata.

This document is informational. It does not replace the original license text, copyright notices, or other obligations of any third-party component. Those terms continue to apply to the respective components.

## Verification Basis

The inventory was generated for the repository state dated 2026-07-12 from `package-lock.json` and a clean `npm ci` installation. `package.json` declares two direct runtime dependencies. The resolved installation contains 68 package paths and 67 unique package and version pairs, including transitive dependencies.

Recreate the inventory for a release after installing the lockfile-defined dependencies:

```bash
npm ci
npm ls --all
```

Update this document whenever `package.json` or `package-lock.json` changes. Do not infer versions from version ranges in `package.json`.

## Direct Runtime Dependencies

| Component | Version | License | Purpose |
|---|---:|---|---|
| dotenv | 17.4.2 | BSD-2-Clause | Loads supported runtime configuration from environment files. |
| express | 5.2.1 | MIT | Provides the HTTP callback, REST, and static administration server. |

## Transitive Runtime Dependencies

The following components are resolved transitively by the direct runtime dependencies above.

| Component | Version | License |
|---|---:|---|
| accepts | 2.0.0 | MIT |
| body-parser | 2.3.0 | MIT |
| bytes | 3.1.2 | MIT |
| call-bind-apply-helpers | 1.0.2 | MIT |
| call-bound | 1.0.4 | MIT |
| content-disposition | 1.1.0 | MIT |
| content-type | 1.0.5 | MIT |
| content-type | 2.0.0 | MIT |
| cookie | 0.7.2 | MIT |
| cookie-signature | 1.2.2 | MIT |
| debug | 4.4.3 | MIT |
| depd | 2.0.0 | MIT |
| dunder-proto | 1.0.1 | MIT |
| ee-first | 1.1.1 | MIT |
| encodeurl | 2.0.0 | MIT |
| es-define-property | 1.0.1 | MIT |
| es-errors | 1.3.0 | MIT |
| es-object-atoms | 1.1.2 | MIT |
| escape-html | 1.0.3 | MIT |
| etag | 1.8.1 | MIT |
| finalhandler | 2.1.1 | MIT |
| forwarded | 0.2.0 | MIT |
| fresh | 2.0.0 | MIT |
| function-bind | 1.1.2 | MIT |
| get-intrinsic | 1.3.0 | MIT |
| get-proto | 1.0.1 | MIT |
| gopd | 1.2.0 | MIT |
| has-symbols | 1.1.0 | MIT |
| hasown | 2.0.4 | MIT |
| http-errors | 2.0.1 | MIT |
| iconv-lite | 0.7.2 | MIT |
| inherits | 2.0.4 | ISC |
| ipaddr.js | 1.9.1 | MIT |
| is-promise | 4.0.0 | MIT |
| math-intrinsics | 1.1.0 | MIT |
| media-typer | 1.1.0 | MIT |
| merge-descriptors | 2.0.0 | MIT |
| mime-db | 1.54.0 | MIT |
| mime-types | 3.0.2 | MIT |
| ms | 2.1.3 | MIT |
| negotiator | 1.0.0 | MIT |
| object-inspect | 1.13.4 | MIT |
| on-finished | 2.4.1 | MIT |
| once | 1.4.0 | ISC |
| parseurl | 1.3.3 | MIT |
| path-to-regexp | 8.4.2 | MIT |
| proxy-addr | 2.0.7 | MIT |
| qs | 6.15.3 | BSD-3-Clause |
| range-parser | 1.3.0 | MIT |
| raw-body | 3.0.2 | MIT |
| router | 2.2.0 | MIT |
| safer-buffer | 2.1.2 | MIT |
| send | 1.2.1 | MIT |
| serve-static | 2.2.1 | MIT |
| setprototypeof | 1.2.0 | ISC |
| side-channel | 1.1.1 | MIT |
| side-channel-list | 1.0.1 | MIT |
| side-channel-map | 1.0.1 | MIT |
| side-channel-weakmap | 1.0.2 | MIT |
| statuses | 2.0.2 | MIT |
| toidentifier | 1.0.1 | MIT |
| type-is | 2.1.0 | MIT |
| unpipe | 1.0.0 | MIT |
| vary | 1.1.2 | MIT |
| wrappy | 1.0.2 | ISC |

## License and Notice Handling

Sekalum is licensed under [AGPL-3.0-only](../../LICENSE). Third-party components retain their own licenses. Consult the installed package metadata and the respective upstream project for original license texts and any attribution or notice requirements.

The project-level `NOTICE`, [Legal Information](LEGAL.md), and `DISCLAIMER.md` provide the applicable Sekalum legal context. This inventory does not add terms to, or alter, a third-party license.

## Repository Identity Check

CP-012A also verifies the public repository identity before release. `package.json`, both root name fields in `package-lock.json`, and the active Docker Compose service and container names use `credential-hub`.

The identity scan searches for `token-manager`, `Token Manager`, `token_manager`, `tokenmanager`, and `TOKEN_MANAGER`. Remaining matches are intentionally retained only in the following contexts:

- `TokenManager` source code and its component test remain a documented compatibility facade for `CredentialManager`.
- The persisted backup type `token-manager-backup` remains for storage-format compatibility.
- Historical, archive, and review documents retain predecessor terminology where it is necessary evidence of the project history.

These retained matches are not current package metadata, active Compose naming, or public product terminology.

## Scope Boundary

This is a lockfile-based inventory of npm runtime packages. It is not a vulnerability report, a software bill of materials in a regulated interchange format, or a substitute for release-specific license due diligence.
