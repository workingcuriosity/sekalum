---
title: Data Model Reference
version: 1.4.0
classification: Public
status: Active
category: Data Model
canonical: true
owner: Credential HUB
approved_by: pending
maintainer: cyphre-san productions
contact: luiscyphre404@gmail.com
license: AGPL-3.0-only
copyright: "© 2026 cyphre-san productions"
target_audience:
  - Entwickler
  - Architekten
dependent_documents:
  - docs/architecture/Gesamtarchitektur.md
  - docs/project/Storage.md
  - docs/api-reference/index.md
  - docs/adr/ADR-020-Credential-Consumer-API.md
  - docs/adr/ADR-021-Generic-Credential-Method-Model.md
  - docs/architecture/glossary/GLOSSARY.md
change_history:
  - version: 1.4.0
    date: 2026-07-26
    change: Harmonizes the public domain relationships and method-aware Credential contract with ADR-020 and ADR-021.
  - version: 1.3.0
    date: 2026-07-16
    change: Documents the active R5 CredentialMethod model and explicit compatibility migration boundary.
  - version: 1.2.0
    date: 2026-07-16
    change: Records the target CredentialMethod identity and its issue #47 implementation boundary.
  - version: 1.1.0
    date: 2026-07-13
    change: Documents generic Credential collection persistence alongside the legacy TokenRecord compatibility path.
  - version: 1.0.0
    date: 2026-07-11
    change: CP-007 leitet die aktive Datenmodellreferenz aus Domain-Modellen und Lifecycle-Tests ab.
---

# Data Model Reference

## Core credential model

`Credential` is the primary domain object. It has `credentialId`, `providerKey`, optional `credentialMethodKey`, optional `externalReference`, `lifecycleState`, an immutable collection of `secrets`, `metadata`, timestamps, and a version. Updates create new immutable instances and increment the version.

`CredentialSecret` holds an ID, name, value, optional metadata, and timestamps. `CredentialMetadata` holds display name, description, scopes, tags, expiry, and extensible custom data.

```text
Credential
  -> one or more CredentialSecret
  -> one CredentialMetadata
  -> zero or more history entries, secret versions, policies and notifications
```

## Domain relationships

The active domain relationships are:

```text
Provider
  -> zero or more CredentialMethods
  -> zero or more ProviderMethodBindings

ProviderMethodBinding
  -> one Provider
  -> one CredentialMethod
  -> Provider-specific public metadata
  -> optional adapters for method-declared operations

Credential
  -> one Provider
  -> one selected ProviderMethodBinding when method-aware
  -> one or more CredentialSecrets
  -> public CredentialMetadata

Consumer
  -> authenticated runtime application identity

ConsumerGrant
  -> one Consumer/API-token identity
  -> one Credential
  -> one Provider key
  -> explicit permitted Secret names
```

`Provider` represents the external system. It does not own an alternative
method field schema for a method-aware Credential. `CredentialMethod` and
`ProviderMethodBinding` are domain contracts, not additional stored Secret
models or Consumer-specific models. `ConsumerGrant` authorizes runtime use;
it does not replace Consumer authentication or represent a Credential.

## CredentialMethod model

ADR-021 defines the active identity of a method-based Credential as `providerKey` plus one explicit `credentialMethodKey`. The method key selects one ProviderMethodBinding, which makes the method available for the Provider; the CredentialMethod itself defines the permitted Credential and Secret fields plus operation capabilities, while the binding may only supply a Provider Adapter for a declared operation. It is neither a second Provider key nor a replacement for the Credential ID; many Credentials may share the same Provider and method.

`CredentialMethod` is a reusable declarative description of one authentication
or credential procedure. It owns the ordered field definitions, required and
Secret classification, and permitted operations. `ProviderMethodBinding`
connects that method to one Provider and may add Provider-specific public
metadata or an adapter for an operation already declared by the method. A
binding cannot add fields or capabilities.

`credentialMethodKey` is persisted as a first-class field. A method-aware Provider requires it for creation and validates that both the method and its binding exist. At startup, compatible existing Credentials are migrated and persisted with an explicit method key: durable `credentialType`, the legacy OAuth token shape, or a single unambiguous binding may select that key. Ambiguous records fail with `CREDENTIAL_METHOD_MIGRATION_AMBIGUOUS`; `metadata.type`, `metadata.credentialType`, and secret-name inference are not runtime method-selection fallbacks.

The target model does not add method-specific Secret storage. `CredentialSecret`
remains generic; the selected CredentialMethod exclusively defines which named
fields are Secrets and which fields are public metadata. The same method field
contract is consumed by REST validation, Wizard rendering, CSV mapping and
import validation.

## Consumer and Consumer Grant model

`Consumer` is an authenticated runtime application represented at runtime by
the API-token identity. It does not select or interpret a CredentialMethod and
does not own Credential storage, lifecycle or Provider authentication.

`ConsumerGrant` is the explicit authorization relationship between that
Consumer identity, one Credential, its Provider key and the permitted Secret
names. Grant evaluation occurs during Consumer API resolution. Only active
Credentials and explicitly granted Secret fields are eligible for resolution.
The Consumer API returns resolved values only through its authenticated,
`no-store` response and never persists a second Consumer-specific Credential
model.

## Lifecycle

Credential states are `registered`, `validated`, `active`, `expiring`, `expired`, `revoked`, and `deleted`. Actions are separate from states: `create`, `validate`, `refresh`, `revoke`, `delete`, and `health-check`.

`CredentialHistoryEntry` records a credential ID, timestamp, source, action, result, actor, summary, and optional structured details. `LifecycleNotification` references an optional credential and provider, with `open`, `acknowledged`, or `resolved` status and `info`, `warning`, or `critical` severity.

## Policies and secret versions

`CredentialPolicy` can match Credentials by Provider key and a persisted
credential-type compatibility value. That policy selector is not a runtime
fallback for `credentialMethodKey` selection. The policy contains rotation and
expiry-warning settings, optional owner role, criticality, active or disabled
status, timestamps and version.

`CredentialSecretVersion` stores an immutable snapshot of secrets for one credential with a positive version number, reason, creator, timestamp, and metadata. It supports history and controlled rollback through the corresponding service.

## API tokens

`ApiToken` is separate from provider credentials. It stores token prefix and hash, never plaintext token content, plus user ID, scopes, creation data, optional expiry, revocation, last use, and version. Its derived status is `active`, `expired`, or `revoked`; revocation takes precedence over expiry. `toPublicJSON()` omits the hash.

## Legacy boundary

`CredentialCollectionStoreAdapter` persists current `Credential` objects without mapping them to provider-token fields. `TokenRecord` remains a legacy persistence record for existing OAuth provider token files; `LegacyTokenCredentialStoreAdapter` maps those records to and from `Credential`. `CompositeCredentialStoreAdapter` exposes both sources through `CredentialStore` while new API-key and connection work remains on the generic model.

## Verification boundary

This reference was verified against `src/models/`, the credential lifecycle services, and the corresponding model, policy, history, secret-version, notification, and API-token tests. The CredentialMethod section records the active issue #47 implementation. This reference does not define API payload schemas, provider-specific fields, or storage encryption details.
