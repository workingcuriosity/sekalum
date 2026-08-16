# Instagram OAuth2 Provider

## Status

MS9 F6.2 ergänzt Instagram als eigenen fachlichen Provider innerhalb der Meta-Familie.

## Business-Ziel

Der Sekalum verwaltet Instagram-Credentials zentral, damit spätere Instagram-Automatisierungen auf Basis der Instagram API sicher mit Access-/Refresh-Lifecycle angebunden werden können.

## Konfiguration

```env
INSTAGRAM_CLIENT_ID=
INSTAGRAM_CLIENT_SECRET=
INSTAGRAM_REDIRECT_URI=
```

## Default Scopes

```text
instagram_business_basic
```

Weitere Instagram-Berechtigungen werden erst ergänzt, wenn dazu konkrete Business-Funktionen implementiert werden.

## Architektur

Instagram ist ein eigener fachlicher Provider und kein Facebook-Unterprofil.

```text
InstagramProvider
  -> InstagramOAuthService
  -> InstagramApiClient
```

Die gemeinsame Meta-Zugehörigkeit wird über Provider-Metadaten markiert:

```json
{
  "platformFamily": "meta"
}
```

Gemeinsame Meta-Technik bleibt Gegenstand von AB-013 Provider-Familien / Shared Provider Infrastructure.

## Nicht Bestandteil von F6.2

- Publishing
- Kommentare
- Insights
- DMs
- Facebook-Page-Verknüpfung
- Business-Login-Ausbau

F6.2 umfasst ausschließlich den Credential Lifecycle.
