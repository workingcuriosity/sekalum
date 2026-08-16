# Sekalum n8n Examples

Diese Workflows demonstrieren den offiziellen Consumer API Ablauf von Sekalum.

## Enthaltene Beispiele

### Consumer API Example (OpenAI)

Zeigt:

- Discovery
- Credential Selection
- Resolve
- OpenAI Request
- Sanitized Result

### OAuth Consumer Example (Twitch)

Zeigt:

- Discovery
- Runtime-Public Fields
- Resolve
- OAuth Request
- Sanitized Result

### Consumer API Template

Generischer Ausgangspunkt für eigene Integrationen und die Auswahl eines
Credentials aus mehreren Discover-Ergebnissen.

Das Template zeigt:

- ein n8n-Item pro von Discover geliefertem Credential;
- providerbasierte Auswahl über `metadata.displayName` mit einem Switch;
- getrennte Twitch- und OpenAI-Zweige;
- Weitergabe des ausgewählten `credentialKey` an Resolve;
- einen sicheren Auffangzweig für nicht konfigurierte Provider.

Die Auswahl ist unabhängig von der Reihenfolge der Discover-Items. Der
Sekalum-Node unterstützt zusätzlich einen lokalen Provider Filter: leer für
alle Provider oder mit einem Provider-Namen für Variante A.

Der Anwender muss lediglich konfigurieren:

- Credential Display Name
- Secret Names
- Public Fields

---

## Voraussetzungen

- Sekalum läuft
- Consumer API Token vorhanden
- Credential eingerichtet
- Consumer Grant vorhanden

---

## Sicherheit

Sekalum liefert Secrets ausschließlich über Resolve.

Die Beispiele geben niemals Secret-Werte aus.
