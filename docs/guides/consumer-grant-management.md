# Consumer-Grant-Verwaltung

Diese Anleitung beschreibt den Beta-1-Stand. Consumer- und Credential-
Zuordnungen sind in Beta 1 schreibgeschuetzt; bearbeitbar bleibt nur die
explizite Freigabe von Secret-Feldnamen je Credential. Die Admin-Seite stellt
diese bestehende Berechtigungsgrenze als Consumer-Zugriff dar, ohne das
Grant-Modell oder die API zu veraendern.

Die Verwaltungsseite `/admin/consumer-grants.html` zeigt vorhandene Consumer-Grants und erlaubt ihre gezielte Aktualisierung. Ein Grant ist die explizite Least-Privilege-Freigabe eines Credentials und einzelner Secret-Feldnamen fuer genau eine Consumer-API-Identitaet.

1. Einen Management-Bearer-Token mit `consumer-grants:manage` eingeben. Der Token bleibt nur im Speicher der geöffneten Seite und wird weder in Local Storage noch im Formular gespeichert.
2. Optional nach Consumer-ID, Credential-ID oder Provider-Key filtern.
3. Den jeweiligen Grant oeffnen. Die Uebersicht zeigt Consumer, Credential, Provider und ausschliesslich die Namen der freigegebenen Secret-Felder.
4. Nur die fuer den konkreten Consumer benoetigten Secret-Feldnamen eingeben und speichern. Eine leere Liste wird vor dem Senden und durch den Server abgelehnt; die Oberflaeche ergaenzt keine versteckten Standardfelder oder Wildcards.

Fuer eine neue Freigabe verwenden Sie den Credential Wizard mit einem
Management Token, der `consumer-grants:manage` besitzt. Waehlen Sie genau eine
Consumer-Identitaet, ein Credential, den Provider und die zulaessigen Secret-
Feldnamen. Ein Grant autorisiert weder andere Credentials noch andere Provider
oder Felder. Die serverseitige Grant-Pruefung bleibt fuer jeden Discovery- und
Resolve-Aufruf massgeblich.

Vor dem Speichern zeigt der Wizard eine schreibgeschuetzte Grant Preview. Sie
trennt die ausgewaehlten Secret-Feldnamen von ausgeschlossenen Feldern und
ordnet Discovery, Resolve und Runtime-Public dem bestehenden Consumer-Vertrag
zu. Die Vorschau fuehrt keinen API-Aufruf aus, zeigt keine Secret-Werte und
veraendert keine Berechtigung; der Server bleibt fuer die tatsaechliche
Grant-Pruefung massgeblich.

Die Seite zeigt nie Secret-Werte. Management- und Consumer-Token bleiben nur
im Arbeitsspeicher der geoeffneten Seite; sie werden nicht in Browser Storage
gespeichert. Die Diagnose prueft die Konfiguration ohne Secret-Werte
anzuzeigen, ersetzt aber nicht den echten Consumer-Resolve.

Die Seite zeigt nie Secret-Werte und kann keine neue Freigabe erzeugen. Neue Grants werden weiterhin bewusst im Credential Wizard angelegt.

### Was der Consumer-Zugriff bedeutet

Der Consumer sieht in **Discovery** nur aktive Credentials mit passender
Freigabe sowie deren öffentliche Metadaten und Feldvertrag. **Resolve** liefert
nur ausdrücklich angeforderte Secret-Felder, die für genau dieses Credential
und diese Consumer-Identität freigegeben sind. Andere Credentials,
Provider-Interna, nicht freigegebene Felder und nicht autorisierte Secret-Werte
sind nicht zugänglich; Wildcards gibt es nicht. Der Consumer-API-Token
authentifiziert den Consumer. Der Management-Token dient ausschließlich der
Administration und ist keine Consumer-Berechtigung.
