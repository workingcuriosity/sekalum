# Credential Wizard: Abschluss einer Consumer-Integration

Der Wizard unterscheidet bewusst zwischen **Credential bereit** und **Integration abgeschlossen**. Eine erfolgreiche OAuth-Rückkehr oder das Anlegen eines Credentials speichert nur das Credential; sie erteilt noch keinem Consumer Zugriff.

1. Provider konfigurieren, OAuth abschließen oder ein Credential anlegen. Der Wizard zeigt anschließend **Credential bereit** und fordert zur Grant-Konfiguration auf.
2. Einen vorhandenen Consumer wählen oder einen neuen Consumer-Token mit einem ausdrücklich eingegebenen Owner erzeugen. Der Klartext-Token eines neuen Consumers wird nur einmal angezeigt und bleibt ausschließlich im Speicher der geöffneten Seite.
3. Nur die erforderlichen Secret-Feldnamen auswählen und den Grant speichern. Bei OAuth-Credentials können dazu die systemverwalteten Runtime-Felder `accessToken` und, sofern vorhanden, `refreshToken` gehören; ihre Werte werden weder im Wizard noch über Provider-Metadaten angezeigt. Die Diagnose kann Berechtigung, Credential und Feldliste prüfen, ist aber kein Abschlussnachweis.
4. Für einen echten Abschluss den neuen Einmal-Token oder bei einem vorhandenen Consumer einen einmalig eingegebenen Consumer-Token verwenden. Der Wizard ruft damit `POST /api/v1/consumer/credentials/:credentialKey/resolve` auf und prüft Erfolg, `credentialKey` und `Cache-Control: no-store`.
5. Erst nach diesem echten Resolve erscheint **Integration abgeschlossen** samt Navigation zum Dashboard oder zum nächsten Credential.

Scheitert der Resolve-Aufruf, bleibt das Credential bereit und der gespeicherte Grant erhalten. Der Token kann korrigiert oder neu eingegeben und die Prüfung ohne einen Neustart des Wizards wiederholt werden. Nach einer OAuth-Rückkehr ohne Management Token bleibt derselbe Zustand sichtbar; nach Eingabe des Tokens setzt der Wizard direkt bei der Grant-Konfiguration fort.

Ändert sich nach einem fehlgeschlagenen oder erfolgreichen Resolve der Consumer, das Credential, der Provider oder die ausgewählte Secret-Feldliste, verwirft der Wizard den bisherigen Abschlussnachweis. Er gleicht die neue Auswahl mit dem tatsächlich gespeicherten Grant ab: dieselbe Consumer-/Credential-/Provider-Bindung wird bei geänderten Feldern aktualisiert; für einen anderen Consumer wird dessen eigener Grant geladen oder erstellt. Erst nach erfolgreichem Speichern der aktuellen Auswahl startet ein neuer Resolve. Bei einer reinen Token-Korrektur wird dagegen kein Grant unnötig geändert.

Bei wiederholten oder parallelen Versuchen gilt ausschließlich der zuletzt gestartete Grant-/Resolve- oder Diagnoseversuch. Eine Auswahländerung oder ein erneuter Submit macht ältere Antworten ungültig; sie können weder den gespeicherten Grant noch den Verifikationsstatus, Token-Zustand oder die sichtbare Rückmeldung verändern.

Secret-Werte werden dabei weder angezeigt noch gespeichert oder protokolliert. Die Resolve-Antwort wird ausschließlich zur unmittelbaren Erfolgsprüfung verarbeitet und verworfen.
