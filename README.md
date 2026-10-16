# SecureMessage – Testversion

Deutschsprachige Offline-Anwendung für Windows und macOS (Python 3.12).

## Installation der fertigen Programme

Die Programme stehen unter **Releases** zum Download. Sie sind nicht von Apple
notarisiert bzw. nicht mit einem Microsoft-Zertifikat signiert. Beide Systeme
warnen daher beim ersten Start. Das betrifft alle unsignierten Programme und
ist kein Hinweis auf Schadsoftware.

### macOS (Apple Silicon)

`SecureMessage-<Version>-macOS-arm64.dmg` öffnen und die App auf „Programme“
ziehen. Beim ersten Start meldet macOS, die App könne nicht überprüft werden
oder sei „beschädigt“. **Nicht** in den Papierkorb legen, sondern:

- **Systemeinstellungen → Datenschutz & Sicherheit** → ganz unten
  **„Dennoch öffnen“** klicken, oder
- im Terminal einmalig ausführen:

  ```bash
  xattr -dr com.apple.quarantine /Applications/SecureMessage.app
  ```

Die ausführliche Anleitung liegt als `LIESMICH.txt` im DMG.

### Windows 11

`SecureMessage-<Version>-Windows-x64.exe` ist ein einzelnes Programm ohne
Installation; es kann z. B. in einen eigenen Ordner gelegt werden.

1. **Browser-Warnung beim Download** (Edge: „wird nicht häufig
   heruntergeladen“): über **„…“ → „Beibehalten“** bzw. „Trotzdem
   beibehalten“ speichern.
2. **„Der Computer wurde durch Windows geschützt“** (SmartScreen) beim ersten
   Start: auf **„Weitere Informationen“** klicken, dann auf
   **„Trotzdem ausführen“**. Danach erscheint die Meldung nicht mehr.
3. **Smart App Control:** Ist diese Funktion aktiv (Windows-Sicherheit →
   App- & Browsersteuerung), blockiert Windows unsignierte Programme
   vollständig, ohne Ausnahme-Knopf. SecureMessage ist dann auf diesem PC
   nicht nutzbar, solange Smart App Control eingeschaltet ist.
4. **Virenscanner:** Mit PyInstaller gebaute Programme werden gelegentlich
   fälschlich gemeldet. Im Zweifel die Datei beim Herausgeber verifizieren.

Der erste Start dauert einige Sekunden, weil sich das Programm zunächst in
einen temporären Ordner entpackt.

### Updates

Es gibt bewusst keine automatische Update-Prüfung; die App nimmt keine
Verbindung ins Internet auf. Neue Versionen werden persönlich weitergegeben.

## Entwicklung (PyCharm-Terminal)

Projektordner öffnen, die bestehende `.venv` beibehalten und im Terminal ausführen:

```bash
python -m pip install -r requirements.txt
python main.py
```

Falls `python` nicht auf die Projektumgebung verweist, unter macOS `.venv/bin/python` verwenden.

## Bedienung

- Verschlüsseln: Kennung A01–E20 auswählen, Passwort vom Papier eintippen, Nachricht schreiben, verschlüsseln, Ergebnis kopieren und über WhatsApp senden.
- Entschlüsseln: Modus wechseln, vollständigen `SM1:...`-Text einfügen (Zeilenumbrüche und Leerzeichen aus dem Messenger stören nicht), Kennung wird erkannt, Papierpasswort eintippen, entschlüsseln.
- Dateien (Reiter „Dateien“): Eine oder mehrere Dateien (zusammen höchstens 200 MB) hineinziehen oder auswählen, Kennung und Passwort angeben, „Verschlüsseln und speichern …“. Die entstehende `.smf`-Datei über WhatsApp als **Dokument** senden. Zum Entschlüsseln die `.smf`-Datei hineinziehen, die Kennung wird erkannt, Passwort eintippen, „Entschlüsseln“ und anschließend „Speichern unter …“. Vorhandene Dateien werden beim Speichern mehrerer Dateien nie überschrieben.
- Das Programm speichert weder Passwörter noch Nachrichten. Achtung: Die Zwischenablage kann Inhalte über das Programmende hinaus behalten, auch über Cloud-Synchronisierung oder Clipboard-Manager.

## Verschlüsselungsformat

`SM1:<KENNUNG>:<Base64url-ohne-Padding>`

Binärpayload: 16 Byte zufälliges Salt, 12 Byte zufälliger Nonce, AES-GCM-Ciphertext mit 16 Byte Tag. AES-256-GCM-Schlüssel: Argon2id aus UTF-8-Passwort und Salt (64 MiB, 3 Durchläufe, Parallelität 1, 32 Byte Ausgabe). Authentifizierte Zusatzdaten: UTF-8 `SM1:<KENNUNG>`. Pro Nachricht neue kryptografisch zufällige Werte. Kennung ist nicht geheim. Falsche Passwörter und manipulierte Nachrichten werden abgewiesen.

### Dateiformat (`.smf`)

`SMF1<KENNUNG>` (7 Byte, unverschlüsselt, als Zusatzdaten authentifiziert) + 16 Byte Salt + 12 Byte Nonce + AES-256-GCM-Ciphertext mit 16 Byte Tag; Schlüsselableitung wie oben. Der verschlüsselte Inhalt besteht aus 4 Byte Länge, einem JSON-Verzeichnis `[{"name", "size"}, …]` und den aneinandergereihten Dateiinhalten. Dateinamen sind damit verschlüsselt; sichtbar bleibt nur die ungefähre Gesamtgröße. Beim Entschlüsseln werden nur einfache Dateinamen ohne Pfadanteile akzeptiert.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Sicherheitsgrenzen

- Diese selbst entwickelte Anwendung ist **nicht unabhängig sicherheitsgeprüft**. Für hochkritische Kommunikation nur nach externem Audit verwenden.
- Gemeinsame Passwörter bieten keine Forward Secrecy und keine eindeutige Absenderauthentisierung. Wer das Papierpasswort besitzt, kann Nachrichten unter dieser Kennung erzeugen.
- Passwort nur persönlich übergeben. Papier sicher aufbewahren. Ein Passwort möglichst nur für eine Nachricht verwenden und anschließend auf beiden Seiten markieren.
- Der Klartext bleibt im Eingabe-/Ergebnisfeld und ggf. in der Zwischenablage, bis er entfernt wird. Passwortfelder werden nach Nutzung geleert, aber Python kann die vollständige Speicherbereinigung nicht garantieren.
- Kein Netzwerkcode, keine Telemetrie; die Anwendung verwendet aber externe Python-Pakete. Für reproduzierbare Releases später Versionen fixieren und Builds prüfen.
- Dateien werden vollständig im Arbeitsspeicher verarbeitet (bis 200 MB; dabei kurzzeitig knapp 1 GB RAM). Entschlüsselte Dateien landen erst durch „Speichern unter …“ auf der Festplatte und liegen dann unverschlüsselt dort – nach Gebrauch selbst löschen.
