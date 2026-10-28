# Classic Mail MCP

**Dein Postfach. Dein Agent. Dein Server.**

Classic Mail verbindet bestehende IMAP-/SMTP-Postfächer mit einem MCP-fähigen KI-Assistenten. Du betreibst die Software selbst: lokal mit Docker, auf deinem Server oder über Google Cloud Run. Pro Installation gibt es einen Betreiber mit bis zu zehn Postfächern.

Die öffentliche Version ist eine Preview. Automatisierte Tests prüfen Protokoll und Schutzmechanismen; dein Anbieter und dein Client müssen zusätzlich praktisch getestet werden. Es gibt noch kein unabhängiges Sicherheitsaudit.

## Lokal starten

Voraussetzungen: Docker mit Compose, Python 3 und ein Postfach mit IMAP/SMTP-Passwort oder App-Passwort.

```sh
git clone https://github.com/kapitelh/classic-mail-mcp.git
cd classic-mail-mcp
python3 scripts/setup.py
docker compose up --build -d
```

Der Assistent fragt Passwörter verdeckt ab und erzeugt eigene Zufallsschlüssel. Zugangsdaten landen in `.secrets/config.json`, nicht im Git-Repository oder Docker-Image.

Im MCP-Client eintragen:

- Name: `classic-mail`
- Typ: Streamable HTTP
- URL: `http://127.0.0.1:8080/mcp`
- Bearer-Token: Wert von `bearerToken` aus deiner privaten Konfiguration.

Verlangt das Feld den **Namen einer Umgebungsvariable**, dort beispielsweise `CLASSIC_MAIL_TOKEN` eintragen und diese Variable beim Start des Clients setzen. Das Google-OAuth-Secret gehört nicht in dieses Feld.

Danach Konten auflisten lassen, `check_connection` ausführen und eine echte E-Mail lesen. Eine grüne Statusseite allein bestätigt keinen funktionierenden Postfachzugriff.

## Lesen oder Vollzugriff

Standardmäßig sind sechs Lesefunktionen aktiv. Für alle 21 Funktionen einschließlich Senden, Entwürfen, Ordnern und Löschen in `.env` setzen:

```dotenv
ACCESS_MODE=read-write
```

Anschließend `docker compose up -d` und die Werkzeuge im Client neu laden. Richte im Client Bestätigungen für Senden und irreversible Aktionen ein. Die Software stellt kein eigenes Freigabefenster bereit.

## Öffentlich erreichbar

Für ChatGPT oder andere entfernte Clients brauchst du eine öffentliche HTTPS-Adresse und OAuth. Die [Deployment-Anleitung](deployment.md) erklärt Docker hinter einem Reverse Proxy und Google Cloud Run.

Jede Person verwendet ein eigenes Cloud-Projekt bzw. einen eigenen Server, eigene Zugangsdaten und eigene Speicherung. Google meldet dich am MCP an; die Verbindung zum IMAP-/SMTP-Anbieter verwendet separat deine Mailzugangsdaten.

TLS ist verpflichtend: IMAP 993 und SMTP 465 oder STARTTLS auf 143/587. Provider mit zwingendem XOAUTH2, lokale Klartext-Bridges und beliebige Sonderports sind derzeit nicht unterstützt. Die Mailinhalte, die du abrufst, werden an deinen verbundenen KI-Client weitergegeben.

Weitere Informationen: [Englische Hauptanleitung](../README.md), [Konfiguration](configuration.md), [Client-Einrichtung](clients.md), [Fehlerhilfe](troubleshooting.md), [Sicherheitsmodell](security.md). MIT-Lizenz.

## Leseverbesserungen ab 2.1.0

Leere Klartextteile werden bei vorhandenem HTML durch eine HTML-zu-Text-Konvertierung ergänzt. Nachrichten über 8 MiB werden über einzelne MIME-Textteile gelesen; Anhänge werden dabei nicht vollständig geladen. Für alle Textteile zusammen gilt weiterhin ein Budget von 8 MiB (`bodyLimited`).

Lange Texte sind in Seiten mit 50.000 Zeichen abrufbar: `nextTextOffset` unverändert als `textOffset` übergeben, bis `null` zurückkommt. Anhänge können in 128-KiB-Blöcken bis 128 MiB dekodiert / 192 MiB kodiert abgerufen werden. Bei gestreamten Anhängen bleibt `size` bis zum letzten Block `null`; `encodedSize` ist keine dekodierte Dateigröße. Senden und Weiterleiten behalten ihr 8-MiB-Limit. Die Textkonvertierung führt keine Links oder Skripte aus und bietet weder OCR noch Entschlüsselung.
