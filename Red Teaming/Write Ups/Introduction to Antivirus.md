

# Task 1 - Einführung
Willkommen bei Einführung in AV

Antivirensoftware (AV) ist eine der wichtigsten hostbasierten Sicherheitslösungen, die verfügbar sind, um Malware-Angriffe auf dem Rechner des Endbenutzers zu erkennen und zu verhindern. AV-Software besteht aus verschiedenen Modulen, Funktionen und Erkennungstechniken, die in diesem Raum besprochen werden.

Als Red Teamer oder Pentester ist es wichtig, die Funktionsweise von AV-Software und deren Erkennungstechniken zu verstehen. Mit diesem Wissen wird es einfacher, Techniken zur Umgehung von AV zu entwickeln.

Lernziele

- Was ist Antivirensoftware?
- Erkennungsansätze von Antivirensoftware
- Auflistung der installierten AV-Software auf dem Zielrechner
- Testen in einer simulierten Umgebung

Voraussetzungen für den Raum

- Allgemeine Kenntnisse über hostbasierte Erkennungslösungen; weitere Informationen im Raum [The Lay of the Land](https://tryhackme.com/r/room/thelayoftheland).
- Allgemeine Erfahrungen mit Hashing-Kryptografie; weitere Informationen im Raum [Hashing - Crypto 101](https://tryhackme.com/r/room/hashingcrypto101).
- Grundkenntnisse über Yara-Regeln; weitere Informationen im THM [Yara](https://tryhackme.com/r/room/yara) Raum.

## Fragen:
Fangen wir an!
```
Keine Antwort nötig
```

# Task 2 - Antivirus Software
### Was ist Antivirensoftware?

Antivirensoftware (AV) ist eine zusätzliche Sicherheitsschicht, die darauf abzielt, die Ausführung und Verbreitung bösartiger Dateien in einem Zielbetriebssystem zu erkennen und zu verhindern.

Es handelt sich um eine hostbasierte Anwendung, die in Echtzeit (im Hintergrund) läuft, um die aktuellen und neu heruntergeladenen Dateien zu überwachen und zu überprüfen. Die AV-Software untersucht und entscheidet mithilfe verschiedener Techniken, ob Dateien bösartig sind, welche später in diesem Raum behandelt werden.

Interessanterweise war die erste Antivirensoftware ausschließlich dazu konzipiert, [Computerviren](https://malware-history.fandom.com/wiki/Virus) zu erkennen und zu entfernen. Heutzutage hat sich das geändert; moderne Antivirenprogramme können nicht nur Computerviren, sondern auch andere schädliche Dateien und Bedrohungen erkennen und entfernen.

### Was sucht Antivirensoftware?

Traditionelle Antivirensoftware sucht nach Malware mit vordefinierten bösartigen Mustern oder Signaturen. Malware ist schädliche Software, deren Hauptziel es ist, Schaden auf einem Zielrechner zu verursachen, einschließlich, aber nicht beschränkt auf:

- Vollständigen Zugriff auf einen Zielrechner erlangen.
- Sensible Informationen wie Passwörter stehlen.
- Dateien verschlüsseln und beschädigen.
- Andere bösartige Software oder unerwünschte Werbung einschleusen.
- Die kompromittierte Maschine nutzen, um weitere Angriffe wie Botnet-Attacken durchzuführen.

### AV vs. andere Sicherheitsprodukte

Neben Antivirensoftware bieten auch andere hostbasierte Sicherheitslösungen Echtzeitschutz für Endgeräte. Endpoint Detection and Response (EDR) ist eine Sicherheitslösung, die Echtzeitschutz basierend auf Verhaltensanalysen bietet. Eine Antivirenanwendung führt das Scannen, Erkennen und Entfernen bösartiger Dateien durch. EDR hingegen überwacht verschiedene Sicherheitsüberprüfungen auf dem Zielrechner, einschließlich Dateiaktivitäten, Speicher, Netzwerkverbindungen, Windows-Registrierung, Prozesse usw.

Moderne Antivirenprodukte sind so konzipiert, dass sie die traditionellen Antivirenfunktionen und andere erweiterte Funktionalitäten (ähnlich den EDR-Funktionalitäten) in einem Produkt integrieren, um umfassenden Schutz vor digitalen Bedrohungen zu bieten. Für weitere Informationen über hostbasierte Sicherheitslösungen empfehlen wir den THM-Raum: [The Lay of the Land](https://tryhackme.com/r/room/thelayoftheland) zu besuchen.

### Antivirensoftware in Vergangenheit und Gegenwart

[McAfee Associates, Inc](https://de.wikipedia.org/wiki/McAfee). begann 1987 mit der ersten Implementierung von Antivirensoftware. Diese wurde "VirusScan" genannt und hatte damals das Hauptziel, einen Virus namens "Brain" zu entfernen, der John McAfees Computer infiziert hatte. Später schlossen sich andere Unternehmen dem Kampf gegen Viren an. Antivirensoftware wurde Scanner genannt und war eine Kommandozeilen-Software, die nach bösartigen Mustern in Dateien suchte.

Seitdem haben sich die Dinge verändert. Heutzutage verwendet Antivirensoftware eine grafische Benutzeroberfläche (GUI), um Scans nach bösartigen Dateien und andere Aufgaben durchzuführen. Auch Schadprogramme haben sich weiterentwickelt und zielen nun auf Opfer unter Windows und anderen Betriebssystemen ab. Moderne Antivirensoftware unterstützt die meisten Geräte und Plattformen, einschließlich Windows, Linux, macOS, Android und iOS. Sie hat sich verbessert und ist intelligenter und ausgeklügelter geworden, da sie ein Bündel vielseitiger Funktionen enthält, darunter Antivirus, Anti-Exploit, Firewall, Verschlüsselungstool usw.

Wir werden einige dieser AV-Funktionen in der nächsten Aufgabe besprechen.

## Fragen:
Was bedeutet AV?:
```
Antivirus
```

Welcher PC-Antivirenhersteller brachte die erste AV-Software auf den Markt?
```
McAfee
```

Antiviren-Software ist eine auf _____ basierende Sicherheitslösung.
```
Host
```

# Task 3 - Antivirus Funktionen
### Antivirus Engines

Eine AV-Engine ist dafür verantwortlich, bösartigen Code und Dateien zu finden und zu entfernen. Gute Antivirensoftware implementiert einen effektiven und soliden AV-Kern, der bösartige Dateien genau und schnell analysiert. Außerdem sollte sie verschiedene Dateitypen unterstützen und verarbeiten können, einschließlich Archivdateien, bei denen sie sich selbst extrahieren und alle komprimierten Dateien überprüfen kann.

Die meisten AV-Produkte teilen die gleichen grundlegenden Funktionen, die jedoch unterschiedlich implementiert sind. Dazu gehören unter anderem:

- Scanner
- Erkennungstechniken
- Kompressoren und Archive
- Entpacker
- Emulatoren

### Scanner

Die Scanner-Funktion ist in den meisten AV-Produkten enthalten: Antivirensoftware läuft und scannt in Echtzeit oder auf Abruf. Diese Funktion ist in der grafischen Benutzeroberfläche (GUI) oder über die Eingabeaufforderung verfügbar. Der Benutzer kann sie bei Bedarf verwenden, um Dateien oder Verzeichnisse zu überprüfen. Die Scanner-Funktion muss die bekanntesten bösartigen Dateitypen unterstützen, um die Bedrohung zu erkennen und zu entfernen. Darüber hinaus kann sie je nach AV-Software auch andere Arten des Scannens unterstützen, einschließlich Schwachstellen, E-Mails, Windows-Speicher und Windows-Registrierung.

### Erkennungstechniken

Eine AV-Erkennungstechnik sucht nach und erkennt bösartige Dateien; verschiedene Erkennungstechniken können innerhalb der AV-Engine verwendet werden, darunter:

- Signaturbasierte Erkennung ist die traditionelle AV-Technik, die nach vordefinierten bösartigen Mustern und Signaturen in Dateien sucht.
- Heuristische Erkennung ist eine fortschrittlichere Technik, die verschiedene Verhaltensmethoden einbezieht, um verdächtige Dateien zu analysieren.
- Dynamische Erkennung ist eine Technik, die Systemaufrufe und APIs überwacht sowie Tests und Analysen in einer isolierten Umgebung durchführt.

Wir werden diese Techniken in der nächsten Aufgabe behandeln. Eine gute AV-Engine erkennt bösartige Dateien genau und schnell mit weniger falsch-positiven Ergebnissen. Wir werden mehrere AV-Produkte vorstellen, die ungenaue Ergebnisse liefern und eine Datei falsch klassifizieren.

### Kompressoren und Archive

Die Funktion "Kompressoren und Archive" sollte in jeder Antivirensoftware enthalten sein. Sie muss verschiedene Systemdateitypen unterstützen und verarbeiten können, einschließlich komprimierter oder archivierter Dateien: ZIP, TGZ, 7z, XAR, RAR usw. Bösartiger Code versucht oft, hostbasierte Sicherheitslösungen zu umgehen, indem er sich in komprimierten Dateien versteckt. Aus diesem Grund muss die Antivirensoftware alle Dateien dekomprimieren und scannen, bevor ein Benutzer eine Datei im Archiv öffnet.

### PE (Portable Executable) Parsing und Entpacker

Malware versteckt und packt seinen bösartigen Code, indem es ihn innerhalb eines Payloads komprimiert und verschlüsselt. Es dekomprimiert und entschlüsselt sich während der Laufzeit, um die statische Analyse zu erschweren. Daher muss Antivirensoftware in der Lage sein, die meisten bekannten Packer (UPX, Armadillo, ASPack usw.) vor der Laufzeit zu erkennen und zu entpacken, um eine statische Analyse durchzuführen.

Malware-Entwickler verwenden verschiedene Techniken, wie das Packen, um die Größe zu reduzieren und die Struktur der bösartigen Datei zu verändern. Beim Packen wird die ursprüngliche ausführbare Datei komprimiert, um die Analyse zu erschweren. Daher muss Antivirensoftware über eine Entpackerfunktion verfügen, um geschützte oder komprimierte ausführbare Dateien in den Originalcode zu entpacken.

Eine weitere Funktion, die Antivirensoftware haben muss, ist ein Parser für Windows Portable Executable (PE) Header. Das Parsen der PE-Header ausführbarer Dateien hilft, bösartige von legitimer Software (.exe-Dateien) zu unterscheiden. Das PE-Dateiformat in Windows (32 und 64 Bit) enthält verschiedene Informationen und Ressourcen, wie Objektcode, DLLs, Symboldateien, Schriftdateien und Speicherabbilder.

### Emulatoren

Ein Emulator ist eine Antivirenfunktion, die eine weitergehende Analyse verdächtiger Dateien durchführt. Sobald ein Emulator eine Anfrage erhält, führt der Emulator die verdächtigen (exe, DLL, PDF usw.) Dateien in einer virtualisierten und kontrollierten Umgebung aus. Er überwacht das Verhalten der ausführbaren Dateien während der Ausführung, einschließlich der Windows-API-Aufrufe, der Registrierung und anderer Windows-Dateien. Die folgenden sind Beispiele für Artefakte, die der Emulator sammeln kann:

- API-Aufrufe
- Speicherabbilder
- Änderungen im Dateisystem
- Protokollereignisse
- Laufende Prozesse
- Webanfragen

Ein Emulator stoppt die Ausführung einer Datei, wenn genügend Artefakte gesammelt wurden, um Malware zu erkennen.

### Weitere gängige Funktionen

Die folgenden sind einige gängige Funktionen, die in Antivirenprodukten zu finden sind:

- Ein Selbstschutztreiber, um das AV vor Angriffen durch Malware zu schützen.
- Firewall- und Netzwerkanalyse-Funktionalität.
- Kommandozeilen- und grafische Schnittstellen-Tools.
- Ein Daemon oder Dienst.
- Eine Managementkonsole.

## Fragen:
Welche AV-Funktion analysiert Malware in einer sicheren und isolierten Umgebung?
```
Emulator
```

Die _______ Funktion ermöglicht die Wiederherstellung oder Entschlüsselung der komprimierten ausführbaren Dateien in das Original.
```
Unpacker
```

Lesen Sie die obigen Ausführungen, um mit der nächsten Aufgabe fortzufahren, in der wir die AV-Erkennungstechniken besprechen.
```
Keine Antwort nötig
```
