# Abusing Windows Internals
Dies ist eine einführung zu dem TryHackMe Raum: [Abusing Windows Internals](https://tryhackme.com/r/room/abusingwindowsinternals)

# Task 1 - Einführung
In diesem Kurs werden wir untersuchen, wie man Payloads erstellt und bereitstellt, wobei der Schwerpunkt darauf liegt, die Erkennung durch gängige Antiviren-Engines zu vermeiden. Wir werden verschiedene Techniken betrachten, die uns als Angreifer zur Verfügung stehen, und die Vor- und Nachteile jeder einzelnen diskutieren.

Ziele

- Erlernen, wie Shellcodes erstellt werden.
- Untersuchung der Vor- und Nachteile von gestuften Payloads.
- Erstellung von unauffälligen Shellcodes zur Vermeidung von AV-Erkennung.

Voraussetzungen

Es wird empfohlen, einige Vorkenntnisse darüber zu haben, wie Antivirensoftware funktioniert, sowie ein grundlegendes Verständnis von Verschlüsselung und Codierung zu besitzen. Obwohl es nicht zwingend erforderlich ist, können Kenntnisse in grundlegender Assemblersprache ebenfalls hilfreich sein. Außerdem empfehlen wir ein grundlegendes Verständnis im Lesen und Verstehen von Funktionen (C, C#).

# Task 2 - Herausforderung
In dieser Herausforderung haben wir eine Windows-Maschine mit einer Webanwendung vorbereitet, über die Sie Ihre Payloads hochladen können. Nach dem Hochladen werden die Payloads von einer Antivirensoftware überprüft und ausgeführt, wenn sie als frei von Malware erkannt werden. Das Hauptziel dieser Herausforderung ist es, die Antivirensoftware auf der VM zu umgehen und die Flagge im Dateisystem zu erfassen. Nutzen Sie gerne alle Techniken, die im Raum diskutiert wurden, indem Sie diese unter http://COSTUM-IP/ hochladen.

Wichtige Punkte:

- Versuchen Sie, die diskutierten Techniken zu kombinieren.
- Die Website unterstützt nur EXE-Dateien.
- Sobald die Antivirensoftware die hochgeladene Datei gescannt und keine schädlichen Codes gefunden hat, wird die Datei ausgeführt. Wenn also alles richtig zusammengefügt ist, sollten Sie eine umgekehrte Shell erhalten.
![Antivirus GUI Showcase](Bilder/2024-07-01-AV-GUI-Showcase.png)

Sie können die Fragen für diese Aufgabe vorerst ignorieren, aber stellen Sie sicher, dass Sie auf sie zurückkommen, sobald Sie die Antivirensoftware erfolgreich umgangen und eine Shell erhalten haben.

Bereiten Sie die angehängte virtuelle Maschine (VM) vor, um mit dem Inhalt des Raums fortzufahren, bevor Sie zur nächsten Sektion übergehen! Die VM wird in Ihrem Browser bereitgestellt und sollte automatisch im geteilten Bildschirm erscheinen. Falls die VM nicht sichtbar ist, verwenden Sie die blaue Schaltfläche "Split View anzeigen" oben rechts auf der Seite. Wenn Sie bevorzugen, über RDP eine Verbindung herzustellen, können Sie dies mit den folgenden Anmeldedaten tun:
![Login Credentials](Bilder/2024-07-01-Login-Credentials.png)

Du wirst auch die AttackBox für einige Aufgaben benötigen, daher ist dies ein guter Zeitpunkt, um damit anzufangen.

## Fragen:
Welche Antivirensoftware läuft auf der virtuellen Maschine?
```
Windows Defender
```

Wie lautet der Name des Benutzerkontos, auf das du Zugriff hast?
```
```

Erstelle eine funktionierende Shell auf der Opfermaschine und lies die Datei auf dem Desktop des Benutzers. Was ist die Flagge?
```
```

Task 3 - PE Struktur
Diese Aufgabe hebt einige der wichtigen Elemente der PE-Datenstruktur für Windows-Binärdateien hervor.

Was ist PE?

Das Portable Executable (PE) ist das Dateiformat für ausführbare Dateien unter Windows, das eine Datenstruktur darstellt, welche die für Dateien notwendigen Informationen enthält. Es dient dazu, den ausführbaren Dateicode auf einer Festplatte zu organisieren. Betriebssystemkomponenten wie Windows- und DOS-Lader können diese Dateien in den Speicher laden und auf Basis der analysierten Dateiinformationen aus dem PE ausführen.

Im Allgemeinen haben Windows-Binärdateien wie EXE, DLL und Objektcode dieselbe PE-Struktur und funktionieren im Windows-Betriebssystem für die CPU-Architekturen (x86 und x64).

Die PE-Struktur umfasst verschiedene Abschnitte, die Informationen über die Binärdatei enthalten, wie Metadaten und Verweise auf Speicheradressen externer Bibliotheken. Einer dieser Abschnitte ist der PE-Header, der Metadateninformationen, Zeiger und Verknüpfungen zu Abschnitten im Speicher enthält. Ein anderer Abschnitt ist der Datenabschnitt, der Container enthält, die die für den Windows-Lader erforderlichen Informationen zum Ausführen eines Programms enthalten, wie ausführbarer Code, Ressourcen, Verknüpfungen zu Bibliotheken, Datenvariablen usw.
![Aufbau und Komponenten einer Portablen Ausführbaren Datei (PE-Datei)](Bilder/2024-07-01-Aufbau-und-Komponenten-einer-Portablen-Ausführbaren-Datei-(PE-Datei).png)

Es gibt verschiedene Arten von Datencontainern in der PE-Struktur, die jeweils unterschiedliche Daten halten:

1. `.text` speichert den tatsächlichen Programmcode.
2. `.data` enthält initialisierte und definierte Variablen.
3. `.bss` enthält nicht initialisierte Daten (deklarierte Variablen ohne zugewiesene Werte).
4. `.rdata` enthält schreibgeschützte Daten.
5. `.edata` enthält exportierbare Objekte und zugehörige Tabelleninformationen.
6. `.idata` enthält importierte Objekte und zugehörige Tabelleninformationen.
7. `.reloc` enthält Informationen zur Bild-Adressumsetzung.
8. `.rsrc` verknüpft externe Ressourcen, die vom Programm verwendet werden, wie Bilder, Icons, eingebettete Binärdateien und eine Manifestdatei, die alle Informationen zu Programmversionen, Autoren, Unternehmen und Urheberrecht enthält.

Die PE-Struktur ist ein umfangreiches und komplexes Thema, und wir werden hier nicht zu detailliert auf die Header und Datenabschnitte eingehen. Diese Aufgabe bietet einen Überblick über die PE-Struktur auf hoher Ebene. Wenn du mehr Informationen zu diesem Thema erhalten möchtest, empfehlen wir, die folgenden THM-Räume zu überprüfen, wo das Thema detaillierter erklärt wird:

- [Windows Internals](https://tryhackme.com/r/room/windowsinternals)
- Analyse von PE-Headern

Du kannst auch weitere detaillierte Informationen über PE auf der [Website der Windows PE-Format-Dokumentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) erhalten.

Wenn wir uns den Inhalt der PE ansehen, sehen wir, dass er eine Reihe von Bytes enthält, die für Menschen nicht lesbar sind. Dennoch enthält er alle Details, die der Loader benötigt, um die Datei auszuführen. Im Folgenden sind die Beispiel-Schritte aufgeführt, mit denen der Windows-Loader eine ausführbare Binärdatei liest und als Prozess ausführt:

1. **Header-Abschnitte:** DOS-, Windows- und optionale Header werden analysiert, um Informationen über die EXE-Datei bereitzustellen. Zum Beispiel:
   - Die magische Zahl beginnt mit "MZ", was dem Loader signalisiert, dass es sich um eine EXE-Datei handelt.
   - Dateisignaturen
   - Ob die Datei für die x86- oder x64-CPU-Architektur kompiliert ist.
   - Erstellungszeitstempel.

2. **Analyse der Abschnittstabelle-Details:** Anzahl der Abschnitte, die die Datei enthält.

3. **Zuordnung der Dateiinhalte in den Speicher basierend auf:**
   - Der Einstiegspunkt-Adresse und dem Offset der Bildbasis.
   - RVA: Relative Virtual Address, Adressen bezogen auf Imagebase.

4. **Imports, DLLs und andere Objekte werden in den Speicher geladen.**

5. **Die Einstiegspunkt-Adresse wird lokalisiert und die Hauptausführungsfunktion wird ausgeführt.**

**Warum müssen wir über PE Bescheid wissen?**

Es gibt ein paar Gründe, warum wir es lernen müssen. Erstens erfordert die Technik des Packens und Entpackens detaillierte Kenntnisse über die PE-Struktur.

Der andere Grund ist, dass AV-Software und Malware-Analysten EXE-Dateien auf der Grundlage der Informationen im PE-Header und anderen PE-Abschnitten analysieren. Daher müssen wir die Struktur der Windows-Portable-Executable-Dateien verstehen, um Malware mit AV-Evasion-Fähigkeiten zu erstellen oder zu modifizieren, die auf eine Windows-Maschine abzielt, und wissen, wo der bösartige Shellcode gespeichert werden kann.

Wir können kontrollieren, in welchem Datenabschnitt wir unseren Shellcode speichern, indem wir definieren, wie wir die Shellcode-Variable definieren und initialisieren. Hier sind einige Beispiele, die zeigen, wie wir den Shellcode in PE speichern können:

- Die Definition des Shellcodes als lokale Variable innerhalb der Hauptfunktion speichert ihn im `.text` PE-Abschnitt.
- Die Definition des Shellcodes als globale Variable speichert ihn im `.data`-Abschnitt.
- Eine weitere Technik besteht darin, den Shellcode als Rohbinärdatei in einem Iconbild zu speichern und es im Code zu verlinken, sodass er im `.rsrc`-Datenabschnitt angezeigt wird.
- Wir können einen benutzerdefinierten Datenabschnitt hinzufügen, um den Shellcode zu speichern.

**PE-Bear**

Die angehängte VM ist eine Windows-Entwicklungsmaschine, die die Tools zum Analysieren von EXE-Dateien enthält und die besprochenen Details lesen kann. Zur einfachen Nutzung haben wir eine Kopie der PE-Bear-Software auf dem Desktop bereitgestellt, die die PE-Struktur überprüft: Header, Abschnitte usw. PE-Bear bietet eine grafische Benutzeroberfläche, um alle relevanten EXE-Details anzuzeigen. Um eine EXE-Datei zur Analyse zu laden, wähle `Datei -> PE laden (Strg + O)`.
![PE Bear new file load](Bilder/2024-07-01-PE-Bear-new-file-load.png)

Sobald eine Datei geladen ist, können wir alle PE-Details sehen. Der folgende Screenshot zeigt die PE-Details der geladenen Datei, einschließlich der Header und Abschnitte, die wir zuvor in dieser Aufgabe besprochen haben.
![PE Bear loaded file](Bilder/2024-07-01-PE-Bear-loaded-file.png)

Jetzt ist es an der Zeit, es auszuprobieren! Lade die Datei **thm-intro2PE.exe**, um die unten stehenden Fragen zu beantworten. Die Datei befindet sich unter folgendem Pfad: `c:\Tools\PE files\thm-intro2PE.exe`.

## Fragen:
Was sind die letzten 6 Stellen des MD5-Hashwerts der Datei **thm-intro2PE.exe**?
```
```

Was ist der Wert der Magic Number der Datei **thm-intro2PE.exe** (in Hexadezimal)?
```
```

Was ist der Einstiegspunkt-Wert der Datei **thm-intro2PE.exe**?
```
```

Wie viele Abschnitte hat die Datei **thm-intro2PE.exe**?
```
```

Eine benutzerdefinierte Sektion könnte verwendet werden, um zusätzliche Daten zu speichern. Malware-Entwickler nutzen diese Technik, um einen neuen Abschnitt zu erstellen, der ihren bösartigen Code enthält und den Programmfluss umleitet, um den Inhalt des neuen Abschnitts auszuführen. Wie lautet der Name dieser zusätzlichen Sektion?
```
```

Überprüfe den Inhalt der zusätzlichen Sektion. Was ist die Flagge?
```
```
