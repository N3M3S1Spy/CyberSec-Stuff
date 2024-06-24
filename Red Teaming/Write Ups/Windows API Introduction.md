# Windows API Introduction
Das ist eine einführung zu dem TryHackMe Raum: [Windows API Introduction](https://tryhackme.com/r/room/windowsapi)

# Task 1 - Introduction (Einführung)
Die Windows-API bietet Funktionen, mit denen man direkt mit wichtigen Teilen des Windows-Betriebssystems arbeiten kann. Sie wird von vielen genutzt, darunter Sicherheitsforscher, Angreifer, Verteidiger, Softwareentwickler und Anbieter von Lösungen.

Die API kann leicht in das Windows-System integriert werden und bietet viele Anwendungsmöglichkeiten. Zum Beispiel wird die Win32-API für die Entwicklung von schädlicher Software, Sicherheitssoftware (wie EDR - Endpoint Detection & Response) und allgemeiner Software verwendet. Mehr Informationen zu den Einsatzmöglichkeiten der API findet man im Windows API Index.

### Lernziele:

1. Verstehen, was die Windows-API ist, wofür sie verwendet wird und wie sie mit dem Betriebssystem zusammenarbeitet.
2. Lernen, wie man die Windows-API in verschiedenen Programmiersprachen verwendet.
3. Verstehen, wie die Windows-API böswillig genutzt werden kann und praktische Beispiele analysieren.

Vor Beginn dieses Kurses ist es hilfreich, ein grundlegendes Verständnis der Betriebssystemarchitektur zu haben. Grundlegende Programmierkenntnisse sind ebenfalls nützlich, aber nicht zwingend erforderlich.

Dieser Kurs soll die Grundlagen der Windows-API vermitteln. Wir werden kurz die Implementierungen der Win32-API ansprechen, uns aber darauf konzentrieren, warum und wo API-Aufrufe verwendet werden.

# Task 2 - Subsystem und Hardware Interaktion
Programme müssen oft auf Windows-Subsysteme (z.B. Dateisysteme, Netzwerkdienste, Prozess- und Thread-Verwaltung, Sicherheitsdienste, Gerätemanagement) oder Hardware zugreifen oder diese ändern, sind jedoch eingeschränkt, um die Stabilität des Computers zu gewährleisten. Um dieses Problem zu lösen, hat Microsoft die Win32-API veröffentlicht, eine Bibliothek, die eine Schnittstelle zwischen Benutzeranwendungen und dem Kernel bietet.

Windows unterscheidet den Hardwarezugriff durch zwei verschiedene Modi: **Benutzer**- und **Kernelmodus**. Diese Modi bestimmen, auf welche Hardware, Kernel und Speicher eine Anwendung oder ein Treiber zugreifen darf. API- oder Systemaufrufe dienen als Schnittstelle zwischen diesen Modi und senden Informationen an das System, die im Kernelmodus (z.B. Verwaltung von Hardwarezugriffen, Speicherverwaltung, Prozessscheduling) verarbeitet werden.

| Benutzer Modus | Kernal Modus|
| -------------- | ----------- |
| Kein Direkter Hardware zugriff | Direkter Hardware zugriff |
| Zugriff auf "eigene" Speicherplätze | Zugriff auf den gesamten physischen Speicher |

Für mehr informationen zum Thema Speicher Management ( Memory Management ) ist der [TryHackMe Windows Internals](https://tryhackme.com/r/room/windowsinternals) Raum geeignet

Nachfolgend ist eine Darstellung, wie eine Benutzeranwendung API-Aufrufe nutzen kann, um Kernel-Komponenten zu verändern:
1. User Application: Eine Benutzeranwendung läuft im Benutzermodus/Userland.
2. API (Win32 API): Die Benutzeranwendung verwendet die Win32 API, um Systemfunktionen aufzurufen.
3. Switching Point: An diesem Punkt erfolgt der Wechsel vom Benutzermodus in den Kernelmodus.
4. System Calls: Die API-Aufrufe werden in Systemaufrufe umgewandelt.
5. Kernel: Die Systemaufrufe interagieren mit dem Kernel, der die Kernfunktionen des Betriebssystems steuert.
6. Physical Memory: Der Kernel verwaltet den physischen Speicher.
7. Hardware: Der Kernel steuert die Hardware-Komponenten des Systems.

Wenn man sieht, wie Programmiersprachen mit der Win32-API arbeiten, wird der Prozess komplexer: Die Anwendung geht zuerst durch die Laufzeitumgebung der Programmiersprache, bevor sie die API verwendet.

### Fragen:
Hat ein Prozess im Benutzermodus direkten Hardwarezugriff? (Ja/Nein)
```
Nein, das Bedriebssystem verhindert dies.
```
Wird ein Prozess im Kernelmodus geöffnet, wenn man eine Anwendung als Administrator startet? (Ja/Nein)
```
Nein, der Kernal Modus wird nur bei Funktionen aufgerufen die diesen Modus benötigen. Dazu muss man die Anwendung auch nicht als Administrator starten.
```

# Task 3 - Komponenten der Windows API
Die Win32-API, allgemein bekannt als die Windows-API, umfasst mehrere abhängige Komponenten, die verwendet werden, um die Struktur und Organisation der API zu definieren.

Lassen Sie uns die Win32-API durch einen top-down Ansatz aufschlüsseln. Wir nehmen an, dass die API die oberste Ebene ist und die Parameter, die einen spezifischen Aufruf ausmachen, die unterste Ebene sind. In der folgenden Tabelle beschreiben wir die top-down Struktur auf hoher Ebene und gehen später ins Detail.
| Ebene | Erläurterung |
| ----- | ---------------------------------------------------------------------------------------------------------------------------- |
| API   | Ein oberster/allgemeiner Begriff oder Theorie, der verwendet wird, um jeden Aufruf in der Win32-API-Struktur zu beschreiben. |
| Headerdateien oder Imports | Definiert Bibliotheken, die zur Laufzeit importiert werden, festgelegt durch Headerdateien oder Bibliotheksimporte. Verwendet Zeiger, um die Funktionsadresse zu erhalten. |
| Kern-DLLs | Eine Gruppe von vier DLLs, die Aufrufstrukturen definieren (KERNEL32, USER32 und ADVAPI32). Diese DLLs definieren Kernel- und Benutzerdienste, die nicht in einem einzigen Subsystem enthalten sind. |
| Ergänzende DLLs | Andere DLLs, die als Teil der Windows-API definiert sind. Steuern separate Subsysteme des Windows-Betriebssystems. Etwa 36 weitere definierte DLLs (NTDLL, COM, FVEAPI usw.). |
| Aufrufstrukturen | Definiert den API-Aufruf selbst und die Parameter des Aufrufs. |
| API-Aufrufe | Der in einem Programm verwendete API-Aufruf, bei dem die Funktionsadressen über Zeiger erhalten werden. |
| Ein-/Aus-Parameter | Die durch die Aufrufstrukturen definierten Parameterwerte. |

Lassen Sie uns diese Definitionen erweitern; in der nächsten Aufgabe werden wir das Importieren von Bibliotheken, die Kern-Headerdatei und die Aufrufstruktur besprechen. In Aufgabe 4 werden wir tiefer in die Aufrufe eintauchen und verstehen, wo und wie die Aufrufparameter und Varianten verarbeitet werden.

### Fragen:
Welche Headerdatei importiert und definiert die User32-DLL und deren Struktur?: (Benötigt externe rescherche)
```
winuser.h - google nach User32-DLL dann stößt man auf die Wiki seite **Microsoft Windows library files** und dort unter User32-DLL steht geschrieben das es von windows user importiert wird.
```
Welche übergeordnete Headerdatei enthält alle anderen erforderlichen untergeordneten und Kern-Headerdateien?
```
windows.h - windows.h wird standart mäßig importiert wenn man mit der Windows-API arbeiten möchte
```

# Task 4 - OS Libraries
Jeder API-Aufruf der Win32-Bibliothek befindet sich im Speicher und benötigt einen Zeiger auf eine Speicheradresse. Der Prozess des Erhaltens von Zeigern auf diese Funktionen wird durch die Implementierungen der ASLR (Address Space Layout Randomization) verschleiert; jede Programmiersprache oder jedes Paket hat ein einzigartiges Verfahren, um ASLR zu überwinden. In diesem Abschnitt werden wir die zwei beliebtesten Implementierungen besprechen: [P/Invoke](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke) und die [Windows-Headerdatei](https://learn.microsoft.com/en-us/windows/win32/winprog/using-the-windows-headers).
