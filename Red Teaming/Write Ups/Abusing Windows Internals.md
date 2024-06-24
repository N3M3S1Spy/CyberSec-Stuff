# Abusing Windows Internals
Dies ist eine einführung zu dem TryHackMe Raum: [Abusing Windows Internals](https://tryhackme.com/r/room/abusingwindowsinternals)

# Task 1 - Introduction (Einführung)
Windows-Internals sind entscheidend für die Funktionsweise des Windows-Betriebssystems. Dies macht sie zu einem lukrativen Angriffsziel für bösartige Zwecke. Windows-Internals können verwendet werden, um Code zu verbergen und auszuführen, Erkennungen zu umgehen und mit anderen Techniken oder Exploits zu verknüpfen.

Der Begriff Windows-Internals umfasst jede Komponente, die auf der Backend-Seite des Windows-Betriebssystems gefunden werden kann. Dazu gehören Prozesse, Dateiformate, COM (Component Object Model), Taskplanung, I/O-System usw. Dieser Raum wird sich darauf konzentrieren, Prozesse und ihre Komponenten, DLLs (Dynamic Link Libraries) sowie das PE (Portable Executable) Format zu missbrauchen und auszunutzen.

### Lernziele:

- Verständnis dafür entwickeln, wie interne Komponenten angreifbar sind
- Erlernen, wie man Schwachstellen in Windows-Internals ausnutzt und missbraucht
- Verständnis für Maßnahmen zur Minderung und Erkennung dieser Techniken entwickeln
- Anwendung der erlernten Techniken auf eine Fallstudie aus der realen Welt

Bevor Sie mit diesem Raum beginnen, machen Sie sich mit der grundlegenden Nutzung und Funktionalität von Windows vertraut. Es ist empfelendwert, den Raum zu [Windows-Internals](https://tryhackme.com/r/room/windowsinternals) zu absolvieren. Grundlegende Programmierkenntnisse in C++ und PowerShell werden ebenfalls empfohlen, sind aber nicht zwingend erforderlich.

# Task 2 - Prozesse ausnutzen
Anwendungen, die auf deinem Betriebssystem laufen, können einen oder mehrere Prozesse enthalten. Prozesse verwalten und repräsentieren ein Programm, das ausgeführt wird.

Prozesse haben viele weitere Unterkomponenten und interagieren direkt mit dem Speicher oder dem virtuellen Speicher, was sie zu einem idealen Ziel macht. Die folgende Tabelle beschreibt jede kritische Komponente von Prozessen und deren Zweck.
| Prozesskomponente                | Zweck                                                                 |
|----------------------------------|----------------------------------------------------------------------|
| Privater virtueller Adressraum   | Virtuelle Speicheradressen, die dem Prozess zugewiesen sind.         |
| Ausführbares Programm            | Definiert Code und Daten, die im virtuellen Adressraum gespeichert sind. |
| Offene Handles                   | Definiert Handles zu Systemressourcen, auf die der Prozess zugreifen kann. |
| Sicherheitskontext               | Das Zugriffstoken definiert den Benutzer, Sicherheitsgruppen, Berechtigungen und andere Sicherheitsinformationen. |
| Prozess-ID                       | Eindeutige numerische Kennung des Prozesses.                          |
| Threads                          | Abschnitt eines Prozesses, der zur Ausführung eingeplant ist.        |

Für weitere Informationen über Prozesse, sieh dir den [Windows Internals](https://tryhackme.com/r/room/windowsinternals) Raum an.

Prozessinjektion wird häufig als Oberbegriff verwendet, um das Einschleusen von schädlichem Code in einen Prozess durch legitime Funktionalitäten oder Komponenten zu beschreiben. In diesem Raum konzentrieren wir uns auf vier verschiedene Arten der Prozessinjektion, wie unten beschrieben.
| Injektionstyp                     | Funktion                                                                                   |
|-----------------------------------|--------------------------------------------------------------------------------------------|
| Process Hollowing                 | Code in einen angehaltenen und "ausgehöhlten" Zielprozess einschleusen                      |
| Thread Execution Hijacking        | Code in einen angehaltenen Zielthread einschleusen                                          |
| Dynamic-link Library Injection    | Eine DLL in den Prozessspeicher einschleusen                                                 |
| Portable Executable Injection     | Ein PE-Image selbst in einen Zielprozess einschleusen, das auf eine schädliche Funktion zeigt |

Es gibt viele andere Formen der Prozessinjektion, die von MITRE im Rahmen der T1055 beschrieben werden. [MITRE T1055](https://attack.mitre.org/techniques/T1055/)
