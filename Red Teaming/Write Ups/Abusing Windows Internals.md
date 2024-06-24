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

Auf der grundlegendsten Ebene nimmt die Prozessinjektion die Form der Shellcode-Injektion an.

Auf einer höheren Ebene kann die Shellcode-Injektion in vier Schritte unterteilt werden:

1. Öffnen eines Zielprozesses mit allen Zugriffsrechten.
2. Allozieren von Speicher im Zielprozess für den Shellcode.
3. Schreiben des Shellcodes in den allozierten Speicher im Zielprozess.
4. Ausführen des Shellcodes mithilfe eines Remote-Threads.

Die Schritte können auch grafisch dargestellt werden, um zu zeigen, wie Windows-API-Aufrufe mit dem Prozessspeicher interagieren.

![Shellcode Injection Prozess Darstellung](Bilder/2024-06-24-Shellcode_Injection_Prozess_Darstellung.png)

# Erklärung der Shellcode-Injektionsgrafik

Diese Grafik zeigt die Schritte der Shellcode-Injektion in einem Zielprozess durch einen bösartigen Prozess und wie Windows-API-Aufrufe dabei interagieren. Hier ist eine Erklärung der einzelnen Schritte und Komponenten:

1. **OpenProcess**:
   - Der bösartige Prozess (unten links) verwendet die API-Funktion `OpenProcess`, um den Zielprozess (oben links) mit allen erforderlichen Zugriffsrechten zu öffnen. Dies ermöglicht dem bösartigen Prozess, auf den Speicher des Zielprozesses zuzugreifen.

2. **VirtualAlloc**:
   - Der bösartige Prozess verwendet die API-Funktion `VirtualAlloc`, um einen Speicherbereich im Zielprozess zu allozieren. Dieser Schritt bereitet den Speicher vor, in den der Shellcode geschrieben werden soll.

3. **WriteProcessMemory**:
   - Der bösartige Prozess verwendet die API-Funktion `WriteProcessMemory`, um den Shellcode in den zuvor allokierten Speicherbereich im Zielprozess zu schreiben.

4. **CreateRemoteThread**:
   - Der bösartige Prozess verwendet die API-Funktion `CreateRemoteThread`, um einen neuen Thread im Zielprozess zu erstellen, der den Shellcode ausführt. Dies ermöglicht es dem bösartigen Code, innerhalb des Kontextes des Zielprozesses ausgeführt zu werden.

## Prozessspeicherregionen

- Die verschiedenen Speicherregionen des Zielprozesses sind in blau dargestellt, einschließlich DLLs, Register, Prozess-Heap, Thread-Stack und allgemeine Prozessspeicherregionen.
- Die "Malicious Memory Region" (bösartige Speicherregion) ist der Bereich, in dem der Shellcode eingefügt und ausgeführt wird.

Durch diese Schritte wird der Shellcode in den Speicher des Zielprozesses injiziert und ausgeführt, was dem Angreifer die Möglichkeit gibt, Kontrolle über den Zielprozess zu erlangen und bösartige Aktivitäten durchzuführen.
