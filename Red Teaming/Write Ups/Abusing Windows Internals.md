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
