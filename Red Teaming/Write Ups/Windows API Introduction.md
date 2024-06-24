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
| --- | --- |
Für mehr informationen zum Thema Speicher Management ( Memory Management ) ist der [Windows Internals](https://tryhackme.com/r/room/windowsinternals) Raum geeignet
