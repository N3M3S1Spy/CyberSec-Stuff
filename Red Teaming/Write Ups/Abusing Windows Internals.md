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

Im ersten Schritt der Shellcode-Injektion müssen wir einen Zielprozess mit speziellen Parametern öffnen. `OpenProcess` wird verwendet, um den Zielprozess zu öffnen, der über die Befehlszeile angegeben wird.
```C++
processHandle = OpenProcess(
	PROCESS_ALL_ACCESS, // Defines access rights
	FALSE, // Target handle will not be inhereted
	DWORD(atoi(argv[1])) // Local process supplied by command-line arguments 
);
```


Im zweiten Schritt müssen wir Speicher in der Größe des Shellcodes allozieren. Die Speicherallokation wird mit `VirtualAllocEx` durchgeführt. Innerhalb des Aufrufs wird der Parameter `dwSize` mit der Funktion sizeof definiert, um die Anzahl der Bytes des Shellcodes zu erhalten, die allokiert werden sollen.
```C++
remoteBuffer = VirtualAllocEx(
	processHandle, // Opened target process
	NULL, 
	sizeof shellcode, // Region size of memory allocation
	(MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
	PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);
```


Im dritten Schritt können wir nun den allokierten Speicherbereich verwenden, um unseren Shellcode zu schreiben. `WriteProcessMemory` wird häufig verwendet, um in Speicherbereiche zu schreiben.
```C++
WriteProcessMemory(
	processHandle, // Opened target process
	remoteBuffer, // Allocated memory region
	shellcode, // Data to write
	sizeof shellcode, // byte size of data
	NULL
);
```


Im vierten Schritt haben wir nun die Kontrolle über den Prozess, und unser schädlicher Code ist im Speicher geschrieben. Um den im Speicher befindlichen Shellcode auszuführen, können wir `CreateRemoteThread` verwenden; Threads steuern die Ausführung von Prozessen.
```C++
remoteThread = CreateRemoteThread(
	processHandle, // Opened target process
	NULL, 
	0, // Default size of the stack
	(LPTHREAD_START_ROUTINE)remoteBuffer, // Pointer to the starting address of the thread
	NULL, 
	0, // Ran immediately after creation
	NULL
);
```

Wir können diese Schritte zusammenfassen, um einen einfachen Prozessinjektor zu erstellen. Verwenden Sie den bereitgestellten C++ Injektor und experimentieren Sie mit der Prozessinjektion.

Shellcode-Injektion ist die grundlegendste Form der Prozessinjektion; in der nächsten Aufgabe werden wir untersuchen, wie wir diese Schritte für das Process Hollowing modifizieren und anpassen können.

## Fragen:

Identifizieren Sie eine PID eines Prozesses, der als THM-Attacker ausgeführt wird, um diesen zu zielen. Sobald die PID identifiziert ist, geben Sie die PID als Argument an, um shellcode-injector.exe im Verzeichnis Injectors auf dem Desktop auszuführen.
```
Gehe auf dem TaskManager und gehe unter Details und suche dort nach einem Prozess, als beispiel nutzte ich den Explorer.exe prozess. syntax shellcode-injector.exe <PID>
```

Welche Flagge wird nach dem Einspritzen des Shellcodes erhalten?
```
THM{1nj3c710n_15_fun!}
```

# Task 3 -
