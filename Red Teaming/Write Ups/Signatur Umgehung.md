Ein Gegner kann Schwierigkeiten haben, spezifische Erkennungsmethoden zu überwinden, wenn er es mit einer fortschrittlichen Antiviren-Engine oder einer **EDR** (**E**ndpoint **D**etection & **R**esponse) Lösung zu tun hat. Selbst nach der Anwendung einiger der häufigsten in den [Prinzipien der Verschleierung](https://tryhackme.com/r/room/obfuscationprinciples) diskutierten Verschleierungstechniken können Signaturen in einer schädlichen Datei weiterhin vorhanden sein.

Um persistente Signaturen zu bekämpfen, können Gegner jede einzelne beobachten und nach Bedarf angehen.

In diesem Raum werden wir verstehen, was Signaturen sind und wie man sie findet, und dann versuchen, sie mit einem neutralen Denkansatz zu brechen. Um tiefer einzusteigen und heuristische Signaturen zu bekämpfen, werden wir auch fortgeschrittene Code-Konzepte und "Best Practices" für Malware diskutieren.

### Lernziele

- Ursprung der Signaturen verstehen und lernen, sie in schädlichem Code zu beobachten/erkennen.
- Dokumentierte Verschleierungsmethoden implementieren, um Signaturen zu brechen.
- Nicht-Verschleierungs-Techniken nutzen, um nicht funktionsorientierte Signaturen zu durchbrechen.

Dieser Raum baut auf den [Prinzipien der Verschleierung](https://tryhackme.com/r/room/obfuscationprinciples) auf; wir empfehlen dringend, ihn abzuschließen, bevor Sie mit diesem Raum beginnen, falls Sie dies noch nicht getan haben.

Bevor Sie diesen Raum starten, machen Sie sich mit grundlegenden Programmierlogiken und Syntaxen vertraut. Kenntnisse in C und PowerShell sind empfohlen, aber nicht zwingend erforderlich.

Wir haben eine Basis-Windows-Maschine mit den für diesen Raum benötigten Dateien bereitgestellt. Sie können auf die Maschine im Browser oder über RDP mit den folgenden Anmeldedaten zugreifen:

Maschinen-IP: `MACHINE_IP`             Benutzername: `Student`             Passwort: `TryHackMe!`

# Task 2 - Signaturidentifikation
Bevor wir uns darauf stürzen, Signaturen zu brechen, müssen wir verstehen und identifizieren, wonach wir suchen. Wie im [Einführungskurs zur Antivirensoftware](https://tryhackme.com/r/room/introtoav) erklärt, werden Signaturen von Antiviren-Engines verwendet, um möglicherweise verdächtige und/oder schädliche Programme zu verfolgen und zu identifizieren. In dieser Aufgabe werden wir untersuchen, wie wir manuell bestimmen können, an welcher genauen Stelle im Byte eine Signatur beginnt.

Beim Identifizieren von Signaturen, ob manuell oder automatisiert, müssen wir einen iterativen Prozess anwenden, um festzustellen, an welchem Byte eine Signatur beginnt. Indem wir ein kompiliertes Binärprogramm rekursiv in der Mitte teilen und testen, können wir eine grobe Schätzung des Byte-Bereichs erhalten, der weiter untersucht werden muss.

Wir können die nativen Dienstprogramme `head`, `dd` oder `split` verwenden, um ein kompiliertes Binärprogramm zu teilen. Im folgenden Befehlsfenster werden wir durch die Verwendung von head gehen, um die erste Signatur in einem msfvenom-Binärprogramm zu finden.

Nachdem Sie das Binärprogramm geteilt haben, verschieben Sie es von Ihrer Entwicklungsumgebung auf eine Maschine mit der Antiviren-Engine, die Sie testen möchten. Wenn ein Alarm erscheint, gehen Sie zum unteren Teil des geteilten Binärprogramms und teilen es erneut. Wenn kein Alarm erscheint, gehen Sie zum oberen Teil des geteilten Binärprogramms und teilen es erneut. Setzen Sie dieses Muster fort, bis Sie nicht mehr bestimmen können, wohin Sie gehen sollen; dies tritt normalerweise im Bereich von Kilobytes auf.

Sobald Sie den Punkt erreicht haben, an dem Sie das Binärprogramm nicht mehr genau teilen können, können Sie einen Hex-Editor verwenden, um das Ende des Binärprogramms zu betrachten, wo die Signatur vorhanden ist.
```hex
0000C2E0  43 68 6E E9 0A 00 00 00 0C 4D 1A 8E 04 3A E9 89  Chné.....M.Ž.:é‰
0000C2F0  67 6F BE 46 01 00 00 6A 40 90 68 00 10 00 00 E9  go¾F...j@.h....é
0000C300  0A 00 00 00 53 DF A1 7F 64 ED 40 73 4A 64 56 90  ....Sß¡.dí@sJdV.
0000C310  6A 00 68 58 A4 53 E5 E9 08 00 00 00 15 0D 69 B6  j.hX¤Såé......i¶
0000C320  F4 AB 1B 73 FF D5 E9 0A 00 00 00 7D 43 00 40 DB  ô«.sÿÕé....}C.@Û
0000C330  43 8B AC 55 82 89 C3 90 E9 08 00 00 00 E4 95 8E  C‹¬U‚‰Ã.é....ä•Ž
0000C340  2C 06 AC 29 A3 89 C7 90 E9 0B 00 00 00 0B 32 AC  ,.¬)£‰Ç.é.....2¬
```

Wir kennen die Position einer Signatur, aber wie gut lesbar sie ist, hängt sowohl vom verwendeten Tool als auch von der Kompilierungsmethode ab.

Nun möchte niemand stundenlang hin und her gehen, um schlechte Bytes zu finden; lassen Sie uns das automatisieren! Im nächsten Schritt werden wir einige FOSS (Free and Open-Source Software) Lösungen betrachten, die uns dabei helfen können, Signaturen in kompiliertem Code zu identifizieren.

## Fragen:
Verwenden Sie das Wissen, das Sie in dieser Aufgabe gewonnen haben, um die Binärdatei unter `C:\Users\Student\Desktop\Binaries\shell.exe` mit einem in dieser Aufgabe besprochenen nativen Dienstprogramm zu teilen. Bestimmen Sie rekursiv, ob die aufgeteilte Binärdatei eine Erkennung auslöst, bis Sie das nächstgelegene Kibibyte ermitteln, an dem die erste Signatur erkannt wird.
```
Keine Antwort nötig
```

Auf das nächstgelegene Kibibyte gerundet, wo befindet sich das erste erkannte Byte?
```

```

# Task 3 - Automatisierung der Signaturidentifizierung
Der Prozess aus der vorherigen Aufgabe kann ziemlich mühsam sein. Um ihn zu beschleunigen, können wir ihn automatisieren, indem wir Skripte verwenden, um Bytes über ein Intervall für uns aufzuteilen. [Find-AVSignature](https://github.com/PowerShellMafia/PowerSploit/blob/master/AntivirusBypass/Find-AVSignature.ps1) wird eine angegebene Byte-Range durch ein bestimmtes Intervall teilen.
```powershell
PS C:\> . .\FInd-AVSignature.ps1
PS C:\> Find-AVSignature

cmdlet Find-AVSignature at command pipeline position 1
Supply values for the following parameters:
StartByte: 0
EndByte: max
Interval: 1000

Do you want to continue?
This script will result in 1 binaries being written to "C:\Users\TryHackMe"!
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): y
```

Dieses Skript erleichtert einen Großteil der manuellen Arbeit, hat aber immer noch einige Einschränkungen. Obwohl es weniger Interaktion als die vorherige Aufgabe erfordert, muss dennoch ein geeignetes Intervall festgelegt werden, damit es ordnungsgemäß funktioniert. Das Skript überwacht auch nur die Zeichenfolgen der Binärdatei, wenn sie auf die Festplatte abgelegt werden, anstatt die vollständige Funktionalität des Antivirus-Motors zum Scannen zu nutzen.

Um dieses Problem zu lösen, können wir andere FOSS (Free and Open-Source Software) Tools verwenden, die die Motoren selbst nutzen, um die Datei zu scannen, darunter [DefenderCheck](https://github.com/matterpreter/DefenderCheck), [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) und [AMSITrigger](https://github.com/RythmStick/AMSITrigger). In dieser Aufgabe werden wir uns hauptsächlich auf ThreatCheck konzentrieren und am Ende kurz auf die Verwendung von AMSITrigger eingehen.
##
### ThreatCheck

ThreatCheck ist ein Fork von DefenderCheck und gilt als das am weitesten verbreitete/zuverlässigste der drei Tools. Zur Identifizierung möglicher Signaturen nutzt ThreatCheck mehrere Antivirus-Motoren gegen aufgeteilte kompilierte Binärdateien und gibt an, wo es schlechte Bytes vermutet.

ThreatCheck stellt keine vorkompilierte Version für die Öffentlichkeit zur Verfügung. Für eine einfache Nutzung haben wir das Tool bereits für Sie kompiliert; es befindet sich auf dem Desktop unter `C:\Users\Administrator\Desktop\Tools` des angehängten Computers.

Nachfolgend die grundlegende Syntax von ThreatCheck.
```cmd
C:\>ThreatCheck.exe --help
  -e, --engine    (Default: Defender) Scanning engine. Options: Defender, AMSI
  -f, --file      Analyze a file on disk
  -u, --url       Analyze a file from a URL
  --help          Display this help screen.
  --version       Display version information.
```

Für unsere Zwecke müssen wir nur eine Datei und optional einen Motor angeben. Allerdings werden wir AMSITrigger hauptsächlich verwenden, wenn es um **AMSI** (**A**nti-**M**alware **S**can **I**nterface) geht, wie wir später in dieser Aufgabe besprechen werden.
```cmd
C:\>ThreatCheck.exe -f Downloads\Grunt.bin -e AMSI
	[+] Target file size: 31744 bytes
	[+] Analyzing...
	[!] Identified end of bad bytes at offset 0x6D7A
	00000000   65 00 22 00 3A 00 22 00  7B 00 32 00 7D 00 22 00   e·"·:·"·{·2·}·"·
	00000010   2C 00 22 00 74 00 6F 00  6B 00 65 00 6E 00 22 00   ,·"·t·o·k·e·n·"·
	00000020   3A 00 7B 00 33 00 7D 00  7D 00 7D 00 00 43 7B 00   :·{·3·}·}·}··C{·
	00000030   7B 00 22 00 73 00 74 00  61 00 74 00 75 00 73 00   {·"·s·t·a·t·u·s·
	00000040   22 00 3A 00 22 00 7B 00  30 00 7D 00 22 00 2C 00   "·:·"·{·0·}·"·,·
	00000050   22 00 6F 00 75 00 74 00  70 00 75 00 74 00 22 00   "·o·u·t·p·u·t·"·
	00000060   3A 00 22 00 7B 00 31 00  7D 00 22 00 7D 00 7D 00   :·"·{·1·}·"·}·}·
	00000070   00 80 B3 7B 00 7B 00 22  00 47 00 55 00 49 00 44   ·?³{·{·"·G·U·I·D
	00000080   00 22 00 3A 00 22 00 7B  00 30 00 7D 00 22 00 2C   ·"·:·"·{·0·}·"·,
	00000090   00 22 00 54 00 79 00 70  00 65 00 22 00 3A 00 7B   ·"·T·y·p·e·"·:·{
	000000A0   00 31 00 7D 00 2C 00 22  00 4D 00 65 00 74 00 61   ·1·}·,·"·M·e·t·a
	000000B0   00 22 00 3A 00 22 00 7B  00 32 00 7D 00 22 00 2C   ·"·:·"·{·2·}·"·,
	000000C0   00 22 00 49 00 56 00 22  00 3A 00 22 00 7B 00 33   ·"·I·V·"·:·"·{·3
	000000D0   00 7D 00 22 00 2C 00 22  00 45 00 6E 00 63 00 72   ·}·"·,·"·E·n·c·r
	000000E0   00 79 00 70 00 74 00 65  00 64 00 4D 00 65 00 73   ·y·p·t·e·d·M·e·s
	000000F0   00 73 00 61 00 67 00 65  00 22 00 3A 00 22 00 7B   ·s·a·g·e·"·:·"·{
```

Das ist so einfach! Es ist keine weitere Konfiguration oder Syntax erforderlich, und wir können direkt damit beginnen, unsere Werkzeuge anzupassen. Um dieses Tool effizient zu nutzen, können wir zunächst identifizieren, welche schlechten Bytes entdeckt wurden, diese rekursiv aufbrechen und das Tool erneut ausführen, bis keine Signaturen mehr identifiziert werden.

Hinweis: Es können falsch-positive Ergebnisse auftreten, bei denen das Tool keine schlechten Bytes meldet. Dies erfordert Ihre eigene Intuition, um zu beobachten und zu lösen; wir werden jedoch dies in Aufgabe 4 weiter diskutieren.
##
### AMSITrigger

Wie in der Runtime Detection Evasion behandelt, nutzt AMSI die Laufzeit, was es schwerer macht, Signaturen zu identifizieren und zu lösen. ThreatCheck unterstützt auch bestimmte Dateitypen wie PowerShell nicht, was AMSITrigger jedoch tut.

AMSITrigger wird den AMSI-Motor nutzen und Funktionen gegen ein bereitgestelltes PowerShell-Skript scannen und jede spezifische Code-Sektion melden, von der es glaubt, dass sie gemeldet werden muss.

AMSITrigger bietet eine vor-kompilierte Version auf ihrem GitHub und kann auch auf dem Desktop der angehängten Maschine gefunden werden.

Nachfolgend die Syntax-Nutzung von AMSITrigger:
