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
Bevor wir uns darauf stürzen, Signaturen zu brechen, müssen wir verstehen und identifizieren, wonach wir suchen. Wie im Einführungskurs zur Antivirensoftware erklärt, werden Signaturen von Antiviren-Engines verwendet, um möglicherweise verdächtige und/oder schädliche Programme zu verfolgen und zu identifizieren. In dieser Aufgabe werden wir untersuchen, wie wir manuell bestimmen können, an welcher genauen Stelle im Byte eine Signatur beginnt.

Beim Identifizieren von Signaturen, ob manuell oder automatisiert, müssen wir einen iterativen Prozess anwenden, um festzustellen, an welchem Byte eine Signatur beginnt. Indem wir ein kompiliertes Binärprogramm rekursiv in der Mitte teilen und testen, können wir eine grobe Schätzung des Byte-Bereichs erhalten, der weiter untersucht werden muss.

Wir können die nativen Dienstprogramme head, dd oder split verwenden, um ein kompiliertes Binärprogramm zu teilen. Im folgenden Befehlsfenster werden wir durch die Verwendung von head gehen, um die erste Signatur in einem msfvenom-Binärprogramm zu finden.

Nachdem Sie das Binärprogramm geteilt haben, verschieben Sie es von Ihrer Entwicklungsumgebung auf eine Maschine mit der Antiviren-Engine, die Sie testen möchten. Wenn ein Alarm erscheint, gehen Sie zum unteren Teil des geteilten Binärprogramms und teilen es erneut. Wenn kein Alarm erscheint, gehen Sie zum oberen Teil des geteilten Binärprogramms und teilen es erneut. Setzen Sie dieses Muster fort, bis Sie nicht mehr bestimmen können, wohin Sie gehen sollen; dies tritt normalerweise im Bereich von Kilobytes auf.

Sobald Sie den Punkt erreicht haben, an dem Sie das Binärprogramm nicht mehr genau teilen können, können Sie einen Hex-Editor verwenden, um das Ende des Binärprogramms zu betrachten, wo die Signatur vorhanden ist.
