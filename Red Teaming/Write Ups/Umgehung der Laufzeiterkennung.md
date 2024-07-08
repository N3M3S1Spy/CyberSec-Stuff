Mit der Veröffentlichung von PowerShell <3 durch das Blue Team hat Microsoft AMSI (Anti-Malware Scan Interface) eingeführt, eine Laufzeitüberwachungslösung, die entwickelt wurde, um Bedrohungen zu erkennen und zu überwachen.

Lernziele

- Verstehen des Zwecks von Laufzeit-Erkennungen und wie sie implementiert werden.
- Erlernen und Anwenden von Techniken zur Umgehung von AMSI.
- Verständnis für gängige Abwehrmaßnahmen und potenzielle Alternativen zu Techniken.

Laufzeit-Erkennungsmaßnahmen können viele Kopfschmerzen und Hindernisse verursachen, wenn es darum geht, bösartigen Code auszuführen. Glücklicherweise gibt es für uns Angreifer mehrere Techniken und Methoden, die wir nutzen können, um gängige Laufzeit-Erkennungslösungen zu umgehen.

In diesem Raum wird Forschung von mehreren Autoren und Forschern verwendet; alle Credits gehen an die jeweiligen Eigentümer.

Bevor Sie diesen Raum beginnen, machen Sie sich mit der Betriebssystemarchitektur im Allgemeinen vertraut. Grundlegende Programmierkenntnisse in C# und PowerShell sind ebenfalls empfohlen, aber nicht zwingend erforderlich.

Wir haben eine grundlegende Windows-Maschine bereitgestellt, die die für diesen Raum benötigten Dateien enthält. Sie können auf die Maschine im Browser oder über RDP mit den folgenden Anmeldeinformationen zugreifen:

Maschinen-IP: `MACHINE_IP`             Benutzername: `THM-Attacker`             Passwort: `Tryhackme!`

# Task 2 - Laufzeiterkennung
Bei der Ausführung von Code oder Anwendungen wird fast immer eine Laufzeitumgebung durchlaufen, unabhängig vom Interpreter. Dies ist besonders häufig beim Einsatz von Windows-API-Aufrufen und der Interaktion mit .NET zu beobachten. Die CLR (Common Language Runtime) und DLR (Dynamic Language Runtime) sind die Laufzeiten für .NET und die gängigsten, denen man bei der Arbeit mit Windows-Systemen begegnet. In dieser Aufgabe werden wir nicht auf die Details der Laufzeiten eingehen; stattdessen diskutieren wir, wie sie überwacht werden und wie bösartiger Code erkannt wird.

Eine Laufzeit-Erkennungsmaßnahme scannt den Code vor der Ausführung in der Laufzeit und entscheidet, ob er bösartig ist oder nicht. Abhängig von der Erkennungsmaßnahme und der zugrunde liegenden Technologie kann diese Erkennung auf String-Signaturen, Heuristiken oder Verhaltensweisen basieren. Wenn Code als verdächtig eingestuft wird, wird ihm ein Wert zugewiesen, und wenn dieser innerhalb eines festgelegten Bereichs liegt, wird die Ausführung gestoppt und möglicherweise die Datei oder der Code in Quarantäne versetzt oder gelöscht.

Laufzeit-Erkennungsmaßnahmen unterscheiden sich von einem herkömmlichen Antivirenprogramm, da sie direkt aus dem Speicher und der Laufzeit heraus scannen. Gleichzeitig können Antivirenprodukte ebenfalls solche Laufzeit-Erkennungen nutzen, um mehr Einblick in die Aufrufe und Hooks zu erhalten, die vom Code ausgehen. In einigen Fällen verwenden Antivirenprodukte einen Laufzeit-Erkennungsstrom als Teil ihrer Heuristiken.

In diesem Raum konzentrieren wir uns hauptsächlich auf AMSI (Anti-Malware Scan Interface). AMSI ist eine nativ mit Windows ausgelieferte Laufzeit-Erkennungsmaßnahme und stellt eine Schnittstelle für andere Produkte und Lösungen dar.

## Fragen:
