# Task 1 - Einführung
"Living Off the Land" ist ein Trendbegriff in der Red-Team-Community. Der Name stammt aus dem realen Leben, wo man von dem lebt, was das Land bietet. Ebenso nutzen Angreifer und Malware-Ersteller die eingebauten Tools und Dienstprogramme eines Zielcomputers aus. Der Begriff "Living Off the Land" wurde erstmals auf der DerbyCon3 im Jahr 2013 eingeführt und hat seitdem in der Red-Team-Community an Bedeutung gewonnen, indem er zu einer häufig verwendeten und beliebten Technik wurde.

Diese eingebauten Tools führen verschiedene regelmäßige Aktivitäten innerhalb des Zielsystems oder der Netzwerkkapazitäten aus; sie werden jedoch zunehmend missbraucht, beispielsweise durch die Verwendung des Tools CertUtil zum Herunterladen bösartiger Dateien auf den Zielrechner.

Die Hauptidee besteht darin, Microsoft-signierte Programme, Skripte und Bibliotheken zu verwenden, um sich in die Umgebung einzufügen und Abwehrkontrollen zu umgehen. Red Teamers möchten nicht erkannt werden, wenn sie ihre Aktivitäten auf dem Ziel ausführen, daher ist die Nutzung dieser Tools sicherer, um ihre Tarnung aufrechtzuerhalten.

Folgende sind einige Kategorien, die "Living Off the Land" umfasst:

- Aufklärung
- Dateioperationen
- Ausführung beliebigen Codes
- Laterale Bewegung
- Umgehung von Sicherheitsprodukten

Lernziele:

- Erfahren Sie mehr über den Begriff "Living Off the Land" in Red-Team-Engagements.
- Lernen Sie das LOLBAS-Projekt kennen und wie Sie es verwenden.
- Verstehen und anwenden der Techniken, die in Red-Teaming-Engagements verwendet werden.

Raumvoraussetzungen:

- Grundkenntnisse in allgemeinen Hacking-Techniken.
- Abschluss des Lernpfads für Junior Penetration Tester.
- TryHackMe Modul für den Red-Team-Initialzugriff.

Wir haben eine Windows 10 Pro-Maschine bereitgestellt, um diesen Raum abzuschließen. Sie können die In-Browser-Funktion verwenden oder, wenn Sie möchten, über RDP eine Verbindung herstellen. Stellen Sie sicher, dass Sie dabei die AttackBox bereitstellen oder sich über das VPN verbinden.

Verwenden Sie die folgenden Anmeldedaten:

- Maschinen-IP: MACHINE_IP
- Benutzername: thm
- Passwort: TryHackM3

---

**Aufgabe 2 - Windows Sysinternals**

Was ist Windows Sysinternals?

Windows Sysinternals ist eine Sammlung von Tools und erweiterten Systemdienstprogrammen, die entwickelt wurden, um IT-Profis bei der Verwaltung, Fehlerbehebung und Diagnose des Windows-Betriebssystems in verschiedenen fortgeschrittenen Themen zu unterstützen.

Die Sysinternals Suite ist in verschiedene Kategorien unterteilt, darunter:

- Festplattenverwaltung
- Prozessverwaltung
- Netzwerktools
- Systeminformationen
- Sicherheitstools

Um die Windows Sysinternals-Tools zu verwenden, müssen wir die Microsoft-Lizenzvereinbarung dieser Tools akzeptieren. Dies können wir tun, indem wir das Argument -accepteula an der Befehlszeile übergeben oder es während der Ausführung der Tools über die GUI tun.

Einige beliebte Windows Sysinternals-Tools sind:

- ProcMon
- Process Explorer
- Autoruns
- TCPView
- PsExec

Weitere Informationen zur Sysinternals Suite finden Sie auf der Webseite der Tools auf Microsoft Docs hier.

Sysinternals Live

Eine großartige Funktion von Windows Sysinternals ist, dass keine Installation erforderlich ist. Microsoft bietet einen Windows Sysinternals-Dienst namens Sysinternals Live an, mit verschiedenen Möglichkeiten zur Verwendung und Ausführung der Tools. Wir können darauf über Folgendes zugreifen:

- Webbrowser (Link)
- Windows-Freigabe
- Befehlszeile

Um diese Tools zu verwenden, laden Sie sie herunter oder geben Sie den Pfad \\live.sysinternals.com\tools in den Windows Explorer ein.

Beachten Sie, dass da die angehängte VM keinen Internetzugang hat, wir die Sysinternals-Tools im Verzeichnis C:\Tools\ vorab heruntergeladen haben.

Wenn Sie mehr über Windows Sysinternals erfahren möchten, empfehlen wir Ihnen, sich mit folgenden zusätzlichen Ressourcen vertraut zu machen:

- TryHackMe Raum: Sysinternals
- Microsoft Sysinternals Ressourcenwebsite

Nutzung und Vorteile für das Red Team

Obwohl eingebaute und Sysinternals-Tools nützlich für Systemadministratoren sind, werden diese auch von Hackern, Malware und Penetrationstestern aufgrund des innewohnenden Vertrauens, das sie innerhalb des Betriebssystems genießen, verwendet. Dieses Vertrauen ist für Red Teamers vorteilhaft, die nicht von Sicherheitskontrollen auf dem Zielsystem erkannt oder erwischt werden möchten. Daher wurden diese Tools genutzt, um Erkennung und andere Blau-Team-Kontrollen zu umgehen.

Denken Sie daran, dass aufgrund der zunehmenden Nutzung durch Angreifer und Malware-Ersteller diese Tools heute bekannt sind und defensive Maßnahmen gegen die meisten von ihnen implementiert wurden.
