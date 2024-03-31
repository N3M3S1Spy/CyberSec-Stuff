# Einführung
TryHackMe Raum [Cyber Kill Chain](https://tryhackme.com/room/cyberkillchainzmt)  

## Task 1 - Einführung: Zusammenfassung
### Was ist eine Kill Chain?:  
Eine "Kill Chain" ist ein Militärisches Konzept, das sich auf die Struktur eines Angriffes bezieht nur Digital, die vorgänge sind dabei die selben wie im echten leben. Es beginnt mit Reconnaissance(Aufklärung), Weaponization(Bewaffnung), Delivery(Auslieferung), Exploitaion(Ausnutzung), Installation(Installation), Command and Control(Befehl und Kontrolle) und Action on Objectives(Aktion auf Ziele).


### Was sind die einzelnen Punkte einer Cyber Kill Chain?:
1. **Reconnaissance (Aufklärung)**: Der Angreifer sammelt Informationen über das Ziel, wie z.B. Netzwerkstruktur, Standort, Systeme und Schwachstellen.
2. **Weaponization (Bewaffnung)**: Der Angreifer erstellt oder passt schädlichen Code so an, das es für das Ziel conform ist.
3. **Delivery (Auslieferung)**: Das Ziel empfängt die schädliche Payload, meist über E-Mail-Anhänge(Social-Engeniring), infizierte Websiten oder USB-Sticks.
4. **Exploitation (Ausnutzung)**: Der Angreifer nutzt Schwachstellen im System, um Zugriff zu erhalten oder die Ausführung des schädlichen Codes zu ermöglichen.
5. **Installation (Installation)**: In diesem Punk wird auf dem Ziel-System Schädliche Software ausgeführt, oft um dauerhaften Zugriff zu ermöglichen.
6. **Command and Control (Befehl und Kontrolle)**: Bei diesem Punkt wird eine Verbindung zwischen dem Angreifer und dem Ziel hergestellt, um Befehle zu senden und Daten zu emfangen.
7. **Actions on Objectives (Aktionen auf Ziele)**: Hier wird der das Ziel des Angriffs erreicht, wie z.B. Datenextraktion, Manipulation oder Zerstörung.

### Wer hat die Cyber Kill Chain entwickelt?:
Die Erfindung der Modernen Cyber Kill Chain im bereich Cyber Sicherheit verdanken wir Lockheed Martin, ein globales Sicherheits- und Luft- und Raumfahrtunternehme.

## Task 2 - Reconnaissance (Aufklärung): Zusammenfassung
### Was ist die Definition von Aufklärung?:
Bei der Aufklärunf geht es darum informationen über das Ziel zu sammeln, wie System Informationen oder auch Informationen über den Besitzer des Systems, um dadurch den volgenden Angriff besser durch zu führen.

### Welche Techniken werden zur aufklärung genutzt?:
**OSINT** (Open-Source Intelligence) ist eine der belibtesteb und verbreitesten Techniken, dies bentzen potentielle Angreiffer am Häufigsten um informationen über das Ziel herrauszu finden.   

### Was genau fällt und OSINT?:
1. **Passive Reconnaissance (Passive Aufklärung)**: Dies beinhaltet Informationen zusammeln die öffentlich zugänglich sind, wie Blog, Kommentare, Accounts und Websits. Kurz gesagt alles was keine direkte Interaktion mit dem Ziel vorrausetzt fällt unter **Passive Reconnaissance**.
2. **Active Reconnaissance (Aktive Aufklärung)**: Active Aufklärung beinhaltet Techniken wie: Port-Scan, Ping-Scan, DNS-Scan, OS-Scan und Netzwerk-Scan. Kurz gesagt, die **Active Reconnaissance** ist das gegenteil zur Passive Reconnaissance, die Aufklärung wird dann Aktiv wenn es eine direkte interaktion mit dem Ziel benötigt.
3. **Social Engineering (Soziale Manipulation)**: Social Engineering beschreibt eine Technik die eine direkte Interaktion mit der Firma oder der Ziel Person vorraussetzt, wie z.B. Telefonate um Informationen von Mitarbeitern oder Privat Personen zu erlangen aber auch gefälschte E-Mails sind häufig im einsatz (Phishing).
4. **Partner- und Lieferantenanalysen**: **Partner- und Lieferantenanalyse** ist auch ein wichtiger Punkt da das eigentliche ziel System nicht immer angreiffbar ist, aber durch ein nicht gut genug gesichertes Partner- oder Lieferanten unternehmen oder Freunde einer Privat-Person erhöht sich massiv die Chance für eine bessere aufklärung.
5. **Technische Analysen**: **Technische Analyse** umfasst die aufklärung welche Software oder Hardware auf dem Zielsystem vorhanden sind. Solche Informatinonen können meist in Technick Foren gesammelt werden.
6. **E-Mail Harvesting**: **E-Mail Harvesting** umfasst den Prozess des sammelns von E-Mail addressen der Orginisation oder der Privat-Person. Diese können dann für Phishing-Angriffe verwendet werden.

## Task 3 - Weaponization (Bewaffnung): Zusammenfassung
### Was passiert in der Bewaffnungs Phase?:
In der Bewaffnungs Phase ist es von entscheidener bedeutung die richtigen tools, exploits und Techniken aus zu suchen um auf dem System Fuß zu fassen.

### Was währe der Ablauf der Technik wahl?:
1. Als erstes gibt es da die Infektions Techniken       darunter zählen: Microsoft Office-Dokumente mit schädlichen Makros - VBA-Scripte, USB-Laufwerk implantierte Viren und Keystroke-Injection-Tools: meist als USB-Sticks getarnt wie ein Rubber ducky.
2. Als nächstes würde sich ein Angreifer um  Command-and-Control-Techniken kümmern, um Befehler auf dem Ziel System aus zu führen und weiter Payloads auf dem Ziel system zu bekommen. Informationen hierzu gibt es hier: [MITRE ATT&CK ](https://attack.mitre.org/tactics/TA0011/).
3. Als letztes würde ein Angreifer sich um eine Backdoor instalation kümmern.

## Task 4 - Delivery (Lieferung): Zusammenfassung
### Was passiert in der Liferungs Phase?:
In der Lieferungs Phase entscheidet sich der Angreifer wie er die Malware auf das Ziel System bekommt.

### Welche Techniken stehen dem Angreifer zu verfügung?:
1. Phishing E-Mails
2. Bad USB-Sticks
3. Watering-Hole-Attack

## Task 5 - Exploitation (Angriff): Zusammenfassung
### Was passiert in der Angriff
In der Angriffs Phase bekommt der Angreifer zugriff auf das system

## Task 6 - Installation (Installation)
### Was passiert in der Installations Phase?:
In der Installations Phase kümmert sich der Angreifer um das installieren eines permanten zugangs, auch genannt [Backdoor](https://www.trendmicro.com/vinfo/us/security/definition/backdoor). Dadurch bekommt der Angreifer permanent zugriff auf das System.

## Task 7 - Command & Control (Kommand und Kontrolle): Zusammenfassung
### Was passiert in der Command & Control Phase?:
In der 7 Phase der Cyber Kill chain führt der Angreifer Befehle auf dem Ziel System aus und hat kontroller über das System.

## Task 8 - Action of Target (Exfiltration) / Aktionen auf Ziele (Exfiltration): Zusammenfassung
### Was passiet in der Exfiltratons Phase?:
Die Exfiltrations Phase umfasst alles von sammlung bis hinzu änderung an daten, hier ein Liste dazu:
1. Sammeln von Nutzer/Anmelde Daten.
2. Rechte erweitern.
3. Interne Softwareschwachstellen ausnutzen.
4. Durch das Netzwerk bewegen.
5. Sammeln und Filtern von Daten.
6. Löschen der Backups und Shadow Kopien von Microsoft Windows.
7. Daten überschreiben oder beschädigen.
