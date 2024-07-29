# Task 1 - Einführung
Eine Firewall ist eine Software oder Hardware, die den Netzwerkverkehr überwacht und mit einer Reihe von Regeln vergleicht, bevor sie ihn weiterleitet oder blockiert. Eine einfache Analogie ist ein Wächter oder Türsteher am Eingang einer Veranstaltung. Dieser Türsteher kann die Identität von Personen anhand einer Reihe von Regeln überprüfen, bevor er ihnen den Zutritt (oder den Ausgang) erlaubt.

Bevor wir detaillierter auf Firewalls eingehen, ist es hilfreich, sich die Inhalte eines IP-Pakets und eines TCP-Segments in Erinnerung zu rufen. Die folgende Abbildung zeigt die Felder, die wir in einem IP-Header erwarten. Wenn die Abbildung kompliziert aussieht, müssen Sie sich keine Sorgen machen, da wir nur an einigen wenigen Feldern interessiert sind. Verschiedene Arten von Firewalls sind in der Lage, verschiedene Paketfelder zu überprüfen; jedoch sollte die grundlegendste Firewall zumindest die folgenden Felder überprüfen können:

- Protokoll
- Quelladresse
- Zieladresse
![2024-07-29-09d8061f603e6ba8e65a185dc4a2d417.png](Bilder/2024-07-29-09d8061f603e6ba8e65a185dc4a2d417.png)

Je nach Protokollfeld kann die Daten im IP-Datagramm eine von vielen Optionen sein. Drei gängige Protokolle sind:

- TCP
- UDP
- ICMP

Im Falle von TCP oder UDP sollte die Firewall mindestens in der Lage sein, die TCP- und UDP-Header auf folgende Punkte zu überprüfen:

- Quellportnummer
- Zielportnummer

Der TCP-Header wird in der untenstehenden Abbildung gezeigt. Es fällt auf, dass es viele Felder gibt, die die Firewall möglicherweise analysieren kann oder nicht; jedoch sollte selbst die am wenigsten umfassende Firewall dem Firewall-Administrator die Kontrolle über erlaubte oder blockierte Quell- und Zielportnummern ermöglichen.  
![2024-07-29-756fac51ff45cbc4af49336b15a30928.png](Bilder/2024-07-29-756fac51ff45cbc4af49336b15a30928.png)

### Lernziele

In diesem Raum werden folgende Themen behandelt:

- Die verschiedenen Arten von Firewalls, entsprechend unterschiedlichen Klassifikationskriterien
- Verschiedene Techniken zur Umgehung von Firewalls

Dieser Raum setzt grundlegende Kenntnisse voraus in:

- ISO/OSI-Schichten und TCP/IP-Schichten. Wir empfehlen, das Modul [Netzwerkgrundlagen](https://tryhackme.com/module/network-fundamentals) durchzugehen, wenn Sie Ihr Wissen auffrischen möchten.
- Netzwerk- und Port-Scanning. Wir empfehlen, das Nmap-Modul zu absolvieren, um mehr über dieses Thema zu erfahren.
- Reverse- und Bind-Shells. Wir empfehlen den Raum „[Was ist eine Shell?](https://tryhackme.com/room/introtoshells)“ um mehr über Shells zu lernen.

### Aufwärmfragen

Die Designlogik traditioneller Firewalls besteht darin, dass eine Portnummer den Dienst und das Protokoll identifiziert. In traditionellen Firewalls, d.h. Paketfilter-Firewalls, wird alles hauptsächlich auf Basis der folgenden Kriterien erlaubt oder blockiert:

- Protokoll, wie TCP, UDP und ICMP
- IP-Quelladresse
- IP-Zieladresse
- Quell-TCP- oder UDP-Portnummer
- Ziel-TCP- oder UDP-Portnummer

Betrachten wir dieses sehr vereinfachte Beispiel. Wenn Sie HTTP-Verkehr blockieren möchten, müssen Sie den TCP-Verkehr von der Quell-TCP-Portnummer 80 blockieren, d.h. der Standardportnummer für HTTP. Wenn Sie HTTPS-Verkehr zulassen möchten, sollten Sie den Verkehr von der Quell-TCP-Portnummer 443 zulassen, d.h. der Portnummer, die standardmäßig für HTTPS verwendet wird. Offensichtlich ist dies nicht effizient, da es andere Standardportnummern gibt, die wir einbeziehen müssen. Darüber hinaus kann der Dienst auf einer nicht-standardmäßigen Portnummer laufen. Jemand könnte einen HTTP-Server auf Port 53 oder 6667 betreiben.

Besuchen Sie das [Service Name and Transport Protocol Port Number Registry](http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml), um mehr über die Standardportnummern zu erfahren und die folgenden Fragen zu beantworten.

## Fragen:
Wenn Sie Telnet blockieren möchten, welche TCP-Portnummer sollten Sie verweigern?
```

```

Wenn Sie HTTPS zulassen möchten, welche TCP-Portnummer müssen Sie zulassen?
```

```

Was ist eine alternative TCP-Portnummer, die für HTTP verwendet wird? Sie wird als „HTTP Alternate“ beschrieben.
```

```

Sie müssen SNMP über SSH, snmpssh, zulassen. Welchen Port sollten Sie zulassen?
```

```

# Task 2 - Types of Firewalls
Es gibt mehrere Möglichkeiten, Firewalls zu klassifizieren. Eine Möglichkeit, Firewalls zu klassifizieren, besteht darin, ob sie eigenständige Geräte sind.

- **Hardware-Firewall (Appliance-Firewall)**: Wie der Name schon sagt, handelt es sich bei einer Appliance-Firewall um ein separates Hardware-Gerät, durch das der Netzwerkverkehr fließen muss. Beispiele hierfür sind Cisco ASA (Adaptive Security Appliance), WatchGuard Firebox und Netgate pfSense Plus Appliance.
- **Software-Firewall**: Dies ist ein Softwareprogramm, das mit dem Betriebssystem gebündelt ist oder das Sie als zusätzlichen Dienst installieren können. MS Windows verfügt über eine integrierte Firewall, die Windows Defender Firewall, die zusammen mit den anderen Betriebssystemdiensten und Benutzeranwendungen läuft. Ein weiteres Beispiel sind Linux iptables und firewalld.

Wir können Firewalls auch wie folgt klassifizieren:

- **Persönliche Firewall**: Eine persönliche Firewall ist dazu gedacht, ein einzelnes System oder ein kleines Netzwerk zu schützen, beispielsweise eine kleine Anzahl von Geräten und Systemen in einem Heimnetzwerk. Höchstwahrscheinlich verwenden Sie zu Hause eine persönliche Firewall, ohne ihr viel Beachtung zu schenken. Viele drahtlose Zugangspunkte, die für den Heimgebrauch konzipiert sind, haben beispielsweise eine integrierte Firewall. Ein Beispiel dafür ist Bitdefender BOX. Ein weiteres Beispiel ist die Firewall, die Teil vieler drahtloser Zugangspunkte und Heimrouter von Linksys und Dlink ist.
- **Kommerzielle Firewall**: Eine kommerzielle Firewall schützt mittelgroße bis große Netzwerke. Daher würden Sie höhere Zuverlässigkeit und Verarbeitungsgeschwindigkeit erwarten, zusätzlich zur Unterstützung einer höheren Netzwerkbandbreite. Höchstwahrscheinlich durchlaufen Sie eine solche Firewall, wenn Sie von Ihrer Universität oder Ihrem Unternehmen aus auf das Internet zugreifen.

Aus der Perspektive des Red Teams ist die wichtigste Klassifizierung die nach den Fähigkeiten der Firewall-Inspektion. Es ist sinnvoll, über die Fähigkeiten der Firewall in Bezug auf die ISO/OSI-Schichten nachzudenken, die in der folgenden Abbildung dargestellt sind. Bevor wir Firewalls basierend auf ihren Fähigkeiten klassifizieren, ist es wichtig zu wissen, dass Firewalls sich auf die Schichten 3 und 4 konzentrieren und in geringerem Maße auf Schicht 2. Next-Generation-Firewalls sind auch darauf ausgelegt, die Schichten 5, 6 und 7 abzudecken. Je mehr Schichten eine Firewall inspizieren kann, desto ausgefeilter wird sie und desto mehr Rechenleistung benötigt sie.  
![2024-07-29-ad200ff1a857631d88940d3e3637736b.png](Bilder/2024-07-29-ad200ff1a857631d88940d3e3637736b.png)

Basierend auf den Fähigkeiten der Firewall können wir die folgenden Firewall-Typen auflisten:

- **Packet-Filtering Firewall**: Packet-Filtering ist die grundlegendste Art von Firewall. Diese Art von Firewall inspiziert das Protokoll, die Quell- und Ziel-IP-Adressen sowie die Quell- und Zielports im Fall von TCP- und UDP-Datagrammen. Es handelt sich um eine stateless Inspection Firewall.
- **Circuit-Level Gateway**: Zusätzlich zu den von Packet-Filtering-Firewalls angebotenen Funktionen können Circuit-Level Gateways zusätzliche Fähigkeiten bieten, wie z.B. die Überprüfung des TCP-Drei-Wege-Handshake gegen die Firewall-Regeln.
- **Stateful Inspection Firewall**: Im Vergleich zu den vorherigen Typen bietet diese Art von Firewall eine zusätzliche Schutzebene, da sie die etablierten TCP-Sitzungen verfolgt. Dadurch kann sie alle TCP-Pakete außerhalb einer etablierten TCP-Sitzung erkennen und blockieren.
- **Proxy Firewall**: Eine Proxy-Firewall wird auch als Application Firewall (AF) und Web Application Firewall (WAF) bezeichnet. Sie ist so konzipiert, dass sie sich als der ursprüngliche Client tarnt und Anfragen in dessen Namen stellt. Dieser Prozess ermöglicht es der Proxy-Firewall, den Inhalt der Pakete anstelle der Paket-Header zu inspizieren. Allgemein gesprochen wird dies für Webanwendungen verwendet und funktioniert nicht für alle Protokolle.
- **Next-Generation Firewall (NGFW)**: NGFW bietet den höchsten Firewall-Schutz. Sie kann praktisch alle Netzwerkschichten überwachen, von OSI-Schicht 2 bis OSI-Schicht 7. Sie hat Anwendungsbewusstsein und -kontrolle. Beispiele sind die Juniper SRX-Serie und Cisco Firepower.
- **Cloud Firewall oder Firewall as a Service (FWaaS)**: FWaaS ersetzt eine Hardware-Firewall in einer Cloud-Umgebung. Ihre Funktionen können je nach Dienstanbieter mit denen einer NGFW vergleichbar sein; sie profitiert jedoch von der Skalierbarkeit der Cloud-Architektur. Ein Beispiel ist Cloudflare Magic Firewall, eine netzwerkbasierte Firewall. Ein weiteres Beispiel ist Juniper vSRX; es hat die gleichen Funktionen wie eine NGFW, wird jedoch in der Cloud bereitgestellt. Ebenfalls erwähnenswert sind AWS WAF für den Schutz von Webanwendungen und AWS Shield für den DDoS-Schutz.

## Fragen:
Was ist die grundlegendste Art von Firewall?
```

```

Was ist die fortschrittlichste Art von Firewall, die man in Unternehmensräumen haben kann?
```

```

# Task 3 - Evasion via Controlling the Source MAC/IP/Port
Wenn man einen Host hinter einer Firewall scannt, erkennt und blockiert die Firewall normalerweise Port-Scans. In einer solchen Situation muss man seinen Netzwerk- und Port-Scan anpassen, um die Firewall zu umgehen. Ein Netzwerk-Scanner wie Nmap bietet einige Funktionen, die dabei helfen können. In diesem Raum gruppieren wir Nmap-Techniken in drei Gruppen:

1. Umgehung durch Kontrolle der Quell-MAC/IP/Port
2. Umgehung durch Fragmentierung, MTU und Datenlänge
3. Umgehung durch Modifizieren der Header-Felder

Nmap ermöglicht es, die Quelle zu verbergen oder zu fälschen, indem man Folgendes verwendet:

1. Decoys
2. Proxy
3. Gefälschte MAC-Adresse
4. Gefälschte Quell-IP-Adresse
5. Feste Quellport-Nummer

Bevor wir auf jede Methode eingehen, wollen wir zeigen, wie ein Nmap-Stealth-Scan (SYN-Scan) aussieht. Wir scannen ein MS-Windows-Ziel (mit standardmäßig eingebauter Firewall), daher haben wir `-Pn` hinzugefügt, um den Scan auch dann fortzusetzen, wenn keine Ping-Antwort empfangen wird. `-Pn` wird verwendet, um die Host-Erkennung zu überspringen und zu testen, ob der Host aktiv ist. Außerdem haben wir zur Beschleunigung des Scans die 100 häufigsten Ports mit der Option `-F` begrenzt. Der Scan wurde mit folgendem Befehl durchgeführt: `nmap -sS -Pn -F MACHINE_IP`.

Der folgende Screenshot zeigt die von Wireshark erfassten Nmap-Probe-Pakete. Wireshark lief auf demselben System, auf dem Nmap ausgeführt wurde.  
![2024-07-29-169fd944d79366e156fcb6c30ff8018e.png](Bilder/2024-07-29-169fd944d79366e156fcb6c30ff8018e.png)

Wir können alle Details, die in jedem Paket eingebettet sind, untersuchen; für diese Übung möchten wir jedoch Folgendes festhalten:

- Unsere IP-Adresse 10.14.17.226 hat etwa 200 Pakete erzeugt und gesendet. Die -F-Option begrenzt den Scan auf die 100 häufigsten Ports; außerdem wird jedem Port ein zweites SYN-Paket gesendet, wenn es nicht auf das erste antwortet.
- Die Quellportnummer wird zufällig gewählt. Im Screenshot sieht man, dass sie 37710 ist.
- Die Gesamtlänge des IP-Pakets beträgt 44 Byte. Es gibt 20 Byte für den IP-Header, was 24 Byte für den TCP-Header übrig lässt. Es werden keine Daten über TCP gesendet.
- Die Lebensdauer (TTL) beträgt 42.
- Es werden keine Fehler in der Prüfsumme eingeführt.

In den folgenden Abschnitten und Aufgaben werden wir sehen, wie Nmap verschiedene Optionen bietet, um die Firewall und andere Netzwerksicherheitslösungen zu umgehen.

## Fragen:
Wie groß ist das IP-Paket bei einem standardmäßigen Nmap-Stealth-Scan (SYN-Scan)?
```

```

Wie viele Bytes enthält das TCP-Segment in seinem Datenfeld bei einem standardmäßigen Nmap-Stealth-Scan (SYN-Scan)?
```

```

Ungefähr wie viele Pakete erwarten Sie, dass Nmap sendet, wenn der Befehl `nmap -sS -F MACHINE_IP` ausgeführt wird? Runden Sie auf die nächste 100 auf, wie z.B. 100, 200, 300 usw.
```

```

### Decoy(s)

Verstecken Sie Ihren Scan mit Decoys. Durch die Verwendung von Decoys mischt sich Ihre IP-Adresse mit anderen „Decoy“-IP-Adressen. Folglich wird es für die Firewall und das Zielsystem schwierig, herauszufinden, woher der Port-Scan kommt. Darüber hinaus kann dies das Blue-Team erschöpfen, da es jede Quell-IP-Adresse untersuchen muss.

Mit der Option `-D` können Sie Decoy-Quell-IP-Adressen hinzufügen, um das Ziel zu verwirren. Betrachten Sie den folgenden Befehl: `nmap -sS -Pn -D 10.10.10.1,10.10.10.2,ME -F MACHINE_IP`. Die Wireshark-Erfassung ist in der folgenden Abbildung dargestellt.  
![2024-07-29-0123f32d7cc90fca50a3d565824955b1.png](Bilder/2024-07-29-0123f32d7cc90fca50a3d565824955b1.png)

Das Ziel `MACHINE_IP` wird auch Scans von `10.10.10.1` und `10.10.10.2` sehen, obwohl nur eine Quell-IP-Adresse, `ME`, den Scan durchführt. Beachten Sie, dass Nmap Ihre tatsächliche IP-Adresse (`ME`) an einer zufälligen Position einfügt, wenn Sie den ME-Eintrag im Scanbefehl weglassen.

Sie können Nmap auch so einstellen, dass es zufällige Quell-IP-Adressen verwendet, anstatt sie explizit anzugeben. Durch das Ausführen von `nmap -sS -Pn -D RND,RND,ME -F MACHINE_IP` wählt Nmap zwei zufällige Quell-IP-Adressen als Decoys aus. Jedes Mal, wenn Sie diesen Befehl ausführen, verwendet Nmap neue zufällige IP-Adressen. Im folgenden Screenshot sehen wir, wie Nmap zwei zufällige IP-Adressen zusätzlich zu unserer eigenen (`10.14.17.226`) ausgewählt hat.  
![2024-07-29-2fb8362a71b22cdbe9e60fd638c1813c.png](Bilder/2024-07-29-2fb8362a71b22cdbe9e60fd638c1813c.png)

Ungefähr wie viele Pakete erwarten Sie, dass Nmap sendet, wenn der Befehl `nmap -sS -Pn -D RND,10.10.55.33,ME,RND -F MACHINE_IP` ausgeführt wird? Ungefähr auf das nächste Hundert gerundet, wie 100, 200, 300 usw.
```

```

### Proxy

Verwenden Sie einen HTTP/SOCKS4-Proxy. Die Weiterleitung des Portscans über einen Proxy hilft dabei, Ihre IP-Adresse vor dem Zielhost zu verbergen. Diese Technik ermöglicht es Ihnen, Ihre IP-Adresse verborgen zu halten, während das Ziel die IP-Adresse des Proxy-Servers protokolliert. Sie können diesen Weg mit der Nmap-Option `--proxies PROXY_URL` gehen. Zum Beispiel sendet `nmap -sS -Pn --proxies PROXY_URL -F MACHINE_IP` alle seine Pakete über den von Ihnen angegebenen Proxy-Server. Beachten Sie, dass Sie Proxys mit einer durch Kommas getrennten Liste verketten können.

Was erwarten Sie, dass das Ziel als Quelle des Scans sieht, wenn Sie den Befehl `nmap -sS -Pn --proxies 10.10.13.37 MACHINE_IP` ausführen?
```

```

### Gefälschte MAC-Adresse

Fälschen Sie die Quell-MAC-Adresse. Nmap ermöglicht es Ihnen, Ihre MAC-Adresse mit der Option --spoof-mac MAC_ADDRESS zu fälschen. Diese Technik ist knifflig; das Fälschen der MAC-Adresse funktioniert nur, wenn Ihr System im selben Netzwerksegment wie der Zielhost ist. Das Zielsystem wird auf eine gefälschte MAC-Adresse antworten. Wenn Sie sich nicht im selben Netzwerksegment befinden und das gleiche Ethernet teilen, können Sie die Antworten nicht erfassen und lesen. Es ermöglicht Ihnen, Vertrauensbeziehungen basierend auf MAC-Adressen auszunutzen. Darüber hinaus können Sie diese Technik verwenden, um Ihre Scanaktivitäten im Netzwerk zu verbergen. Zum Beispiel können Sie Ihre Scans so erscheinen lassen, als kämen sie von einem Netzwerkdrucker.

Welche Firma hat den folgenden Organizationally Unique Identifier (OUI), d.h. die ersten 24 Bits einer MAC-Adresse, 00:02:DC, registriert?
```

```

### Gefälschte IP-Adresse

Fälschen Sie die Quell-IP-Adresse. Nmap ermöglicht es Ihnen, Ihre IP-Adresse mit `-S IP_ADDRESS` zu fälschen. Das Fälschen der IP-Adresse ist nützlich, wenn Ihr System im selben Subnetz wie der Zielhost ist; andernfalls können Sie die zurückgesendeten Antworten nicht lesen. Der Grund ist, dass der Zielhost auf die gefälschte IP-Adresse antwortet, und wenn Sie die Antworten nicht erfassen können, profitieren Sie nicht von dieser Technik. Eine weitere Verwendung für das Fälschen Ihrer IP-Adresse besteht darin, wenn Sie das System kontrollieren, das diese bestimmte IP-Adresse hat. Folglich, wenn Sie feststellen, dass das Ziel die gefälschte IP-Adresse zu blockieren beginnt, können Sie zu einer anderen gefälschten IP-Adresse wechseln, die zu einem von Ihnen kontrollierten System gehört. Diese Scan-Technik kann Ihnen helfen, eine verdeckte Existenz aufrechtzuerhalten; darüber hinaus können Sie diese Technik nutzen, um Vertrauensbeziehungen im Netzwerk basierend auf IP-Adressen auszunutzen.

Um den Gegner in die Irre zu führen, haben Sie beschlossen, Ihre Portscans so erscheinen zu lassen, als kämen sie von einem lokalen Zugangspunkt, der die IP-Adresse `10.10.0.254` hat. Welche Option muss Ihrem Nmap-Befehl hinzugefügt werden, um Ihre Adresse entsprechend zu fälschen?
```

```

### Fester Quellportnummer

Verwenden Sie eine spezifische Quellportnummer. Das Scannen von einer bestimmten Quellportnummer kann hilfreich sein, wenn Sie feststellen, dass Firewalls eingehende Pakete von bestimmten Quellportnummern wie Port 53 oder 80 zulassen. Ohne den Paketinhalt zu inspizieren, sehen Pakete von Quell-TCP-Port 80 oder 443 wie Pakete von einem Webserver aus, während Pakete von UDP-Port 53 wie Antworten auf DNS-Abfragen aussehen. Sie können Ihre Portnummer mit den Optionen `-g` oder `--source-port` festlegen.

Der folgende Wireshark-Screenshot zeigt einen Nmap-Scan mit der festen Quell-TCP-Portnummer 8080. Wir haben den folgenden Nmap-Befehl verwendet: `nmap -sS -Pn -g 8080 -F MACHINE_IP`. Sie können im Screenshot sehen, dass alle TCP-Verbindungen von derselben TCP-Portnummer gesendet werden.  
![2024-07-29-a0307f9e74e7f110b546dc7b423a288e.png](Bilder/2024-07-29-a0307f9e74e7f110b546dc7b423a288e.png)

Natürlich, hier ist die Übersetzung:

---

Du entscheidest dich, Nmap zu verwenden, um nach offenen UDP-Ports zu scannen. Du bemerkst, dass die Verwendung von `nmap -sU -F MACHINE_IP`, um die offenen häufigen UDP-Ports zu entdecken, keine bedeutungsvollen Ergebnisse liefert. Was musst du zu deinem Nmap-Befehl hinzufügen, um die Quellportnummer auf 53 zu setzen?

Dies ist eine kurze Zusammenfassung der in dieser Aufgabe besprochenen Nmap-Optionen:

Evasion Approach  |  Nmap Argument  
--- | ---  
Verstecke einen Scan mit Täuschungs-IP-Adressen  |  `-D DECOY1_IP1,DECOY_IP2,ME`  
Verstecke einen Scan mit zufälligen Täuschungs-IP-Adressen  |  `-D RND,RND,ME`  
Verwende einen HTTP/SOCKS4-Proxy zum Weiterleiten von Verbindungen  |  `--proxies PROXY_URL`  
Spoofing der Quell-MAC-Adresse  |  `--spoof-mac MAC_ADDRESS`  
Spoofing der Quell-IP-Adresse  |  `-S IP_ADDRESS`  
Verwende eine spezifische Quellportnummer  |  `-g PORT_NUM` oder `--source-port PORT_NUM`  

---
