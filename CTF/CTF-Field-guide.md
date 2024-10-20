# **CTF Guide - Ein umfassender Leitfaden für alle Kategorien**

## **Inhaltsverzeichnis**
1. [Einführung](#einführung)
2. [Installation der wichtigsten Tools](#installation-der-wichtigsten-tools)
3. [CTF-Kategorien und Lösungen](#ctf-kategorien-und-lösungen)
   - 3.1 [Reconnaissance (Recon)](#reconnaissance-recon)
   - 3.2 [Web-Exploitation](#web-exploitation)
   - 3.3 [Forensik](#forensik)
   - 3.4 [Kryptografie](#kryptografie)
   - 3.5 [Reverse Engineering](#reverse-engineering)
   - 3.6 [Pwn (Binary Exploitation)](#pwn-binary-exploitation)
   - 3.7 [Steganographie](#steganographie)
   - 3.8 [Miscellaneous (Sonstiges)](#miscellaneous-sonstiges)
4. [Typische Vorgehensweise für CTFs](#typische-vorgehensweise-für-ctfs)
5. [CTF-Plattformen und Ressourcen](#ctf-plattformen-und-ressourcen)
6. [Zusätzliche Tipps und Tricks](#zusätzliche-tipps-und-tricks)

---

## **Einführung**

Capture-The-Flag (CTF) Wettbewerbe sind ein beliebtes Mittel, um technische Fähigkeiten im Bereich Cybersicherheit zu testen und zu verbessern. CTFs decken eine Vielzahl von Bereichen ab, darunter Web-Exploitation, Forensik, Kryptografie, Reverse Engineering und mehr. Dieser Leitfaden bietet eine umfassende Anleitung zur Vorbereitung und Lösung von CTF-Aufgaben, gibt dir spezifische Tools an die Hand und erklärt detailliert das typische Vorgehen.

---

## **Installation der wichtigsten Tools**

Um sicherzustellen, dass du gut für die meisten CTF-Aufgaben ausgestattet bist, installiere die wichtigsten Tools mit folgendem One-Liner:

```bash
sudo apt update && sudo apt install -y steghide zsteg exiftool binwalk foremost gimp tesseract-ocr imagemagick openjdk-17-jre nmap gobuster sqlmap nikto whatweb john hashcat radare2 gdb pwntools python3-pip && pip3 install pwntools && wget https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve.jar -O stegsolve.jar
```

Dies installiert Tools für:

- **Reconnaissance (Recon)**
- **Web-Exploitation**
- **Forensik**
- **Kryptografie**
- **Reverse Engineering**
- **Pwn (Binary Exploitation)**
- **Steganographie**

---

## **CTF-Kategorien und Lösungen**

### 3.1 **Reconnaissance (Recon)**

Recon ist oft der erste Schritt in einer CTF-Challenge. Hier sammelst du Informationen über Ziele, Server, Domains oder Netzwerke, um Schwachstellen zu finden.

#### **Tools**:
- **Nmap**: Port-Scanner und Service-Detektor
  ```bash
  nmap -sV -p- target.com
  ```

- **WhatWeb**: Analyse des Webserver-Stack (Technologien)
  ```bash
  whatweb target.com
  ```

- **Gobuster**: Verzeichnis-Bruteforcing
  ```bash
  gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
  ```

#### **Vorgehen**:
1. **Port-Scan**: Mit `nmap` alle offenen Ports und Dienste des Ziels identifizieren.
2. **Technologie-Erkennung**: Mit `whatweb` oder ähnlichen Tools die genutzten Technologien der Webseite herausfinden.
3. **Verzeichnisse aufspüren**: Verwende `gobuster` oder `dirb`, um versteckte Verzeichnisse oder Dateien zu finden.

### 3.2 **Web-Exploitation**

Web-Exploitation-Challenges erfordern, dass du Schwachstellen in Webanwendungen findest, die sich oft in der unsachgemäßen Handhabung von Benutzereingaben oder in Fehlkonfigurationen verstecken.

#### **Tools**:
- **Burp Suite**: Web-Proxy-Tool zum Abfangen und Modifizieren von HTTP-Requests.
- **SQLMap**: Automatisiertes SQL-Injection-Tool.
- **Nikto**: Webserver-Schwachstellen-Scanner.
- **XSS-Injector**: Zum Testen von Cross-Site Scripting (XSS).

#### **Häufige Schwachstellen**:
- **SQL-Injection**: Wenn Benutzereingaben direkt in SQL-Abfragen verwendet werden.
  ```bash
  sqlmap -u "http://target.com/page?id=1" --dbs
  ```

- **Cross-Site Scripting (XSS)**: Wenn Benutzer Daten ohne Filterung auf der Seite zurückgegeben werden.
  Beispiel:
  ```javascript
  <script>alert('XSS')</script>
  ```

- **File Inclusion (LFI/RFI)**: Ermöglicht das Einfügen von Dateien in Webanwendungen.
  Beispiel:
  ```bash
  http://target.com/page.php?file=../../../../etc/passwd
  ```

#### **Vorgehen**:
1. **SQL-Injection testen**: Mit `sqlmap` Schwachstellen erkennen und ausnutzen.
2. **XSS-Filter überprüfen**: Teste mit einfachen Payloads wie `"><script>alert(1)</script>`.
3. **Datei-Inklusion prüfen**: Teste `LFI` oder `RFI`, indem du versuchst, Server-Dateien aufzurufen.

### 3.3 **Forensik**

Forensik-Challenges erfordern die Untersuchung und Analyse von Dateien (z. B. Bilder, Netzwerkschnitte, Binärdateien), um versteckte Daten oder Spuren zu finden.

#### **Tools**:
- **Exiftool**: Zum Auslesen von Metadaten.
  ```bash
  exiftool image.jpg
  ```

- **Binwalk**: Sucht nach eingebetteten Dateien in Binärdateien.
  ```bash
  binwalk -e suspect_file
  ```

- **Wireshark**: Analyse von Netzwerkprotokollen.
  ```bash
  wireshark capture.pcap
  ```

- **Steghide**: Zum Verstecken und Extrahieren von Daten in Bilddateien.
  ```bash
  steghide extract -sf image.jpg
  ```

#### **Vorgehen**:
1. **Metadaten analysieren**: Verwende `exiftool`, um interessante Informationen in Bildern oder anderen Dateien zu finden.
2. **Binärdateien untersuchen**: Nutze `binwalk`, um versteckte Dateien zu extrahieren.
3. **Netzwerkverkehr analysieren**: Öffne `PCAP`-Dateien in `Wireshark` und analysiere den Datenverkehr.

### 3.4 **Kryptografie**

Kryptografie-Challenges beinhalten das Knacken von Verschlüsselungen oder das Entschlüsseln von Nachrichten. Häufige Aufgaben umfassen einfache Cäsar-Verschiebungen, RSA oder Hash-Berechnungen.

#### **Tools**:
- **John the Ripper**: Zum Cracken von Passwörtern und Hashes.
  ```bash
  john --wordlist=/usr/share/wordlists/rockyou.txt hashfile
  ```

- **Hashcat**: Ein leistungsstarkes Tool zum Cracken von Hashes mit GPU-Unterstützung.
  ```bash
  hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
  ```

- **CyberChef**: Ein web-basiertes Tool zum Bearbeiten von Verschlüsselungen, Hashes und Encodings (Base64, ROT13, Hex usw.).
  ```bash
  https://gchq.github.io/CyberChef/
  ```

#### **Häufige Verschlüsselungen**:
- **Caesar Cipher**: Einfache Buchstabenverschiebung.
- **RSA**: Eine kryptografische Methode, die öffentliche und private Schlüssel verwendet.
- **Base64**: Ein weit verbreitetes Text-Encoding.

#### **Vorgehen**:
1. **Hash knacken**: Nutze `john` oder `hashcat`, um Passwörter oder Hashes zu knacken.
2. **Manuelle Ciphers**: Nutze Tools wie `CyberChef`, um gängige Verschlüsselungen zu dekodieren.
3. **RSA analysieren**: Prüfe die Public Keys und die Faktoren der Modulus.

### 3.5 **Reverse Engineering**

Reverse Engineering erfordert das Analysieren und Verstehen von Binärdateien, oft um Schwachstellen zu identifizieren oder um ein tieferes Verständnis des Programms zu erlangen.

#### **Tools**:
- **Ghidra**: Ein Open-Source-Reverse-Engineering-Tool von der NSA.
- **Radare2**: Ein leistungsstarkes Framework für Reverse Engineering.
- **GDB**: Ein Debugger, um Programme im Detail zu analysieren.

#### **V

orgehen**:
1. **Dekompilierung**: Nutze `Ghidra`, um Binärdateien zu dekompilieren und ihren Code zu untersuchen.
2. **Debugging**: Verwende `GDB`, um Programme im laufenden Betrieb zu untersuchen und Fehler oder Exploits zu finden.
3. **Analyse der Logik**: Versuche, die Logik des Programms nachzuvollziehen und Eingaben zu manipulieren.

### 3.6 **Pwn (Binary Exploitation)**

Pwn-Aufgaben erfordern oft das Ausnutzen von Speicherfehlern, wie Buffer Overflows, um Kontrolle über ein Programm zu erlangen.

#### **Tools**:
- **Pwntools**: Ein Python-Framework zur Exploit-Entwicklung.
- **GDB**: Zum Debugging von Binärdateien.

#### **Vorgehen**:
1. **Overflow prüfen**: Teste Eingaben auf Buffer Overflow-Schwachstellen.
2. **Exploit schreiben**: Verwende `pwntools`, um einen Exploit zu schreiben, der eine Shell öffnet oder Code ausführt.

---

## **Typische Vorgehensweise für CTFs**

1. **Reconnaissance**: Führe gründliche Recon-Techniken durch, um Informationen über das Ziel zu sammeln.
2. **Schwachstellen identifizieren**: Nutze Web-Exploitation-Techniken und analysiere Dateien.
3. **Exploits entwickeln**: Wende Binäre Exploits oder Web-Exploitation-Techniken an, um die Aufgabe zu lösen.
4. **Dokumentation**: Halte deine Schritte fest und dokumentiere deinen Ansatz.

---

## **CTF-Plattformen und Ressourcen**

- [OverTheWire](https://overthewire.org): Wargames für verschiedene Level.
- [Hack The Box](https://hackthebox.eu): Eine Plattform für virtuelle Maschinen und Exploitation.
- [PicoCTF](https://picoctf.org): Einfache bis mittelgroße CTFs, besonders gut für Anfänger.

---

## **Zusätzliche Tipps und Tricks**

- **Teamwork**: In vielen CTFs ist es sinnvoll, im Team zu arbeiten und verschiedene Aufgaben zu verteilen.
- **Time Management**: Setze Prioritäten und arbeite Aufgaben der Reihe nach ab.
- **Learning by Doing**: Nutze CTFs, um kontinuierlich deine Fähigkeiten zu verbessern. Erwarte nicht, immer sofort die Lösung zu finden.
