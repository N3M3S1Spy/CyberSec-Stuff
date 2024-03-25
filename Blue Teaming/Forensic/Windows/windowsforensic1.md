# Windows Forensic 1
TryHackMe Raum [Windows-Forensic1](https://tryhackme.com/room/windowsforensics1).

Der Einfachheit halber fange ich mit dem Aufgabenblatt 2 an, da sich auf dem ersten Blatt nur Informationen zu Microsoft befinden und dass sie den größten Teil des Desktop-Marktes besitzen.

# Windows-Registry
Die Windows-Registry ist eine Sammlung von Datenbanken, die die Konfigurationsdaten des Systems enthalten. Diese Konfigurationsdaten können Informationen über Hardware, Software oder Benutzer enthalten. Darüber hinaus umfassen sie Daten zu zuletzt verwendeten Dateien, verwendeten Programmen oder mit dem System verbundenen Geräten. Es ist offensichtlich, dass diese Daten aus forensischer Sicht von großem Nutzen sind. In diesem Bereich werden wir Methoden erlernen, um diese Daten zu lesen und die benötigten Informationen über das System zu extrahieren. Sie können die Registry mithilfe von regedit.exe anzeigen, einem integrierten Windows-Dienstprogramm zum Anzeigen und Bearbeiten der Registry. In den kommenden Aufgaben werden wir uns mit anderen Tools beschäftigen, um mehr über die Registrierung zu erfahren.

Die Windows-Registry besteht aus Schlüsseln und Werten. Wenn Sie das Dienstprogramm regedit.exe öffnen, um die Registry anzuzeigen, zeigen die angezeigten Ordner die Registryschlüssel an. Registrywerte sind die Daten, die in diesen Registryschlüsseln gespeichert sind. Eine Registrystruktur ist eine Gruppe von Schlüsseln, Unterschlüsseln und Werten, die in einer einzelnen Datei auf der Festplatte gespeichert sind.

> [!NOTE]
> **Registry Datenbank**  
> Die Registry-Anwendung ist eine Datenbank aus Nutzerdaten und Systemdaten. Diese dient dazu, Einstellungen zu speichern, und Die Registry-Anwendung (regedit.exe) dient dazu, sie aufzulisten.

## Struktur der Registry Datenbank
Auf jedem Windows-System befinden sich diese fünf Root-Verzeichnisse:

1. HKEY_CURRENT_USER
2. HKEY_USERS
3. HKEY_LOCAL_MACHINE
4. HKEY_CLASSES_ROOT
5. HKEY_CURRENT_CONFIG

So definiert Microsoft jeden dieser Root-Schlüssel. Weitere Einzelheiten und Informationen zu den folgenden Windows-Registrierungsschlüsseln finden Sie in der Dokumentation von [Microsoft](https://learn.microsoft.com/en-US/troubleshoot/windows-server/performance/windows-registry-advanced-users).

| Verzeichnisse       | Beschreibung                                                                                                                                   |
|---------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| HKEY_CURRENT_USER   | Enthält den Stamm der Konfigurationsinformationen für den Benutzer derzeit angemeldet. Hier werden die Ordner, Bildschirmfarben und Systemsteuerungseinstellungen des Benutzers gespeichert. Diese Informationen werden mit dem Profil des Benutzers verknüpft. Dieser Schlüssel wird manchmal als abgekürzt HKCU. |
| HKEY_USERS          | HKEY_USERS Enthält alle aktiv geladenen Benutzerprofile auf dem Computer. HKEY_CURRENT_USER ist ein Unterschlüssel von HKEY_USERS. HKEY_USERS wird manchmal als HKU abgekürzt.                                     |
| HKEY_LOCAL_MACHINE | Enthält spezifische Konfigurationsinformationen für den Computer (für jeden). Benutzer). Dieser Schlüssel wird manchmal als HKLM abgekürzt.                                                                    |
| HKEY_CLASSES_ROOT  | Ein Unterschlüssel von `HKEY_LOCAL_MACHINE\Software` ist der HKEY_LOCAL_MACHINE\Software\Classes Schlüssel. Die Informationen, die in diesem Schlüssel gespeichert sind, gewährleisten, dass das richtige Programm geöffnet wird, wenn ein Benutzer unter Windows eine Datei öffnet. Dieser Schlüssel wird gelegentlich als HKCR abgekürzt. Ab Windows 2000 werden diese Informationen in den Schlüsseln HKEY_LOCAL_MACHINE und HKEY_CURRENT_USER gespeichert. Der `HKEY_LOCAL_MACHINE\Software\Classes` Schlüssel enthält Standardkonfigurationen, die für alle Benutzer auf dem lokalen Computer gelten können. Der `HKEY_CURRENT_USER\Software\Classes` Schlüssel überschreibt diese Standardkonfigurationen und gilt nur für den interaktiven Benutzer. Der HKEY_CLASSES_ROOT-Schlüssel bietet eine Sicht auf die Registrierung, die Informationen aus beiden Quellen zusammenführt. HKEY_CLASSES_ROOT stellt auch diese zusammengeführte Sicht für Programme bereit, die für frühere Windows-Versionen entwickelt wurden. Um die Konfigurationen für den interaktiven Benutzer zu ändern, müssen Änderungen im `HKEY_CURRENT_USER\Software\Classes` Schlüssel vorgenommen werden, anstatt unter HKEY_CLASSES_ROOT. Um Standardkonfigurationen zu ändern, müssen Änderungen im HKEY_CURRENT_USER\Software\Classes Schlüssel vorgenommen werden. Wenn Sie Schlüssel unter HKEY_CLASSES_ROOT schreiben, speichert das System die Informationen unter HKEY_CURRENT_USER\Software\Classes. Wenn Sie Werte in einen Schlüssel unter HKEY_CLASSES_ROOT schreiben und dieser Schlüssel bereits unter HKEY_CURRENT_USER\Software\Classes existiert, speichert das System die Informationen dort und nicht unter HKEY_CURRENT_USER\Software\Classes. |
| HKEY_CURRENT_CONFIG| Enthält Informationen zum Hardwareprofil, das vom lokalen Server verwendet wird Computer beim Systemstart.                                                                                                 |
