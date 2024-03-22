# Windows Forensic 1
TryHackMe Raum [Windows-Forensic1](https://tryhackme.com/room/windowsforensics1).

Der einfachhalt haber fangen ich mit dem Aufgabenblatt 2 an, da sich in dem ersten Blatt nur infos zu Microsoft<br>
an sich befinden und das sie den größten teil des Desktop marktes besitzen.

## Registry Datenbank
Die Registry-Anwendung ist eine Datenbank aus Nutzerdaten und Systemdaten. Diese dient dazu um einstellung zu speichern<br>
und Die Registry-Anwendung dient dazu um es aufzulisten

## Strukture der Registry Datenbank
Auf jedem Windows System befinden sich diese Fünf Root-Verzeichnise:<br>

1. HKEY_CURRENT_USER 
2. HKEY_USERS
3. HKEY_LOCAL_MACHINE
4. HKEY_CLASSES_ROOT
5. HKEY_CURRENT_CONFIG 
<br>
So definiert Microsoft jeden dieser Root-Schlüssel. Weitere Einzelheiten und Informationen zu den folgenden Windows-Registrierungsschlüsseln finden Sie in der Dokumentation von [Microsoft](https://learn.microsoft.com/en-US/troubleshoot/windows-server/performance/windows-registry-advanced-users).<br>

| Verzeichnisse | Beschreibung |
| ------------- | ------------ |
| HKEY_CURRENT_USER | Enthält den Stamm der Konfigurationsinformationen für den Benutzer derzeit angemeldet. Hier werden die Ordner, Bildschirmfarben und Systemsteuerungseinstellungen des Benutzers gespeichert. Diese Informationen werden mit dem Profil des Benutzers verknüpft. Dieser Schlüssel wird manchmal als abgekürzt HKCU. |
| HKEY_USERS | HKEY_USERS 	Enthält alle aktiv geladenen Benutzerprofile auf dem Computer. HKEY_CURRENT_USER ist ein Unterschlüssel von HKEY_USERS. HKEY_USERS wird manchmal als HKU abgekürzt. |
| HKEY_LOCAL_MACHINE | Enthält spezifische Konfigurationsinformationen für den Computer (für jeden). Benutzer). Dieser Schlüssel wird manchmal als HKLM abgekürzt. |
| HKEY_CLASSES_ROOT | Ist ein Unterschlüssel von ```HKEY_LOCAL_MACHINE\Software```. Die Information Das hier gespeicherte Programm stellt sicher, dass das richtige Programm geöffnet wird, wenn Sie eine Datei unter Windows öffnen Forscher. Dieser Schlüssel wird manchmal als HKCR abgekürzt.<br><br>Ab Windows 2000 sind diese Informationen unter den Schlüsseln HKEY_LOCAL_MACHINE und HKEY_CURRENT_USER gespeichert. Der ```HKEY_LOCAL_MACHINE\Software\Classes``` Der Schlüssel enthält Standardeinstellungen, die für alle gelten können Benutzer auf dem lokalen Computer. Der ```HKEY_CURRENT_USER\Software\Classes``` Schlüssel hat Einstellungen die die Standardeinstellungen außer Kraft setzen und nur für den interaktiven Benutzer gelten.<br><br>Der HKEY_CLASSES_ROOT-Schlüssel Bietet eine Ansicht der Registrierung, die die Informationen aus diesen beiden Quellen zusammenführt. HKEY_CLASSES_ROOT stellt diese zusammengeführte Ansicht auch für Programme bereit, die für frühere Versionen entwickelt wurden von Windows. Um die Einstellungen für den interaktiven Benutzer zu ändern, müssen Änderungen unter vorgenommen werden ```HKEY_CURRENT_USER\Software\Classes``` statt unter HKEY_CLASSES_ROOT.<br><br>Um es zu ändern Standardeinstellungen, Änderungen müssen unter vorgenommen werden ```HKEY_CURRENT_USER\Software\Classes```.Wenn du Schreiben Sie Schlüssel auf einen Schlüssel unter HKEY_CLASSES_ROOT. Das System speichert die Informationen darunter ```HKEY_CURRENT_USER\Software\Classes```.<br><br>Wenn Sie Werte in einen Schlüssel unter schreiben HKEY_CLASSES_ROOT, und der Schlüssel existiert bereits darunter HKEY_CURRENT_USER\Software\Classes, Das System speichert die Informationen dort und nicht darunter ```HKEY_CURRENT_USER\Software\Classes```. |
<br>
