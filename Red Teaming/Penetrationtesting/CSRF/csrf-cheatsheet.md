# Cross-Site Request Forgery (CSRF) Erklärt

Cross-Site Request Forgery (CSRF) ist eine Art von Sicherheitsanfälligkeit, die in Webanwendungen zu finden ist. Sie ermöglicht es Angreifern, Aktionen im Namen ahnungsloser Benutzer durch Ausnutzung ihrer authentifizierten Sitzungen durchzuführen. Der Angriff wird ausgeführt, wenn ein Benutzer, der in die Plattform eines Opfers eingeloggt ist, eine bösartige Seite besucht. Diese Seite löst dann Anfragen an das Konto des Opfers aus, indem sie Methoden wie das Ausführen von JavaScript, das Einreichen von Formularen oder das Abrufen von Bildern verwendet.

## Voraussetzungen für einen CSRF-Angriff

Um eine CSRF-Sicherheitsanfälligkeit auszunutzen, müssen mehrere Bedingungen erfüllt sein:

1. **Identifizieren Sie eine wertvolle Aktion**: Der Angreifer muss eine Aktion finden, die es wert ist, ausgenutzt zu werden, wie z.B. das Ändern des Passworts, der E-Mail-Adresse oder das Erhöhen von Berechtigungen.

2. **Sitzungsmanagement**: Die Sitzung des Benutzers sollte ausschließlich über Cookies oder den HTTP Basic Authentication-Header verwaltet werden, da andere Header für diesen Zweck nicht manipuliert werden können.

3. **Fehlen unvorhersehbarer Parameter**: Die Anfrage sollte keine unvorhersehbaren Parameter enthalten, da diese den Angriff verhindern können.

# Verteidigung gegen CSRF

Mehrere Gegenmaßnahmen können implementiert werden, um sich gegen CSRF-Angriffe zu schützen:

- **SameSite-Cookies**: Dieses Attribut verhindert, dass der Browser Cookies zusammen mit Cross-Site-Anfragen sendet. [Mehr über SameSite-Cookies.](#)

- **Cross-Origin Resource Sharing (CORS)**: Die CORS-Richtlinie der Opferseite kann die Durchführbarkeit des Angriffs beeinflussen, insbesondere wenn der Angriff das Lesen der Antwort von der Opferseite erfordert. [Erfahren Sie mehr über CORS-Umgehung.](#)

- **Benutzerauthentifizierung**: Die Aufforderung zur Eingabe des Passworts des Benutzers oder das Lösen eines Captchas kann die Absicht des Benutzers bestätigen.

- **Überprüfung von Referrer- oder Origin-Headern**: Die Validierung dieser Header kann helfen sicherzustellen, dass Anfragen von vertrauenswürdigen Quellen stammen. Allerdings kann eine sorgfältige Gestaltung von URLs schlecht implementierte Überprüfungen umgehen, wie z.B.:
  - Verwendung von `http://mal.net?orig=http://example.com` (URL endet mit der vertrauenswürdigen URL)
  - Verwendung von `http://example.com.mal.net` (URL beginnt mit der vertrauenswürdigen URL)

- **Ändern von Parameternamen**: Das Ändern der Namen von Parametern in POST- oder GET-Anfragen kann helfen, automatisierte Angriffe zu verhindern.

- **CSRF-Token**: Die Einbeziehung eines einzigartigen CSRF-Tokens in jede Sitzung und die Anforderung dieses Tokens in nachfolgenden Anfragen kann das Risiko von CSRF erheblich mindern. Die Wirksamkeit des Tokens kann durch die Durchsetzung von CORS erhöht werden.

Das Verständnis und die Implementierung dieser Verteidigungen sind entscheidend für die Aufrechterhaltung der Sicherheit und Integrität von Webanwendungen.

## Umgehung von Verteidigungen

### Von POST zu GET

Vielleicht ist das Formular, das Sie ausnutzen möchten, darauf vorbereitet, eine POST-Anfrage mit einem CSRF-Token zu senden, aber Sie sollten überprüfen, ob auch eine GET-Anfrage gültig ist und ob bei der Sendung einer GET-Anfrage das CSRF-Token weiterhin validiert wird.

### Fehlendes Token

Anwendungen könnten einen Mechanismus implementieren, um Tokens zu validieren, wenn sie vorhanden sind. Eine Sicherheitsanfälligkeit entsteht jedoch, wenn die Validierung ganz übersprungen wird, wenn das Token fehlt. Angreifer können dies ausnutzen, indem sie den Parameter entfernen, der das Token trägt, nicht nur dessen Wert. Dies ermöglicht es ihnen, den Validierungsprozess zu umgehen und einen Cross-Site Request Forgery (CSRF)-Angriff effektiv durchzuführen.

### CSRF-Token ist nicht an die Benutzersitzung gebunden

Anwendungen, die CSRF-Token nicht an Benutzersitzungen binden, stellen ein erhebliches Sicherheitsrisiko dar. Diese Systeme überprüfen Tokens gegen einen globalen Pool, anstatt sicherzustellen, dass jedes Token an die initiierende Sitzung gebunden ist.

So nutzen Angreifer dies aus:

1. Authentifizieren Sie sich mit ihrem eigenen Konto.
2. Erhalten Sie ein gültiges CSRF-Token aus dem globalen Pool.
3. Verwenden Sie dieses Token in einem CSRF-Angriff gegen ein Opfer.

Diese Sicherheitsanfälligkeit ermöglicht es Angreifern, unbefugte Anfragen im Namen des Opfers zu stellen und die unzureichenden Token-Validierungsmechanismen der Anwendung auszunutzen.

### Methodenumgehung

Wenn die Anfrage eine "seltsame" Methode verwendet, überprüfen Sie, ob die Methodenüberschreibungsfunktionalität funktioniert. Wenn beispielsweise die PUT-Methode verwendet wird, können Sie versuchen, die POST-Methode zu verwenden und zu senden: `https://example.com/my/dear/api/val/num?_method=PUT`

Dies könnte auch funktionieren, indem Sie den `_method`-Parameter innerhalb einer POST-Anfrage senden oder die Header verwenden:
- `X-HTTP-Method`
- `X-HTTP-Method-Override`
- `X-Method-Override`

# Umgehung des benutzerdefinierten Header-Tokens

Wenn die Anfrage einen benutzerdefinierten Header mit einem Token als CSRF-Schutzmethode hinzufügt, dann:

- **Testen Sie die Anfrage ohne den benutzerdefinierten Token und auch Header.**
- **Testen Sie die Anfrage mit genau gleicher Länge, aber unterschiedlichem Token.**

## CSRF-Token wird durch ein Cookie verifiziert

Anwendungen können CSRF-Schutz implementieren, indem sie das Token sowohl in einem Cookie als auch in einem Anfrageparameter duplizieren oder indem sie ein CSRF-Cookie setzen und überprüfen, ob das im Backend gesendete Token mit dem Cookie übereinstimmt. Die Anwendung validiert Anfragen, indem sie überprüft, ob das Token im Anfrageparameter mit dem Wert im Cookie übereinstimmt.

Diese Methode ist jedoch anfällig für CSRF-Angriffe, wenn die Website Schwächen aufweist, die es einem Angreifer ermöglichen, ein CSRF-Cookie im Browser des Opfers zu setzen, wie z.B. eine CRLF-Sicherheitsanfälligkeit. Der Angreifer kann dies ausnutzen, indem er ein täuschendes Bild lädt, das das Cookie setzt, gefolgt von der Einleitung des CSRF-Angriffs.

Hier ist ein Beispiel, wie ein Angriff strukturiert sein könnte:

```html
<html>
  <!-- CSRF Proof of Concept - generated by Burp Suite Professional -->
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="https://example.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="asd&#64;asd&#46;asd" />
      <input type="hidden" name="csrf" value="tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E" />
      <input type="submit" value="Submit request" />
    </form>
    <img src="https://example.com/?search=term%0d%0aSet-Cookie:%20csrf=tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E" onerror="document.forms[0].submit();"/>
  </body>
</html>
```
> **Info:** Wenn der CSRF-Token mit dem Sitzungscookie verbunden ist, funktioniert dieser Angriff nicht. In diesem Fall müssten Sie die Sitzung des Opfers setzen, was bedeutet, dass Sie sich selbst angreifen würden.
