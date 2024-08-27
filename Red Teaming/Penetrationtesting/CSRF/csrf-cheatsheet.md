# Cross-Site Request Forgery (CSRF) Erklärt

Cross-Site Request Forgery (CSRF) ist eine Art Sicherheitslücke in Webanwendungen. Sie ermöglicht es Angreifern, Aktionen im Namen ahnungsloser Benutzer durchzuführen, indem sie deren authentifizierte Sitzungen ausnutzen. Der Angriff wird ausgeführt, wenn ein Benutzer, der in eine Opferplattform eingeloggt ist, eine bösartige Website besucht. Diese Website löst dann Anfragen an das Konto des Opfers aus, indem sie Methoden wie das Ausführen von JavaScript, das Absenden von Formularen oder das Abrufen von Bildern verwendet.

## Voraussetzungen für einen CSRF-Angriff

Um eine CSRF-Sicherheitslücke auszunutzen, müssen mehrere Bedingungen erfüllt sein:

- **Wertvolle Aktion identifizieren:** Der Angreifer muss eine Aktion finden, die es wert ist, ausgenutzt zu werden, wie z.B. das Ändern des Passworts oder der E-Mail-Adresse des Benutzers oder das Erhöhen von Berechtigungen.
  
- **Sitzungsverwaltung:** Die Sitzung des Benutzers sollte ausschließlich über Cookies oder den HTTP Basic Authentication-Header verwaltet werden, da andere Header für diesen Zweck nicht manipuliert werden können.
  
- **Fehlen unvorhersehbarer Parameter:** Die Anfrage sollte keine unvorhersehbaren Parameter enthalten, da diese den Angriff verhindern können.

## Schnelltest

Sie können die Anfrage in Burp erfassen, um CSRF-Schutzmaßnahmen zu überprüfen, und um den Schutz im Browser zu testen, können Sie auf „Als Fetch kopieren“ klicken und die Anfrage überprüfen.

## Schutz vor CSRF

Es gibt mehrere Gegenmaßnahmen, die implementiert werden können, um sich vor CSRF-Angriffen zu schützen:

- **SameSite-Cookies:** Dieses Attribut verhindert, dass der Browser Cookies zusammen mit siteübergreifenden Anfragen sendet. Mehr über SameSite-Cookies erfahren.
  
- **Cross-Origin Resource Sharing:** Die CORS-Richtlinie der Opfer-Website kann die Machbarkeit des Angriffs beeinflussen, insbesondere wenn der Angriff das Lesen der Antwort von der Opfer-Website erfordert. Mehr über das Umgehen von CORS erfahren.
  
- **Benutzerverifizierung:** Das Abfragen des Benutzerpassworts oder das Lösen eines Captchas kann die Absicht des Benutzers bestätigen.
  
- **Überprüfung der Referrer- oder Origin-Header:** Das Validieren dieser Header kann helfen, sicherzustellen, dass Anfragen aus vertrauenswürdigen Quellen stammen. Vorsicht jedoch, dass schlecht implementierte Überprüfungen durch sorgfältig gestaltete URLs umgangen werden können, wie z.B.:

    - Verwendung von `http://mal.net?orig=http://example.com` (URL endet mit der vertrauenswürdigen URL)
    - Verwendung von `http://example.com.mal.net` (URL beginnt mit der vertrauenswürdigen URL)
  
- **Ändern von Parameternamen:** Das Ändern der Namen von Parametern in POST- oder GET-Anfragen kann helfen, automatisierte Angriffe zu verhindern.
  
- **CSRF-Token:** Die Einbindung eines eindeutigen CSRF-Tokens in jede Sitzung und die Anforderung dieses Tokens bei nachfolgenden Anfragen kann das Risiko von CSRF erheblich verringern. Die Wirksamkeit des Tokens kann durch Erzwingen von CORS verbessert werden.

Das Verständnis und die Implementierung dieser Verteidigungsmaßnahmen ist entscheidend für die Aufrechterhaltung der Sicherheit und Integrität von Webanwendungen.

## Umgehung von Schutzmaßnahmen

### Von POST zu GET

Vielleicht ist das Formular, das Sie missbrauchen möchten, so vorbereitet, dass es eine POST-Anfrage mit einem CSRF-Token sendet. Sie sollten jedoch überprüfen, ob auch eine GET-Anfrage gültig ist und ob das CSRF-Token weiterhin überprüft wird, wenn Sie eine GET-Anfrage senden.

### Fehlendes Token

Anwendungen könnten einen Mechanismus implementieren, der Tokens validiert, wenn sie vorhanden sind. Eine Schwachstelle entsteht jedoch, wenn die Validierung vollständig übersprungen wird, wenn das Token fehlt. Angreifer können dies ausnutzen, indem sie den Parameter entfernen, der das Token trägt, und nicht nur seinen Wert. Dies ermöglicht es ihnen, den Validierungsprozess zu umgehen und einen Cross-Site Request Forgery (CSRF)-Angriff effektiv durchzuführen.

### CSRF-Token ist nicht an die Benutzersitzung gebunden

Anwendungen, die CSRF-Token nicht an Benutzersitzungen binden, stellen ein erhebliches Sicherheitsrisiko dar. Diese Systeme überprüfen Tokens gegen einen globalen Pool, anstatt sicherzustellen, dass jedes Token an die auslösende Sitzung gebunden ist.

So nutzen Angreifer diese Schwachstelle aus:

- Authentifizierung mit ihrem eigenen Konto.
- Erhalt eines gültigen CSRF-Tokens aus dem globalen Pool.
- Verwendung dieses Tokens in einem CSRF-Angriff gegen ein Opfer.

Diese Schwachstelle ermöglicht es Angreifern, unautorisierte Anfragen im Namen des Opfers durchzuführen, indem sie die unzureichende Token-Validierung der Anwendung ausnutzen.

### Methoden-Umgehung

Wenn die Anfrage eine „seltsame“ Methode verwendet, überprüfen Sie, ob die Methode „Override“-Funktionalität funktioniert. Zum Beispiel, wenn es eine PUT-Methode verwendet, können Sie versuchen, eine POST-Methode zu verwenden und zu senden: `https://example.com/my/dear/api/val/num?_method=PUT`

Dies könnte auch funktionieren, indem Sie den `_method`-Parameter in einer POST-Anfrage oder in den Headern senden:

- `X-HTTP-Method`
- `X-HTTP-Method-Override`
- `X-Method-Override`

### Anpassung der Header-Token-Umgehung

Wenn die Anfrage einen benutzerdefinierten Header mit einem Token als CSRF-Schutzmethode hinzufügt, dann:

- Testen Sie die Anfrage ohne das angepasste Token und den Header.
- Testen Sie die Anfrage mit genau der gleichen Länge, aber einem anderen Token.

### CSRF-Token wird durch ein Cookie überprüft

Anwendungen können CSRF-Schutz implementieren, indem sie das Token sowohl in einem Cookie als auch in einem Anfrageparameter duplizieren oder ein CSRF-Cookie setzen und überprüfen, ob das im Backend gesendete Token dem Cookie entspricht. Die Anwendung validiert Anfragen, indem sie überprüft, ob das Token im Anfrageparameter mit dem Wert im Cookie übereinstimmt.

Diese Methode ist jedoch anfällig für CSRF-Angriffe, wenn die Website Schwachstellen aufweist, die es einem Angreifer ermöglichen, ein CSRF-Cookie im Browser des Opfers zu setzen, wie z.B. eine CRLF-Schwachstelle. Der Angreifer kann dies ausnutzen, indem er ein trügerisches Bild lädt, das das Cookie setzt, gefolgt von der Einleitung des CSRF-Angriffs.

Hier ist ein Beispiel dafür, wie ein Angriff strukturiert werden könnte:

```html
<html>
  <!-- CSRF Proof of Concept - generiert von Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://example.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="asd&#64;asd&#46;asd" />
      <input type="hidden" name="csrf" value="tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E" />
      <input type="submit" value="Anfrage absenden" />
    </form>
    <img src="https://example.com/?search=term%0d%0aSet-Cookie:%20csrf=tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E" onerror="document.forms[0].submit();"/>
  </body>
</html>
```

Beachten Sie, dass dieser Angriff nicht funktioniert, wenn das CSRF-Token mit dem Sitzungs-Cookie verbunden ist, da Sie dann Ihr eigenes Sitzungstoken an das Opfer weitergeben müssen und sich somit selbst angreifen würden.

### Änderung des Content-Types

Um Vorab-Anfragen unter Verwendung der POST-Methode zu vermeiden, sind laut diesem Dokument die folgenden Content-Type-Werte zulässig:

- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `text/plain`

Beachten Sie jedoch, dass die Serverlogik je nach verwendetem Content-Type variieren kann. Sie sollten daher die oben genannten Werte und andere wie `application/json`, `text/xml`, `application/xml` ausprobieren.

Beispiel (von hier) zum Senden von JSON-Daten als `text/plain`:

```html
<html>
  <body>
    <form id="form" method="post" action="https://phpme.be.ax/" enctype="text/plain">
      <input name='{"garbageeeee":"' value='", "yep": "yep yep yep", "url": "https://webhook/"}'>
    </form>
    <script>
        form.submit();
    </script>
  </body>
</html>
```

### Vorab-Anfragen für JSON-Daten umgehen

Beim Versuch, JSON-Daten über eine POST-Anfrage zu senden, ist die Verwendung von `Content-Type: application/json` in einem HTML-Formular nicht direkt möglich. Ebenso löst die Nutzung von `XMLHttpRequest` zur Übermittlung dieses Content-Types eine Vorab-Anfrage aus. Es gibt jedoch Strategien, um diese
