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


> **Info:** Beachten Sie, dass das Vermeiden des `Referer`-Headers durch den HTML-Meta-Tag möglicherweise nicht in allen Browsern oder Konfigurationen wirksam ist. Die Verlässlichkeit dieser Methode kann variieren.

# Content-Type-Änderung

Laut dieser Quelle, um Preflight-Anfragen mit der POST-Methode zu vermeiden, sind die folgenden Content-Type-Werte erlaubt:

- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `text/plain`

Beachten Sie jedoch, dass die Logik der Server variieren kann, abhängig vom verwendeten Content-Type. Daher sollten Sie die genannten Werte und andere wie `application/json`, `text/xml`, `application/xml` testen.

## Beispiel für das Senden von JSON-Daten als `text/plain`

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

## Umgehung von Preflight-Anfragen für JSON-Daten

Beim Versuch, JSON-Daten über eine POST-Anfrage zu senden, ist es nicht direkt möglich, `Content-Type: application/json` in einem HTML-Formular zu verwenden. Ebenso initiiert die Nutzung von XMLHttpRequest, um diesen Inhaltstyp zu senden, eine Preflight-Anfrage. Dennoch gibt es Strategien, um diese Einschränkung möglicherweise zu umgehen und zu überprüfen, ob der Server die JSON-Daten unabhängig vom Content-Type verarbeitet:

- **Verwendung alternativer Inhaltstypen**: Verwenden Sie `Content-Type: text/plain` oder `Content-Type: application/x-www-form-urlencoded`, indem Sie `enctype="text/plain"` im Formular festlegen. Dieser Ansatz testet, ob das Backend die Daten unabhängig vom Content-Type nutzt.

- **Inhaltstyp ändern**: Um eine Preflight-Anfrage zu vermeiden und sicherzustellen, dass der Server den Inhalt als JSON erkennt, können Sie die Daten mit `Content-Type: text/plain; application/json` senden. Dies löst keine Preflight-Anfrage aus, könnte jedoch vom Server korrekt verarbeitet werden, wenn er so konfiguriert ist, `application/json` zu akzeptieren.

- **Nutzung von SWF Flash-Dateien**: Eine weniger gängige, aber machbare Methode besteht darin, eine SWF-Flash-Datei zu verwenden, um solche Einschränkungen zu umgehen. Für ein tieferes Verständnis dieser Technik siehe [diesen Beitrag](#).

## Umgehung der Überprüfungen von Referrer / Origin

### Vermeiden Sie den Referrer-Header

Anwendungen können den `Referer`-Header nur validieren, wenn er vorhanden ist. Um zu verhindern, dass ein Browser diesen Header sendet, kann der folgende HTML-Meta-Tag verwendet werden:

```html
<meta name="referrer" content="never">
```
Dies stellt sicher, dass der `Referer`-Header weggelassen wird, wodurch möglicherweise Validierungsprüfungen in einigen Anwendungen umgangen werden.

