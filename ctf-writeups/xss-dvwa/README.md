# XSS - From Injection to Real Impact (DVWA)

## Context 
This write-up documents the discovery and exploitation of Cross-Site Scripting (XSS) vulnerabilities in a deliberately vulnerable web application (DVWA).

The goal here is not only to trigger JavaScript execution, but to understand: 
- why the vulnerability exists
- how it can be exploited in real-world scenarios
- what security mechanisms are required to mitigate it

## Environment
- Application: Damn Vulnerable Web Application (DVWA)
- Deployment: Docker
- Security Level : Low
- Target OS: Linux

During the initial deployment, a database authentication error occurred due to
a previously initialized MariaDB volume with mismatched credentials.
The issue was resolved by removing persistent volumes and reinitializing the database.


## Reflected XSS - Vulnerability Analysis 

The reflected XSS vulnerability occurs because user-controlled input is directly embedded into the HTML response without any sanitization or output encoding.

In the DVWA reflected XSS module, the application retrieves a GET parameter and echoes it back to the page: 

```php
$name = $_GET['name'];
echo "Hello $name";
```

## Proof of Concept

To validate the vulnerability, the following payload was injected into the vulnerable parameter:

```html
<script>alert(14)</script>
```

THis payload demonstrates that the JavaScript code injected is interpreted and executed by the victim's browser. 

--- 

## The Role of the DOM in XSS Exploitation 

The Document Object Model (DOM) represents the internal structure of a web page as interpreted by the browser. It exposes all page elements ad objects accessible via JavaScript.

When a Cross-Site Scripting vulnerability is exploited, the injected JavaSacript code executes with full access to the DOM of the trusted application. This allows an attacker to dynamically read, modify, or manipulate the page content as seen by the victim.

In the DVWA context, DOM manipulation demonstrates how XSS goes beyond simple JavaScript execution and enables full client-side control. 


---

## Real-World Impact: Session Exposure

Once JAvaScript execution is achieved, the attacker gains access to the browser context of the victim. This includes session cookies used for authentication.

In DVWA, session cookies are accessible via JavaScript, allowing the following payload:

```html
<script>alert(document.cookie)</script>
````

This demonstrates that sensitive authentication data can be exposed, potentially enabling session hijacking.

---

Beyond data exposure, XSS allows full manipulation of the user interface.
An attacker can dynamically modify the page content, dispaly fake forms, or mislead users into performing unintented actions.


---

## Stored XSS - Persistent Client-Side Compromise

Unlike reflected XSS, stored XSS vulnerabilities involve malicious input being permanently stored on the server (e.g, in a database) and served to users whenever the affected page is loaded.

In the DVWA stored XSS module, user input is stored without validation or output encoding, allowing persistent JavaSccript execution across sessions.

This significantly increases the impact, as any user visiting the page will automatially execute the attacker's payload.