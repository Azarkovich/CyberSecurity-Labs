# XSS - From Injection to Real Impact (DVWA)

## Context 
This write-up documents the discovery and exploitation of Cross-Site Scripting (XSS) vulnerabilities in a deliberately vulnerable web application (DVWA).

The goal here is not only to trigger JavaScript execution, but to understand: 
- why the vulnerabity exists
- how it can be exploited in real-world scenarios
- what security mechanisms are required to mitigate it

## Environment
- Application: Damn Vulnerable Web Application (DVWA)
- Deployment: Docker
- Security Level : Low
- Target OS: Linux