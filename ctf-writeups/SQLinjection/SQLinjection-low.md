# SQL Injection - DVWA (Low Security)

## Context
This analysis was performed on a deliberately vulnerable web application (DWVA) deployed locally using Docker.

Target: 127.0.0.1 (localhost)
Service identified: HTTP (Port 80)
Security Level: Low


## 2. Reconnaissance 

A custom Python TCP scanner was used to identify open services on the host.
Port 80 was found open, confirming a web application was running.


## 3. Vulnerability Identification

In the SQL Injection module, a single quote (') was inserted into the input field:

1'

this resulted in a SQL syntax error, indicating that user input was directly embedded into the SQL query without sanitization.


## 4. Exploitation

The following payload was used:

1' OR '1'='1

This modified the SQL query logic and forced the WHERE clause to always evaluate to TRUE.

As a result, multiple database records were returned.


## 5. Root Cause Analysis

The vulnerability exists because:

- User input is concatenated directly into SQL queries.
- No prepares statements are used.
- No input validation or escaping is implemented.


## 6. Security Impact

An attacker could:

- Dump the entire database
- Extract credentials
- Escalate privileges
- Compromise the entire application 


## 7. Remediation

Mitigation strategies inculde:

- Parameterized queries / prepared statements
- Input validation
- Limiting database privileges
- Disabling verbose error messages


## Lessons Learned

This exercise demonstrates how improper input handling can lead to complete database compromise. Understanding SQL query construction is essential for both attackers and defenders. 