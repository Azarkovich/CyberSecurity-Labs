# SQL Injection - From Error-Based to Blind Exploitation (DVWA - Low Security)

## Context
This analysis was performed on a deliberately vulnerable web application (DWVA) deployed locally using Docker.

The goal here is not only to demonstrate successful exploitation, but to understand:
- Why the vulnerability exists at the code level
- How different injection techniques can be applied
- What defensive measures are required to prevent such attacks


### Environment

- Application: Damn Vulnerable Web Application (DVWA)
- Target: 127.0.0.1 (localhost)
- Security Level: Low


A custom Python TCP scanner was used to identify open services on the host.

```bash
python3 scanner-python/mini_scanner.py --target 127.0.0.1 --ports 1-1024
```

**Result**

Port 80 was found open, confirming a web application was running.

---


## Vulnerability Identification

### Initial Testing

In the SQL Injection module, a single quote (') was inserted into the input field:

```sql
1'
```

This resulted in a SQL syntax error, indicating that user input was directly embedded into the SQL query without sanitization.

This confirms the presence of an **Error-Based SQL Injection** vulnerability.


## Error-Based SQL Injection

Error-based SQL injection occurs when the application exposes detailed SQL error messages to the client. These errors provide valuable information about the database structure and query logic.


### Why Error Exposure Is Critical

SQL error messages reveal:
- Database engine type and version
- Query structure and syntax
- Table and column names in some cases

This information accelerates the exploitation process by allowing attackers to craft precise payloads based on the observed behavior.

---


## Boolean-Based SQL Injection

Boolean-based injection exploits the ability to manipulate SQL query logic by injecting conditions that alter the query's boolean evaluation.

### Proof of Concept

The following payload was tested:

```sql
1' OR '1'='1
```

This injection transforms the WHERE clause into a condition that always evaluates to true:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';
```

### Result

The application returned all user records from the database, demonstrating that the injected logic bypassed the intended query restriction.

This technique is foundational to SQL injection exploitation, as it allows attackers to manipulate query conditions and retrieve unauthorized data.

---


## UNION-Based SQL Injection

UNION-Based injection allows combining attacker-controlled queries with the original query.

For a UNION statement to execute successfully, both queries must return the same number of columns.

### Step 1: Column Enumeration

The ORDER BY clause was used to determine the number of columns returned by the original query:

```sql
1' ORDER BY 1 --
1' ORDER BY 2 --
1' ORDER BY 3 --
```

An error occurred when ordering by the third column, confirming that the query returns **2 columns**.

### Step 2: Compatibility Verification

To confirm that the UNION attack is viable, a payload with NULL values was tested:

```sql
1' UNION SELECT NULL,NULL --
```

The query executed without error, confirming that the two queries are compatible.

### Step 3: System Information Extraction

With column compatibility established, the following payload was used to extract database metadata:

```sql
1' UNION SELECT database(), version() --
```

The application returned:
- The current database name
- The MySQL version

### Technical Explanation

The injected query merges with the original query as follows:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1'
UNION
SELECT database(), version();
```

The database processes both SELECT statements and returns a combined result set, allowing arbitrary data extraction.

UNION-based injection is particularly effective because it enables systematic enumeration of database structures via `information_schema`, credential extraction, and retrieval of sensitive application data.

---


## Blind SQL Injection

In production environments, SQL error messages are often suppressed to prevent information disclosure. In such cases, attackers rely on **Blind SQL Injection** techniques, which infer information based on the application's behavioral responses.

Blind SQL injection demonstrates that even without visible error messages, SQL injection vulnerabilities remain exploitable.

### Boolean-Based Blind SQL Injection

Boolean-based blind injection exploits the application's differential responses to true and false conditions.

#### Methodology

Two test payloads were submitted to establish a baseline:

**Test 1 (True condition):**
```sql
1' AND 1=1 --
```
Result: The application displayed the user record for ID 1.

**Test 2 (False condition):**
```sql
1' AND 1=2 --
```
Result: The application returned no data.

This confirms that the application's response differs based on the truth value of the injected condition.

#### Data Extraction

With this behavior established, specific questions can be asked about the database:

```sql
1' AND LENGTH(database())>5 --
```
→ If data is returned, the database name is longer than 5 characters.

```sql
1' AND SUBSTRING(database(),1,1)='d' --
```
→ If data is returned, the first character of the database name is 'd'.

Using this approach, data can be extracted character by character. While manual exploitation is time-consuming, automated tools like `sqlmap` can perform this process efficiently.

### Time-Based Blind SQL Injection

If the application produces identical responses regardless of query success or failure, attackers can use time delays to infer information.

#### Proof of Concept

The following payload introduces a 5-second delay:

```sql
1' AND SLEEP(5) --
```

If the page takes 5 seconds to load, the injected query was executed successfully.

#### Conditional Time Delays

Time-based injection can be combined with conditional logic:

```sql
1' AND IF(LENGTH(database())>5, SLEEP(5), 0) --
```

- If the condition is true, the response is delayed by 5 seconds.
- If false, the response is immediate.

This technique is highly reliable but slower than boolean-based methods. Additionally, repeated use of `SLEEP()` may trigger detection by Web Application Firewalls (WAFs).

### Why Blind SQL Injection Matters

Many developers assume that suppressing SQL error messages mitigates injection risks. However, blind SQL injection demonstrates that exploitation remains viable through behavioral analysis.

Proper input validation and parameterized queries are required regardless of error handling practices.

---


## Security Impact

SQL injection vulnerabilities enable attackers to bypass application logic and directly interact with the database. At the Low security level, the following attack scenarios are possible:

- **Data exfiltration**: Complete database dumps including user credentials, emails, and sensitive application data
- **Authentication bypass**: Using payloads such as `' OR '1'='1` to circumvent login mechanisms
- **Data manipulation**: Unauthorized modification or deletion of database records
- **Privilege escalation**: Exploitation of database permissions to gain elevated access within the application
- **Operating system command execution**: In certain configurations (e.g., MSSQL with `xp_cmdshell`), attackers may execute arbitrary system commands

SQL injection is classified as **Injection (#3)** in the OWASP Top 10 2021 and remains one of the most impactful web application vulnerabilities.

---


## Root Cause Analysis

The vulnerability exists because:

1. **Direct string concatenation**: User input is embedde directly into SQL queries without sanitization.
2. **Lack of parameterized queries**: The application does not use prepared statements to separate SQL logic from data.
3. **Insufficient input validation**: No type checking or validation is performed on user-supplied data
4. **Error message exposure**: SQL error details are displayed to the client, facilitating exploitation

The application operates under the assumption that user input is trustworthy, which is a fundamental security violation

---



## Remediation

Mitigation strategies inculde:

- Parameterized queries / prepared statements
- Input validation
- Limiting database privileges
- Disabling verbose error messages

---



## Conclusion

SQL injection vulnerabilities demonstrate how inadequate input handling can lead to complete database compromise. Unlike client-side attacks such as XSS, SQL injection directly targets the application's data layer, enabling unauthorized access, modification, and extraction of sensitive information.

This analysis covered four primary exploitation techniques:
- **Error-based injection**: Leveraging exposed error messages to refine payloads
- **Boolean-based injection**: Manipulating query logic to bypass authentication and retrieve data
- **UNION-based injection**: Combining queries for structured data exfiltration
- **Blind injection**: Inferring data through behavioral analysis when errors are suppressed

The most critical takeaway is that **escaping user input is insufficient**. Only parameterized queries (prepared statements) provide reliable protection by ensuring a strict separation between SQL code and user-supplied data.

Effective defense requires multiple layers: prepared statements as the primary control, input validation as a supplementary measure, least-privilege database accounts to limit impact, and proper error handling to prevent information disclosure.
