# WEB1 — SQL Injection Automation Tool

Automated SQL injection detection and exploitation framework.

## Overview

This project implements a comprehensive SQL injection scanner that:
- Detects multiple injection types (error-based, boolean-based, union-based, time-based)
- Identifies database type from error messages
- Generates DB-specific payloads (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
- Supports GET and POST parameters
- Exports results to JSON

## Features

- **Multi-technique detection**: Error, boolean, union, and time-based injection
- **Database fingerprinting**: Auto-detect MySQL, PostgreSQL, MSSQL, SQLite, Oracle
- **Payload encoding**: URL, double URL, HTML entities, Unicode encoding
- **Configurable risk/level**: Control scan depth and aggressiveness
- **JSON export**: Save findings for further analysis

## Installation

```bash
pip install requests
```

## Usage

```bash
# Basic scan
python3 sqli_auto.py -u "http://target.com/page?id=1"

# POST request
python3 sqli_auto.py -u "http://target.com/login" -m POST -d "user=admin&pass=test"

# With cookies and headers
python3 sqli_auto.py -u "http://target.com/page?id=1" -c "session=abc123" --header "Authorization: Bearer token"

# Force database type and high risk
python3 sqli_auto.py -u "http://target.com/page?id=1" --db mysql --level 2 --risk 2

# URL-encoded payloads with JSON export
python3 sqli_auto.py -u "http://target.com/page?id=1" --encode url -o results.json

# Verbose output
python3 sqli_auto.py -u "http://target.com/page?id=1" -v
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL with vulnerable parameter |
| `-m, --method` | HTTP method: GET or POST |
| `-d, --data` | POST data (key=value&key2=value2) |
| `-c, --cookies` | Cookies (key=value;key2=value2) |
| `--header` | Custom header (repeatable) |
| `--timeout` | Request timeout in seconds |
| `--delay` | Delay between requests |
| `--level` | Scan level: 1 (basic), 2 (param detection), 3 (full) |
| `--risk` | Risk level: 1 (safe), 2 (moderate), 3 (aggressive) |
| `--db` | Force database type |
| `--encode` | Payload encoding: none, url, double_url, html, unicode |
| `-o, --output` | Export results to JSON |
| `-v, --verbose` | Verbose output |

## Example Output

```
  ╔══════════════════════════════════════════╗
  ║    WEB1 — SQL Injection Automation Tool  ║
  ║        SQLi Detection & Exploit          ║
  ╚══════════════════════════════════════════╝

[*] Target: http://target.com/page?id=1
[*] Method: GET
[*] Level: 1, Risk: 1

[*] Establishing response baseline...
    Baseline: 12453 bytes, 0.23s
[*] Parameters to test: ['id']

[*] Testing parameter: id
[*] Detecting database type...
  [*] Database detected: mysql
[*] Testing error-based injection...
  [+] Error-based SQLi found: param=id, db=mysql
  [!] VULNERABLE: id (error-based, mysql)

============================================================
  SCAN RESULTS
============================================================

  [1] Parameter:   id
      Type:        error_based
      Database:    mysql
      Payload:     ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
      Evidence:    XPATH syntax error: '~5.7.34~'

  Total vulnerabilities: 1
============================================================
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## Running the Scanner

The scanner ships with a **vulnerable target simulator** (a stdlib `http.server`
that intentionally implements an error/boolean-based MySQL injection bug). The
demo mode runs the full detection engine against that localhost simulator — the
exact same code path used against a live target.

```bash
# Offline demo: scans the built-in vulnerable simulator, prints findings, exit 0
python3 sqli_auto.py --demo

# Live target (authorized lab targets only)
python3 sqli_auto.py -u "http://<your-lab-target>/page?id=1"

# POST scan, cookies, headers, JSON export
python3 sqli_auto.py -u "http://<your-lab-target>/login" -m POST -d "user=admin&pass=test" -o findings.json

# Force DB type
python3 sqli_auto.py -u "http://<your-lab-target>/page?id=1" --db mysql

# Verbose
python3 sqli_auto.py -u "http://<your-lab-target>/page?id=1" -v
```

The scanner uses the Python standard library (`urllib`) for all HTTP traffic.
The optional `requests` package is never required; if present it is not used.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests start a local vulnerable simulator and a clean control server, then assert
that (a) the scanner flags the planted SQLi bug and (b) it does not false-positive
on the clean page.

## Live Lab Test Plan

Test only against targets in your own lab (e.g. a local DVWA/MySQL container, or
a deliberately misconfigured app on 127.0.0.1 or 192.0.2.x RFC-5737 space):

1. Deploy the vulnerable test app on a local VM/container.
2. Confirm baseline: `python3 sqli_auto.py -u "http://127.0.0.1:<port>/page?id=1" -v`
   shows a working baseline request.
3. Run the scan: `python3 sqli_auto.py -u "http://127.0.0.1:<port>/page?id=1" --db mysql`
   and confirm a finding is reported.
4. Repeat against a hardened/patch-test control page and confirm no finding.
5. Document the target, params scanned, and evidence in your lab report.

## Metrics

- **Video metric**: 60-second screencast of `--demo` reporting findings plus the
  unittest output (`python3 -m unittest discover -s tests -v`), recorded on the
  lab-only loopback target.

## License

MIT
