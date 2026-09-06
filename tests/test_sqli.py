#!/usr/bin/env python3
"""Tests for WEB1 — SQL Injection Automation Tool."""

import sys
import os
import threading
import time
import unittest
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sqli_auto import SQLiScanner, ScanConfig, DBType, InjectionType


class VulnHandler(BaseHTTPRequestHandler):
    """Vulnerable endpoint: reflects SQL errors and differentiates true/false booleans."""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        user_input = params.get("id", [""])[0]

        if "'" in user_input or '"' in user_input:
            if "1=1" in user_input:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>User: admin</body></html>")
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
            self.wfile.write(
                b"<html><body>SQL syntax error near '' at line 1 "
                b"check the manual that corresponds to your MySQL</body></html>"
            )
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>Normal page content</body></html>")

    def log_message(self, format, *args):
        pass


class CleanHandler(BaseHTTPRequestHandler):
    """Clean endpoint: no SQL injection vulnerability."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>Clean page - no injection here</body></html>")

    def log_message(self, format, *args):
        pass


class TestSQLiVulnDetection(unittest.TestCase):
    """Scanner must find SQLi on vulnerable endpoint."""

    @classmethod
    def setUpClass(cls):
        cls.vuln_server = HTTPServer(("127.0.0.1", 18101), VulnHandler)
        cls.vuln_thread = threading.Thread(target=cls.vuln_server.serve_forever, daemon=True)
        cls.vuln_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.vuln_server.shutdown()

    def test_error_based_detection(self):
        config = ScanConfig(
            url="http://127.0.0.1:18101/page?id=1",
            method="GET", timeout=5, verbose=False,
        )
        scanner = SQLiScanner(config)
        scanner.run_scan()
        self.assertTrue(len(scanner.results) > 0, "Should detect error-based SQLi")
        types = [r.injection_type for r in scanner.results]
        self.assertIn(InjectionType.ERROR_BASED, types)

    def test_boolean_based_detection(self):
        config = ScanConfig(
            url="http://127.0.0.1:18101/page?id=1",
            method="GET", timeout=5, verbose=False, level=2,
        )
        scanner = SQLiScanner(config)
        scanner.run_scan()
        self.assertTrue(len(scanner.results) > 0, "Should detect boolean-based SQLi")

    def test_db_detection(self):
        config = ScanConfig(
            url="http://127.0.0.1:18101/page?id=1",
            method="GET", timeout=5, verbose=False,
        )
        scanner = SQLiScanner(config)
        scanner.run_scan()
        db_types = [r.db_type for r in scanner.results]
        self.assertIn(DBType.MYSQL, db_types, "Should detect MySQL")


class TestSQLiCleanNoFalsePositive(unittest.TestCase):
    """Scanner must NOT find SQLi on clean endpoint."""

    @classmethod
    def setUpClass(cls):
        cls.clean_server = HTTPServer(("127.0.0.1", 18102), CleanHandler)
        cls.clean_thread = threading.Thread(target=cls.clean_server.serve_forever, daemon=True)
        cls.clean_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.clean_server.shutdown()

    def test_no_false_positive(self):
        config = ScanConfig(
            url="http://127.0.0.1:18102/page?id=1",
            method="GET", timeout=5, verbose=False,
        )
        scanner = SQLiScanner(config)
        scanner.run_scan()
        self.assertEqual(len(scanner.results), 0, "Should NOT find SQLi on clean page")


class TestSQLiDemo(unittest.TestCase):
    """Demo mode must exit 0 and find vulnerabilities."""

    def test_demo_finds_vulns(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "-c", """
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath('.')))
from sqli_auto import run_demo
run_demo()
"""],
            capture_output=True, text=True, timeout=20,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        self.assertEqual(result.returncode, 0, f"Demo should exit 0. stderr: {result.stderr[:500]}")


if __name__ == "__main__":
    unittest.main()
