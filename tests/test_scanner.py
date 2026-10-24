"""
Automated Unit Test Suite for SentinelSec v1.1.0
Covers both Regex pattern detection and AST Semantic / Taint analysis.
"""

import unittest
from sentinel.core import Scanner

class TestSentinelScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner()

    # --- REGEX BASELINE TESTS ---
    def test_detect_aws_secret(self):
        code = 'AWS_KEY = "AKIA1234567890ABCDEF"'
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "SEC-001" for f in findings))

    def test_detect_sql_injection(self):
        code = 'cursor.execute(f"SELECT * FROM accounts WHERE id = {acc_id}")'
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "INJ-001" for f in findings))

    def test_detect_command_injection(self):
        code = 'subprocess.Popen(user_cmd, shell=True)'
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "INJ-002" for f in findings))

    def test_detect_weak_crypto_md5(self):
        code = 'token_hash = hashlib.md5(data.encode())'
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "CRY-001" for f in findings))

    def test_clean_code_zero_findings(self):
        code = """
import os
import hashlib

def safe_query(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
        findings = self.scanner.scan_code(code)
        self.assertEqual(len(findings), 0)

    def test_security_score_calculation(self):
        report = self.scanner.scan_path("samples/secure_app.py")
        self.assertGreaterEqual(report.security_score, 90)

    # --- AST SEMANTIC & TAINT ANALYSIS TESTS (v1.1.0) ---
    def test_multiline_subprocess_shell_true(self):
        code = """
subprocess.run(
    cmd,
    shell=True
)
"""
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "INJ-002" for f in findings))

    def test_multiline_sql_injection(self):
        code = """
cursor.execute(
    f"SELECT * FROM users WHERE username = '{user_input}'"
)
"""
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "INJ-001" for f in findings))

    def test_sql_delete_update_injection(self):
        code = 'cursor.execute(f"DELETE FROM accounts WHERE id = {acc_id}")'
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "INJ-001" for f in findings))

    def test_tainted_variable_sql_injection(self):
        code = """
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "INJ-001" for f in findings))

    def test_session_ssl_verification_bypass(self):
        code = """
s = requests.Session()
s.verify = False
"""
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "CFG-002" for f in findings))

    def test_concatenated_aws_key(self):
        code = 'aws_key = "AKIA" + "IOSFODNN7EXAMPLE"'
        findings = self.scanner.scan_code(code)
        self.assertTrue(any(f.rule_id == "SEC-001" for f in findings))


if __name__ == "__main__":
    unittest.main()
