"""
Core scanning engine for SentinelSec.
"""

import os
import re
from typing import List, Dict, Any
from sentinel.rules import SecurityRules, Finding

class ScanReport:
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.findings: List[Finding] = []
        self.scanned_files = 0
        self.scanned_lines = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def security_score(self) -> int:
        # 100 base score, penalties applied based on vulnerability severities
        penalty = (self.critical_count * 25) + (self.high_count * 15) + (self.medium_count * 5) + (self.low_count * 2)
        return max(0, 100 - penalty)

    @property
    def security_grade(self) -> str:
        s = self.security_score
        if s >= 95: return "A+"
        if s >= 85: return "A"
        if s >= 75: return "B"
        if s >= 60: return "C"
        if s >= 40: return "D"
        return "F"

class Scanner:
    def __init__(self, ignored_dirs: List[str] = None):
        self.ignored_dirs = ignored_dirs or [".git", "__pycache__", "venv", ".venv", "node_modules", "dist", "build"]

    def scan_code(self, source_code: str, file_name: str = "<inline>") -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        for line_idx, line in enumerate(lines, 1):
            # Skip empty lines or standard single-line comment blocks
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for rule in SecurityRules.PATTERNS:
                if re.search(rule["regex"], line):
                    snippet = stripped if len(stripped) <= 120 else stripped[:117] + "..."
                    findings.append(Finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        line_number=line_idx,
                        snippet=snippet,
                        description=rule["description"],
                        remediation=rule["remediation"],
                        cwe=rule["cwe"],
                        owasp=rule["owasp"]
                    ))
        return findings

    def scan_path(self, target_path: str) -> ScanReport:
        report = ScanReport(target_path)
        valid_extensions = (".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".json", ".yaml", ".yml")

        if os.path.isfile(target_path):
            self._scan_single_file(target_path, report)
            return report

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in self.ignored_dirs]
            for file in files:
                if file.endswith(valid_extensions):
                    file_path = os.path.join(root, file)
                    self._scan_single_file(file_path, report)

        return report

    def _scan_single_file(self, file_path: str, report: ScanReport):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                file_findings = self.scan_code(content, file_name=file_path)
                report.findings.extend(file_findings)
                report.scanned_files += 1
                report.scanned_lines += len(content.splitlines())
        except Exception as e:
            pass
