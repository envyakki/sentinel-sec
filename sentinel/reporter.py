"""
Report generator for SentinelSec scans (JSON, Markdown, ANSI Terminal).
"""

import json
from sentinel.core import ScanReport

class Reporter:
    @staticmethod
    def to_json(report: ScanReport, indent: int = 2) -> str:
        data = {
            "target": report.target_path,
            "security_score": report.security_score,
            "grade": report.security_grade,
            "summary": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "total": len(report.findings),
                "files_scanned": report.scanned_files,
                "lines_scanned": report.scanned_lines
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "line": f.line_number,
                    "snippet": f.snippet,
                    "description": f.description,
                    "remediation": f.remediation,
                    "cwe": f.cwe,
                    "owasp": f.owasp
                }
                for f in report.findings
            ]
        }
        return json.dumps(data, indent=indent)

    @staticmethod
    def to_markdown(report: ScanReport) -> str:
        md = f"""# SentinelSec Security Audit Report

**Target:** `{report.target_path}`  
**Security Score:** `{report.security_score}/100` (Grade: **{report.security_grade}**)  
**Scanned Files:** `{report.scanned_files}` | **Total Lines:** `{report.scanned_lines}`

---

### Vulnerability Breakdown
* **Critical:** {report.critical_count}
* **High:** {report.high_count}
* **Medium:** {report.medium_count}
* **Low:** {report.low_count}

---

### Detailed Findings

"""
        if not report.findings:
            md += "**No vulnerabilities detected! Codebase meets clean security baseline.**\n"
            return md

        for idx, f in enumerate(report.findings, 1):
            md += f"""#### {idx}. [{f.severity}] {f.title} (`{f.rule_id}`)
* **Line:** `{f.line_number}`
* **Snippet:** `{f.snippet}`
* **Description:** {f.description}
* **Remediation:** {f.remediation}
* **Standard:** `{f.cwe}` | `{f.owasp}`

---
"""
        return md

    @staticmethod
    def print_terminal(report: ScanReport):
        colors = {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[93m",
            "MEDIUM": "\033[94m",
            "LOW": "\033[96m",
            "RESET": "\033[0m",
            "BOLD": "\033[1m"
        }
        
        print("\n" + "="*60)
        print("            [SENTINEL-SEC SECURITY AUDIT]")
        print("="*60)
        print(f" Target: {report.target_path}")
        print(f" Files Scanned: {report.scanned_files} | Total Lines: {report.scanned_lines}")
        print(f" Security Score: {report.security_score}/100 (Grade: {colors['BOLD']}{report.security_grade}{colors['RESET']})")
        print(f" Findings: Critical: {report.critical_count} | High: {report.high_count} | Medium: {report.medium_count}")
        print("-"*60)
        
        if not report.findings:
            print("\033[92m[PASS] All checks passed. Zero security vulnerabilities found!\033[0m\n")
            return
            
        for f in report.findings:
            c = colors.get(f.severity, colors["RESET"])
            print(f"[{c}{f.severity:<8}{colors['RESET']}] Line {f.line_number}: {f.title}")
            print(f"  Snippet: {f.snippet}")
            print(f"  Fix:     {f.remediation}")
            print()
