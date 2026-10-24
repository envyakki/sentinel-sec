#!/usr/bin/env python3
"""
SentinelSec Command Line Interface (CLI)
"""

import sys
import argparse
from sentinel.core import Scanner
from sentinel.reporter import Reporter

def main():
    parser = argparse.ArgumentParser(
        description="SentinelSec: Automated Static Application Security Testing (SAST)"
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to file or directory to scan (default: current dir)")
    parser.add_argument("--format", choices=["terminal", "json", "markdown"], default="terminal", help="Output format")
    parser.add_argument("--output", help="Save report to specified file path")

    args = parser.parse_args()

    scanner = Scanner()
    report = scanner.scan_path(args.path)

    if args.format == "terminal":
        Reporter.print_terminal(report)
    elif args.format == "json":
        res = Reporter.to_json(report)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(res)
            print(f"[+] JSON report saved to: {args.output}")
        else:
            print(res)
    elif args.format == "markdown":
        res = Reporter.to_markdown(report)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(res)
            print(f"[+] Markdown report saved to: {args.output}")
        else:
            print(res)

    # Return exit code 1 if critical vulnerabilities exist
    sys.exit(1 if report.critical_count > 0 else 0)

if __name__ == "__main__":
    main()
