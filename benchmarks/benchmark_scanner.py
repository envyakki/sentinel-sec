"""
SentinelSec AST Performance Benchmark Suite
Measures lines-per-second throughput and AST traversal latency.
"""
import time
import os
from sentinel.core import scan_path

def run_benchmark():
    start = time.perf_counter()
    report = scan_path("samples/vulnerable_app.py")
    elapsed = time.perf_counter() - start
    print(f"[Benchmark] Completed in {elapsed*1000:.2f} ms")
    print(f"[Benchmark] Total Findings: {len(report.findings)}")
    print(f"[Benchmark] Health Score: {report.health_score}/100")

if __name__ == "__main__":
    run_benchmark()
