<div align="center">

# 🛡️ SentinelSec

**Automated Static Application Security Testing (SAST) & Vulnerability Auditing Engine**

[![CI Status](https://img.shields.io/badge/Build-Passing-00F5D4?style=for-the-badge&logo=githubactions&logoColor=black)](https://github.com/envyakki/sentinel-sec/actions)
[![Python Version](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Mapped-FF007A?style=for-the-badge)](https://owasp.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-7928CA?style=for-the-badge)](LICENSE)

<br/>

`SentinelSec` is a lightweight, zero-dependency static code analysis tool designed to audit source code for high-risk security vulnerabilities, hardcoded secrets, injection flaws, and insecure cryptographic implementations before code reaches production.

[Live Web Dashboard](https://envyakki.github.io/sentinel-sec/) • [Report Bug](https://github.com/envyakki/sentinel-sec/issues) • [Request Feature](https://github.com/envyakki/sentinel-sec/issues)

</div>

---

### ⚡ Key Capabilities

* 🔑 **Secret & Credential Discovery:** Identifies exposed AWS tokens, GitHub PATs, RSA private keys, and high-entropy API secrets.
* 💉 **Injection Detection:** Catches raw SQL query formatting (`CWE-89`), dynamic command execution via `subprocess(shell=True)` (`CWE-78`), and arbitrary `eval()` / `exec()` calls.
* 🔒 **Cryptographic Hygiene:** Flags broken hashing algorithms (MD5 / SHA-1) and weak PRNG usage for security tokens (`CWE-328`, `CWE-338`).
* ⚙️ **Config & Misconfigurations:** Detects production `DEBUG=True` flags and disabled SSL verification (`verify=False`).
* 📊 **Multi-Format Reporting:** Generates instant audit logs in Terminal ANSI, structured JSON, and Markdown summaries.
* 🌐 **Interactive Web GUI:** Includes a standalone, client-side cybersecurity dashboard for browser-based scanning.

---

### 🚀 Quickstart & Installation

```bash
# Clone the repository
git clone https://github.com/envyakki/sentinel-sec.git
cd sentinel-sec

# Run tests to verify the scanner
python -m unittest discover tests/
```

---

### 💻 CLI Usage

#### 1. Scan Current Directory
```bash
python cli.py .
```

#### 2. Scan a Specific File & Output Markdown Report
```bash
python cli.py samples/vulnerable_app.py --format markdown --output security_report.md
```

#### 3. Output Structured JSON for CI/CD Pipeline
```bash
python cli.py ./src --format json
```

---

### 🎯 OWASP & CWE Mapping Catalog

| Rule ID | Vulnerability | Severity | CWE Standard | OWASP Top 10 |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-001` | AWS Access Key Exposure | **CRITICAL** | CWE-798 | A07:2021 Identification Failures |
| `SEC-002` | GitHub Personal Token Leak | **CRITICAL** | CWE-798 | A07:2021 Identification Failures |
| `INJ-001` | SQL Injection (Raw Formatting) | **CRITICAL** | CWE-89 | A03:2021 Injection |
| `INJ-002` | OS Command Execution (`shell=True`) | **CRITICAL** | CWE-78 | A03:2021 Injection |
| `CRY-001` | Broken Hash Function (MD5) | **MEDIUM** | CWE-328 | A02:2021 Cryptographic Failures |
| `CFG-001` | Active Debug Mode in Production | **HIGH** | CWE-489 | A05:2021 Security Misconfiguration |

---

### 📂 Repository Structure

```text
sentinel-sec/
├── sentinel/
│   ├── __init__.py         # Package entry
│   ├── core.py             # Scanning orchestrator & scoring matrix
│   ├── rules.py            # Security patterns mapped to OWASP & CWE
│   └── reporter.py         # JSON, Markdown & Terminal formatters
├── web/
│   └── index.html          # Interactive Cyberpunk Web Dashboard (GitHub Pages)
├── samples/
│   ├── vulnerable_app.py   # Antipattern test samples
│   └── secure_app.py       # Remediated clean code reference
├── tests/
│   └── test_scanner.py     # Automated unit test suite
├── .github/workflows/
│   └── ci.yml              # Automated GitHub Actions test runner
├── cli.py                  # CLI executable entrypoint
├── LICENSE                 # MIT License
└── README.md               # Documentation
```

---

### 🌐 Web Dashboard (GitHub Pages)

The repository includes a web dashboard in `web/index.html`. You can preview it locally:

```bash
# Start local preview
python -m http.server 8000 --directory web/
# Open http://localhost:8000 in your browser
```

---

### 👤 Author
Engineered with precision by **[@envyakki](https://github.com/envyakki)**.
