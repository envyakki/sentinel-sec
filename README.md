<div align="center">

# 🛡️ SentinelSec

**Automated Static Application Security Testing (SAST) & Vulnerability Auditing Engine**

[![Version: 1.1.0](https://img.shields.io/badge/Version-1.1.0_Hybrid_AST-00F5D4?style=for-the-badge)](https://github.com/envyakki/sentinel-sec)
[![Python Version](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Mapped-FF007A?style=for-the-badge)](https://owasp.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-7928CA?style=for-the-badge)](LICENSE)

<br/>

`SentinelSec` is a zero-dependency static application security testing (SAST) engine. Unlike naive line-by-line regex linters, SentinelSec employs a **dual-pass hybrid architecture**: fast regex heuristics for multi-language secret scanning combined with an **Abstract Syntax Tree (AST) Semantic & Taint Analysis Engine** to prevent multi-line, variable indirection, and syntax obfuscation evasions.

[Live Web Dashboard](https://envyakki.github.io/sentinel-sec/) • [Report Bug](https://github.com/envyakki/sentinel-sec/issues) • [Request Feature](https://github.com/envyakki/sentinel-sec/issues)

</div>

---

### 🧠 Why SentinelSec? (Regex vs AST Semantic Engine)

Most basic linters evaluate code line-by-line using regular expressions. In real-world codebases, vulnerabilities easily bypass single-line regex rules through argument splitting or variable indirection. 

SentinelSec resolves this by parsing the Python syntax tree:

| Evasion Vector | Naive Line Regex (Tier 1) | SentinelSec Hybrid AST (v1.1.0) |
| :--- | :---: | :---: |
| **Multi-line Subprocess:** `subprocess.run(\n cmd,\n shell=True)` | ❌ Bypassed | ✅ **Caught (AST Call Keyword)** |
| **Non-SELECT SQL Injection:** `cursor.execute(f"DELETE...")` | ❌ Bypassed | ✅ **Caught (AST JoinedStr)** |
| **Variable Indirection (Taint):** `query = f"..."; execute(query)` | ❌ Bypassed | ✅ **Caught (AST Taint Propagation)** |
| **String Split Keys:** `"AKIA" + "IOSFODNN..."` | ❌ Bypassed | ✅ **Caught (AST Constant Evaluation)** |
| **Session SSL Bypass:** `s = requests.Session(); s.verify = False` | ❌ Bypassed | ✅ **Caught (AST Attribute Mutation)** |

---

### ⚡ Key Capabilities

* 🔑 **Secret & Credential Discovery:** Identifies exposed AWS tokens, GitHub PATs, RSA private keys, and high-entropy API secrets.
* 💉 **Injection Detection:** Catches raw SQL query formatting (`CWE-89`), dynamic command execution via `subprocess(shell=True)` (`CWE-78`), and arbitrary `eval()` / `exec()` calls across multi-line blocks.
* 🔒 **Cryptographic Hygiene:** Flags broken hashing algorithms (MD5 / SHA-1) and weak PRNG usage for security tokens (`CWE-328`, `CWE-338`).
* ⚙️ **Config & Misconfigurations:** Detects production `DEBUG=True` flags and disabled SSL verification (`verify=False`).
* 📊 **Multi-Format Reporting:** Generates instant audit logs in Terminal ANSI, structured JSON, and Markdown summaries.
* 🌐 **Interactive Web GUI:** Includes a standalone, client-side cybersecurity dashboard for browser-based scanning with adversarial preset tests.

---

### 🚀 Quickstart & Installation

```bash
# Clone the repository
git clone https://github.com/envyakki/sentinel-sec.git
cd sentinel-sec

# Run tests to verify the scanner (12 unit tests covering Regex + AST)
python -m unittest discover tests/
```

---

### 💻 CLI Usage

#### 1. Scan Current Directory
```bash
python cli.py .
```

#### 2. Scan a Specific File & Output Terminal Report
```bash
python cli.py samples/vulnerable_app.py --format terminal
```

#### 3. Output Markdown Report for Security Audits
```bash
python cli.py samples/vulnerable_app.py --format markdown --output security_report.md
```

#### 4. Output Structured JSON for CI/CD Pipelines
```bash
python cli.py ./src --format json
```

---

### 🎯 OWASP & CWE Mapping Catalog

| Rule ID | Vulnerability | Severity | CWE Standard | OWASP Top 10 | Engine |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-001` | AWS Access Key Exposure | **CRITICAL** | CWE-798 | A07:2021 Identification Failures | Regex + AST Concatenation |
| `SEC-002` | GitHub Personal Token Leak | **CRITICAL** | CWE-798 | A07:2021 Identification Failures | Regex Heuristic |
| `INJ-001` | SQL Injection (Raw Formatting & Taint) | **CRITICAL** | CWE-89 | A03:2021 Injection | AST Semantic Taint |
| `INJ-002` | OS Command Execution (`shell=True`) | **CRITICAL** | CWE-78 | A03:2021 Injection | AST Multi-line Visitor |
| `INJ-003` | Dynamic Code Evaluation (`eval`/`exec`) | **HIGH** | CWE-95 | A03:2021 Injection | AST Call Inspection |
| `CRY-001` | Broken Hash Function (MD5 / SHA-1) | **MEDIUM** | CWE-328 | A02:2021 Cryptographic Failures | AST Call Inspection |
| `CFG-001` | Active Debug Mode in Production | **HIGH** | CWE-489 | A05:2021 Security Misconfiguration | AST Assignment Node |
| `CFG-002` | Disabled SSL Certificate Verification | **HIGH** | CWE-295 | A05:2021 Security Misconfiguration | AST Kwarg & Attribute |

---

### 📂 Repository Structure

```text
sentinel-sec/
├── sentinel/
│   ├── __init__.py         # Package entry (v1.1.0)
│   ├── ast_scanner.py      # AST Semantic & Taint analysis engine
│   ├── core.py             # Scanning orchestrator & scoring matrix
│   ├── rules.py            # Security patterns mapped to OWASP & CWE
│   └── reporter.py         # JSON, Markdown & Terminal formatters
├── web/
│   └── index.html          # Interactive Cyberpunk Web Dashboard (GitHub Pages)
├── samples/
│   ├── vulnerable_app.py   # Antipattern test samples
│   └── secure_app.py       # Remediated clean code reference
├── tests/
│   └── test_scanner.py     # Automated unit test suite (12 test cases)
├── cli.py                  # CLI executable entrypoint
├── LICENSE                 # MIT License
└── README.md               # Documentation
```

---

### 👤 Author
Engineered with precision by **[@envyakki](https://github.com/envyakki)**.
