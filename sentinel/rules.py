"""
Detection rules and vulnerability definitions for SentinelSec.
Mapped against OWASP Top 10 and CWE standards.
"""

from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    line_number: int
    snippet: str
    description: str
    remediation: str
    cwe: str
    owasp: str

class SecurityRules:
    PATTERNS = [
        # --- SECRETS & CREDENTIALS ---
        {
            "id": "SEC-001",
            "title": "AWS Access Key ID Detected",
            "severity": "CRITICAL",
            "regex": r"(?i)(AKIA[0-9A-Z]{16})",
            "description": "Hardcoded AWS Access Key ID exposed in plaintext source code.",
            "remediation": "Move keys to environment variables or use AWS Secrets Manager / IAM Roles.",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures"
        },
        {
            "id": "SEC-002",
            "title": "GitHub Personal Access Token Detected",
            "severity": "CRITICAL",
            "regex": r"(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})",
            "description": "Hardcoded GitHub Personal Access Token found in source code.",
            "remediation": "Revoke the exposed token immediately and load credentials via environment variables.",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures"
        },
        {
            "id": "SEC-003",
            "title": "Private Key / Certificate Block Exposed",
            "severity": "CRITICAL",
            "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "description": "Cryptographic private key file or string embedded directly in source code.",
            "remediation": "Store private keys in a secure key vault or filesystem with restricted permissions.",
            "cwe": "CWE-312: Cleartext Storage of Sensitive Information",
            "owasp": "A02:2021-Cryptographic Failures"
        },
        {
            "id": "SEC-004",
            "title": "Generic Hardcoded Secret or API Key",
            "severity": "HIGH",
            "regex": r"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|password)\s*=\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
            "description": "Sensitive authentication secret assigned as a hardcoded string literal.",
            "remediation": "Utilize dotenv / environment configuration (.env) excluded from git tracking.",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures"
        },

        # --- INJECTION FLAWS ---
        {
            "id": "INJ-001",
            "title": "Potential SQL Injection (String Formatting in Query)",
            "severity": "CRITICAL",
            "regex": r"(?i)(execute|cursor\.execute)\s*\(\s*(f['\"].*SELECT.*\{|['\"].*SELECT.*['\"]\s*%)",
            "description": "Dynamic SQL query constructed using raw string formatting or f-strings.",
            "remediation": "Use parameterized queries (prepared statements) or an ORM (e.g. SQLAlchemy).",
            "cwe": "CWE-89: SQL Injection",
            "owasp": "A03:2021-Injection"
        },
        {
            "id": "INJ-002",
            "title": "Arbitrary Command Execution (Shell Injection)",
            "severity": "CRITICAL",
            "regex": r"(?i)(subprocess\.(Popen|run|call)\s*\(.*shell\s*=\s*True|os\.system\s*\()",
            "description": "System command executed through shell=True, enabling arbitrary shell injection.",
            "remediation": "Pass command arguments as a list with shell=False, or sanitize user input.",
            "cwe": "CWE-78: OS Command Injection",
            "owasp": "A03:2021-Injection"
        },
        {
            "id": "INJ-003",
            "title": "Dynamic Code Evaluation (eval / exec)",
            "severity": "HIGH",
            "regex": r"\b(eval|exec)\s*\([^)]+\)",
            "description": "Use of eval() or exec() allows execution of arbitrary untrusted Python expressions.",
            "remediation": "Refactor logic using ast.literal_eval() or safe dictionary mappings.",
            "cwe": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
            "owasp": "A03:2021-Injection"
        },

        # --- CRYPTOGRAPHIC & INSECURE FUNCTIONS ---
        {
            "id": "CRY-001",
            "title": "Broken / Weak Cryptographic Hash (MD5 / SHA-1)",
            "severity": "MEDIUM",
            "regex": r"\bhashlib\.(md5|sha1)\s*\(",
            "description": "MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks.",
            "remediation": "Migrate to SHA-256 / SHA-3 for hashing, or bcrypt/Argon2 for passwords.",
            "cwe": "CWE-328: Use of Weak Hash",
            "owasp": "A02:2021-Cryptographic Failures"
        },
        {
            "id": "CRY-002",
            "title": "Insecure Pseudo-Random Number Generator (PRNG) for Security",
            "severity": "MEDIUM",
            "regex": r"\brandom\.(random|choice|randint|sample)\s*\(.*(token|key|salt|password|auth)",
            "description": "Standard random module is deterministic and must not be used for security tokens.",
            "remediation": "Use python's 'secrets' module (e.g. secrets.token_urlsafe()) for cryptographic keys.",
            "cwe": "CWE-338: Use of Cryptographically Weak PRNG",
            "owasp": "A02:2021-Cryptographic Failures"
        },

        # --- INSECURE CONFIGURATIONS ---
        {
            "id": "CFG-001",
            "title": "Production Debug Mode Enabled",
            "severity": "HIGH",
            "regex": r"(?i)(DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True)",
            "description": "Debug mode enabled exposes interactive stack traces and system internals in production.",
            "remediation": "Set DEBUG to False in production environments and disable detailed debug pages.",
            "cwe": "CWE-489: Active Debug Code in Production",
            "owasp": "A05:2021-Security Misconfiguration"
        },
        {
            "id": "CFG-002",
            "title": "Disabled SSL Certificate Verification",
            "severity": "HIGH",
            "regex": r"(?i)requests\.(get|post|put|delete)\(.*verify\s*=\s*False",
            "description": "Disabled SSL verification allows attackers to execute Man-In-The-Middle (MITM) attacks.",
            "remediation": "Enable SSL verification (verify=True) and provide custom CA certificates if needed.",
            "cwe": "CWE-295: Improper Certificate Validation",
            "owasp": "A05:2021-Security Misconfiguration"
        }
    ]
