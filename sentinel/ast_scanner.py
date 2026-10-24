"""
AST (Abstract Syntax Tree) Semantic & Taint Analysis Engine for SentinelSec.
Provides deep structural code inspection to prevent multi-line, variable
indirection, and syntax obfuscation evasions.
"""

import ast
from typing import List, Dict, Tuple
from sentinel.rules import Finding


class ASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self, raw_lines: List[str]):
        self.raw_lines = raw_lines
        self.findings: List[Finding] = []
        # Taint tracking: maps variable name to (assignment_line, reason)
        self.tainted_vars: Dict[str, Tuple[int, str]] = {}

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.raw_lines):
            line = self.raw_lines[lineno - 1].strip()
            return line if len(line) <= 120 else line[:117] + "..."
        return "<ast-node>"

    def visit_Assign(self, node: ast.Assign):
        # 1. Track DEBUG = True assignments
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if var_name.upper() == "DEBUG":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        self.findings.append(Finding(
                            rule_id="CFG-001",
                            title="Production Debug Mode Enabled (AST Semantic)",
                            severity="HIGH",
                            line_number=node.lineno,
                            snippet=self._get_snippet(node.lineno),
                            description="Production DEBUG mode assigned as True, exposing internal state and traces.",
                            remediation="Set DEBUG to False in production environments.",
                            cwe="CWE-489: Active Debug Code in Production",
                            owasp="A05:2021-Security Misconfiguration"
                        ))

                # 2. String Concatenation Secret Evasion (e.g. 'AKIA' + '...')
                if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                    left_val = getattr(node.value.left, "value", None)
                    right_val = getattr(node.value.right, "value", None)
                    if isinstance(left_val, str) and isinstance(right_val, str):
                        combined = left_val + right_val
                        if "AKIA" in combined and len(combined) >= 20:
                            self.findings.append(Finding(
                                rule_id="SEC-001",
                                title="Concatenated AWS Access Key ID Detected (AST Semantic)",
                                severity="CRITICAL",
                                line_number=node.lineno,
                                snippet=self._get_snippet(node.lineno),
                                description="Hardcoded AWS key reconstructed via string literal concatenation.",
                                remediation="Store AWS credentials in environment variables or IAM roles.",
                                cwe="CWE-798: Use of Hard-coded Credentials",
                                owasp="A07:2021-Identification and Authentication Failures"
                            ))

                # 3. Taint Tracking: Record variables holding dynamically formatted queries
                if isinstance(node.value, ast.JoinedStr):
                    self.tainted_vars[var_name] = (node.lineno, "f-string formatted expression")
                elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Mod):
                    self.tainted_vars[var_name] = (node.lineno, "%-formatted string expression")
                elif isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "format":
                        self.tainted_vars[var_name] = (node.lineno, ".format() string expression")

        # 4. Attribute mutations: session.verify = False
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr == "verify" and isinstance(node.value, ast.Constant) and node.value.value is False:
                    self.findings.append(Finding(
                        rule_id="CFG-002",
                        title="Disabled SSL Certificate Verification on Session (AST Semantic)",
                        severity="HIGH",
                        line_number=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        description="Session SSL verification disabled via attribute mutation (verify=False).",
                        remediation="Ensure SSL certificate verification is enabled (verify=True).",
                        cwe="CWE-295: Improper Certificate Validation",
                        owasp="A05:2021-Security Misconfiguration"
                    ))

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        attr_name = ""

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{attr_name}"
            elif isinstance(node.func.value, ast.Attribute):
                func_name = f"{getattr(node.func.value.value, 'id', '')}.{node.func.value.attr}.{attr_name}"

        # 1. Subprocess shell=True (multi-line safe)
        is_subprocess_call = (
            func_name.startswith("subprocess.") or
            attr_name in ("Popen", "run", "call", "check_call", "check_output")
        )
        if is_subprocess_call:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(Finding(
                        rule_id="INJ-002",
                        title="Arbitrary Command Execution shell=True (AST Semantic)",
                        severity="CRITICAL",
                        line_number=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        description="Subprocess invocation with shell=True detected across call arguments.",
                        remediation="Pass command arguments as a list with shell=False, avoiding the system shell.",
                        cwe="CWE-78: OS Command Injection",
                        owasp="A03:2021-Injection"
                    ))

        # 2. SQL Injection in execute() calls (covers SELECT, INSERT, UPDATE, DELETE, DROP, etc.)
        if attr_name == "execute" or func_name.endswith(".execute"):
            if node.args:
                first_arg = node.args[0]
                # Direct f-string, % format, or .format()
                is_direct_format = (
                    isinstance(first_arg, ast.JoinedStr) or
                    (isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod)) or
                    (isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format")
                )
                if is_direct_format:
                    self.findings.append(Finding(
                        rule_id="INJ-001",
                        title="SQL Injection via Dynamic String Formatting (AST Semantic)",
                        severity="CRITICAL",
                        line_number=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        description="SQL execute statement directly formats dynamic variables into the query structure.",
                        remediation="Use parameterized queries with prepared placeholders (?, %s, or :param).",
                        cwe="CWE-89: SQL Injection",
                        owasp="A03:2021-Injection"
                    ))
                # Taint tracking: Variable indirection (e.g. query = f"..."; execute(query))
                elif isinstance(first_arg, ast.Name) and first_arg.id in self.tainted_vars:
                    taint_line, taint_reason = self.tainted_vars[first_arg.id]
                    self.findings.append(Finding(
                        rule_id="INJ-001",
                        title=f"SQL Injection via Tainted Variable '{first_arg.id}' (AST Semantic)",
                        severity="CRITICAL",
                        line_number=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        description=f"Query variable '{first_arg.id}' was tainted at line {taint_line} using {taint_reason}.",
                        remediation="Pass unformatted SQL string with query parameters in execute(query, params).",
                        cwe="CWE-89: SQL Injection",
                        owasp="A03:2021-Injection"
                    ))

        # 3. Dynamic Code Execution: eval() or exec()
        if func_name in ("eval", "exec") or attr_name in ("eval", "exec"):
            self.findings.append(Finding(
                rule_id="INJ-003",
                title="Dynamic Code Evaluation (AST Semantic)",
                severity="HIGH",
                line_number=node.lineno,
                snippet=self._get_snippet(node.lineno),
                description=f"Direct invocation of dangerous '{func_name or attr_name}' function.",
                remediation="Refactor logic using ast.literal_eval() or safe dictionary dispatching.",
                cwe="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
                owasp="A03:2021-Injection"
            ))

        # 4. Weak Cryptographic Hash: hashlib.md5 / hashlib.sha1
        if func_name.startswith("hashlib.") or (attr_name in ("md5", "sha1") and "hashlib" in func_name):
            if attr_name in ("md5", "sha1"):
                self.findings.append(Finding(
                    rule_id="CRY-001",
                    title=f"Broken / Weak Cryptographic Hash ({attr_name.upper()}) (AST Semantic)",
                    severity="MEDIUM",
                    line_number=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    description=f"Invocation of collision-vulnerable hash algorithm '{attr_name}'.",
                    remediation="Migrate to SHA-256 / SHA-3 for integrity or bcrypt/argon2 for password hashing.",
                    cwe="CWE-328: Use of Weak Hash",
                    owasp="A02:2021-Cryptographic Failures"
                ))

        # 5. SSL Verification Bypass in requests: verify=False across arguments
        if func_name.startswith("requests.") or attr_name in ("get", "post", "put", "delete", "patch", "request"):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.findings.append(Finding(
                        rule_id="CFG-002",
                        title="Disabled SSL Certificate Verification (AST Semantic)",
                        severity="HIGH",
                        line_number=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        description="HTTP request made with SSL verification explicitly disabled (verify=False).",
                        remediation="Enable SSL verification (verify=True) to prevent MITM tampering.",
                        cwe="CWE-295: Improper Certificate Validation",
                        owasp="A05:2021-Security Misconfiguration"
                    ))

        self.generic_visit(node)


class ASTScanner:
    """Orchestrates AST parsing and analysis on Python source files."""

    @staticmethod
    def analyze(source_code: str) -> List[Finding]:
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            # If not valid Python, skip AST and allow regex scanner to process
            return []

        lines = source_code.splitlines()
        visitor = ASTSecurityVisitor(raw_lines=lines)
        visitor.visit(tree)
        return visitor.findings
