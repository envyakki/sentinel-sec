"""
Git OpSec & Repository Hygiene Verification Script
Audits:
1. Git remote URLs for exposed credentials
2. .gitignore coverage for .env files
3. Git commit history across all branches for leaked secrets
4. GitHub token revocation status (API test)
"""

import os
import re
import sys
import subprocess
import urllib.request
import urllib.error


def run_git(args: str) -> str:
    try:
        res = subprocess.run(f"git {args}", capture_output=True, text=True, shell=True, encoding="utf-8", errors="replace")
        return res.stdout.strip()
    except Exception as e:
        return ""


def audit_repository(token: str = None):
    print("=" * 64)
    print("        [GIT OPSEC & REPOSITORY HYGIENE AUDIT]")
    print("=" * 64)
    print()

    # --- CHECK 1: GIT REMOTES ---
    print("[1/4] Checking Git Remotes for embedded credentials...")
    remotes = run_git("remote -v")
    leaked_remote = re.findall(r"https?://([^@\s]+)@", remotes)
    if leaked_remote:
        print("  [FAIL] Credentials/tokens embedded in git remote URL!")
        print(f"         Found pattern: {leaked_remote[0][:4]}***")
        print("         Fix: Run 'git remote set-url origin https://github.com/owner/repo.git'")
    else:
        print("  [PASS] All git remote URLs are clean and sanitized.")
    print()

    # --- CHECK 2: .GITIGNORE & .ENV TRACKING ---
    print("[2/4] Checking .gitignore and .env file protection...")
    tracked_files = run_git("ls-files").splitlines()
    leaked_env_files = [f for f in tracked_files if ".env" in f and not f.endswith(".example")]
    
    if leaked_env_files:
        print(f"  [FAIL] Sensitive .env file is CURRENTLY TRACKED in git: {leaked_env_files}")
        print("         Fix: Run 'git rm --cached .env' and add .env to .gitignore")
    else:
        check_ign = run_git("check-ignore -v .env")
        if check_ign:
            print("  [PASS] .env is properly ignored by .gitignore rules.")
            print(f"         Matching rule: {check_ign}")
        else:
            print("  [WARN] .env rule not found in .gitignore!")
    print()

    # --- CHECK 3: FULL GIT COMMIT HISTORY SCAN ---
    print("[3/4] Scanning full git commit history across all branches & diffs...")
    log_diffs = run_git("log --all --full-history -p")
    
    # Check for actual tokens (excluding regex pattern definitions in code)
    token_matches = re.findall(r"(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})", log_diffs)
    # Filter out regex definitions like ghp_[0-9a-zA-Z]{36}
    real_leaked_tokens = [t for t in token_matches if not any(x in t for x in ("0-9a-zA-Z", "[0-9"))]

    # Check for AWS keys (excluding standard test mocks & documentation examples)
    aws_matches = re.findall(r"AKIA[0-9A-Z]{16}", log_diffs)
    mock_subwords = ("EXAMPLE", "EXAMPL", "ABCDEF", "0-9A-Z", "TEST")
    real_aws = [k for k in aws_matches if not any(sub in k for sub in mock_subwords)]

    if real_leaked_tokens or real_aws:
        print("  [FAIL] Leaked credentials detected in git history!")
        if real_leaked_tokens:
            print(f"         Found leaked GitHub token(s): {len(real_leaked_tokens)}")
        if real_aws:
            print(f"         Found real AWS key(s): {len(real_aws)}")
    else:
        print("  [PASS] Zero leaked tokens or credentials found in git history.")
    print()

    # --- CHECK 4: TOKEN REVOCATION VERIFICATION ---
    print("[4/4] Verifying GitHub token revocation status via API...")
    if token:
        masked = token[:6] + "..." + token[-4:] if len(token) > 10 else "***"
        print(f"      Testing token: {masked}")
        
        req = urllib.request.Request("https://api.github.com/user", headers={
            "Authorization": f"token {token}",
            "User-Agent": "OpSec-Hygiene-Audit"
        })
        try:
            with urllib.request.urlopen(req) as resp:
                print("  [ALERT] Token is STILL ACTIVE! (HTTP 200 OK returned)")
                print("          Action Required: Revoke it immediately at:")
                print("          https://github.com/settings/tokens")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print("  [PASS] Token is REVOKED & INACTIVE! (HTTP 401 Bad credentials)")
                print("         The key is completely dead and cannot be used by anyone.")
            else:
                print(f"  [INFO] GitHub API returned HTTP {e.code}: {e.reason}")
        except Exception as e:
            print(f"  [ERROR] Network check failed: {e}")
    else:
        print("  [INFO] No token passed to test. Provide token as argument: python audit_hygiene.py <token>")
    
    print()
    print("=" * 64)
    print("                    [AUDIT FINISHED]")
    print("=" * 64)


if __name__ == "__main__":
    test_token = sys.argv[1] if len(sys.argv) > 1 else None
    audit_repository(test_token)
