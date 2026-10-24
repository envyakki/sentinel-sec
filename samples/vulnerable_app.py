"""
VULNERABLE SAMPLE CODE (For Testing SentinelSec)
Do NOT use in production!
"""

import os
import hashlib
import random
import subprocess

# 1. Hardcoded Secret (SEC-001 / SEC-004)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
API_SECRET_KEY = "super_secret_production_key_12345"

# 2. Insecure Crypto (CRY-001)
def hash_user_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# 3. SQL Injection (INJ-001)
def get_user_by_id(cursor, user_id: str):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return cursor.execute(query)

# 4. Command Injection (INJ-002)
def ping_host(host: str):
    subprocess.call(f"ping -c 1 {host}", shell=True)

# 5. Insecure Configuration (CFG-001)
DEBUG = True
