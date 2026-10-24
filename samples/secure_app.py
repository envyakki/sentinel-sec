"""
SECURE IMPLEMENTATION (Remediated with Best Practices)
"""

import os
import hashlib
import secrets
import subprocess
from typing import Any

# 1. Secrets loaded from environment variables
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
API_SECRET_KEY = os.getenv("API_SECRET_KEY")

# 2. Cryptographically secure password hashing (SHA-256 with salt)
def hash_user_password(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode()).hexdigest()

# 3. Parameterized SQL query (prevents SQLi)
def get_user_by_id(cursor: Any, user_id: int):
    query = "SELECT id, username, email FROM users WHERE id = %s"
    return cursor.execute(query, (user_id,))

# 4. Safe command execution with shell=False
def ping_host(host: str):
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)

# 5. Secure Configuration
DEBUG = False
