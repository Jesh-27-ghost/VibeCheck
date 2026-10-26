"""Deliberately vulnerable web application sample for VibeCheck testing.

THIS FILE IS INTENTIONALLY INSECURE - for demonstration and test purposes only.
DO NOT deploy this code. All credentials are fake test values.
"""

import os

# DELIBERATELY INSECURE: Hardcoded API key (test value only)
API_KEY = "sk-test-abc123xyz456verylongfakekey9876"

# DELIBERATELY INSECURE: Hardcoded password (test value only)
DB_PASSWORD = "super_secret_password_123"

# DELIBERATELY INSECURE: Hardcoded database URL with credentials (test value)
DATABASE_URL = "postgresql://admin:mypassword123@localhost:5432/mydb"

# DELIBERATELY INSECURE: JWT secret hardcoded (test value only)
jwt_secret = "my_super_secret_jwt_key_do_not_share"

DEBUG = True


def get_user(user_id):
    """DELIBERATELY INSECURE: SQL injection vulnerability."""
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # BAD: String formatting with user input
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def process_request(request_data):
    """DELIBERATELY INSECURE: eval() with user input."""
    result = eval(request_data["expression"])
    return result


app_config = {
    "cors_origins": "*",
    "debug": True,
    "secret_key": API_KEY,
}
