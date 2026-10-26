"""Corrected version of the vulnerable web application sample.

All hardcoded secrets have been removed and replaced with environment variable
references. SQL injection and eval() issues have been fixed.
"""

import json
import os
import sqlite3

# FIXED: Load secrets from environment variables only
API_KEY = os.environ.get("API_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DATABASE_URL = os.environ.get("DATABASE_URL")
jwt_secret = os.environ.get("JWT_SECRET")

# FIXED: Debug mode controlled by environment variable
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"


def get_user(user_id: int):
    """FIXED: Parameterized query prevents SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # GOOD: Parameterized query — user_id is passed as a parameter, not interpolated
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def process_request(request_data: dict):
    """FIXED: Parses JSON safely instead of using eval()."""
    # GOOD: Use json.loads for structured data instead of eval()
    expression = request_data.get("expression", "")
    # Perform safe processing on known structure rather than arbitrary evaluation
    allowed_keys = {"op", "value"}
    if not isinstance(expression, dict) or not expression.keys() <= allowed_keys:
        raise ValueError("Invalid expression format")
    return expression


app_config = {
    # FIXED: Explicit CORS origin allowlist
    "cors_origins": ["https://yourdomain.com"],
    "debug": DEBUG,
    "secret_key": API_KEY,
}
