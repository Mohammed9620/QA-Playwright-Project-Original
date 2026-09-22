"""
init_db.py
──────────
Recreates the users and otp_store database tables for the OTP security system.

Usage:
    python init_db.py
"""

import sqlite3
import os
from werkzeug.security import generate_password_hash

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

# ── Default seed admin ────────────────────────────────────────────────────────
DEFAULT_EMAIL = "admin@test.com"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "password123"
DEFAULT_ROLE = "admin"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Drop existing tables to refresh schema
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS otp_store")

        # Create users table
        cursor.execute("""
            CREATE TABLE users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                email    TEXT    UNIQUE NOT NULL,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL,
                role     TEXT    NOT NULL
            )
        """)

        # Create otp_store table
        cursor.execute("""
            CREATE TABLE otp_store (
                email      TEXT PRIMARY KEY,
                otp_code   TEXT NOT NULL,
                created_at TEXT NOT NULL,
                attempts   INTEGER DEFAULT 0
            )
        """)

        # Insert default admin user with securely hashed password
        hashed_password = generate_password_hash(DEFAULT_PASSWORD, method="scrypt")
        cursor.execute(
            "INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)",
            (DEFAULT_EMAIL, DEFAULT_USERNAME, hashed_password, DEFAULT_ROLE),
        )

        conn.commit()

    print("[init_db] Database reset ready at: " + DB_PATH)
    print(f"[init_db] Admin seeded: {DEFAULT_USERNAME} / {DEFAULT_EMAIL} (password securely hashed)")


if __name__ == "__main__":
    init_db()

