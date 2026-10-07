"""
otp_service.py
--------------
Shared OTP helpers used by the signup and create_admin routes in app.py.

Provides two functions:
  - request_otp(email)       : full "send OTP" flow (check, generate/reuse, send).
  - verify_otp(email, code)  : full "verify OTP" flow (expiry, attempt limit).

This module is intentionally kept free of Flask imports to avoid circular
imports.  DB_PATH is imported from db.py (the single source of truth);
SMTP credentials are read from environment variables at call time.
"""

import os
import secrets
import sqlite3
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from db import DB_PATH


# ── Configuration ─────────────────────────────────────────────────────────────

_OTP_TTL_MINUTES = 5
_OTP_MAX_ATTEMPTS = 5


# ── Internal: email sender (local copy avoids circular import from app.py) ────

def _send_otp_email(target_email: str, otp_code: str) -> bool:
    """Send *otp_code* to *target_email* via Gmail SMTP (or mock to console)."""
    smtp_email = os.environ.get("SMTP_EMAIL")
    smtp_password = os.environ.get("SMTP_PASSWORD")

    if not smtp_email or not smtp_password:
        print(f"\n[WARNING] SMTP credentials not set (SMTP_EMAIL/SMTP_PASSWORD). Falling back to console.")
        print(f"[MOCK EMAIL SERVICE] Sending OTP to {target_email}: {otp_code}\n")
        return True

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_email
        msg["To"] = target_email
        msg["Subject"] = "QA Automation Engine - Verification Code"

        body = f"Your verification code is: {otp_code}\nThis code will expire in 5 minutes."
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.sendmail(smtp_email, target_email, msg.as_string())
        server.quit()
        print(f"[SMTP] Successfully sent OTP verification email to {target_email}")
        return True
    except Exception as e:
        print(f"[SMTP ERROR] Failed to send email to {target_email}: {e}")
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def request_otp(email: str) -> tuple[bool, str]:
    """Full "send OTP" flow.

    Checks that *email* is not already registered in the users table, then
    reuses a non-expired OTP from otp_store when one exists, otherwise
    generates and stores a fresh 6-digit code, and finally sends it.

    Returns:
        (True,  success_message)  on success.
        (False, error_message)    on any failure.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            # 1. Reject already-registered e-mails
            user_exists = conn.execute(
                "SELECT 1 FROM users WHERE email = ?", (email,)
            ).fetchone()
            if user_exists:
                return False, "Email address is already registered."

            # 2. Check for a still-valid OTP
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT otp_code, created_at FROM otp_store WHERE email = ?",
                (email,),
            ).fetchone()

            now = datetime.now(timezone.utc)
            otp_code = None

            if row:
                try:
                    created_at = datetime.fromisoformat(row["created_at"])
                    if now - created_at < timedelta(minutes=_OTP_TTL_MINUTES):
                        otp_code = row["otp_code"]
                except Exception:
                    pass

            # 3. Generate a new OTP if none is reusable
            if not otp_code:
                otp_code = f"{secrets.randbelow(900000) + 100000}"
                conn.execute(
                    "INSERT OR REPLACE INTO otp_store (email, otp_code, created_at, attempts)"
                    " VALUES (?, ?, ?, 0)",
                    (email, otp_code, now.isoformat()),
                )
                conn.commit()

        # 4. Send – outside the DB context so we don't hold a lock during SMTP
        if _send_otp_email(email, otp_code):
            return True, "OTP sent successfully! Please check your email."
        return False, "Failed to send OTP verification email. Please try again later."

    except Exception as exc:
        return False, f"Database error: {exc}"


def verify_otp(email: str, otp_input: str) -> tuple[bool, str, str | None]:
    """Full "verify OTP" flow.

    Enforces a 5-minute expiry window and invalidates the OTP after
    ``_OTP_MAX_ATTEMPTS`` (5) failed attempts.

    Returns:
        (True,  "",            None)           on successful verification.
        (False, error_message, None)           on any failure / expired / locked.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT otp_code, created_at, attempts FROM otp_store WHERE email = ?",
                (email,),
            ).fetchone()

            if not row:
                return False, "No active OTP request found. Please request a new one.", None

            attempts = row["attempts"] if "attempts" in row.keys() else 0

            # 1. Locked out — too many bad attempts
            if attempts >= _OTP_MAX_ATTEMPTS:
                conn.execute("DELETE FROM otp_store WHERE email = ?", (email,))
                conn.commit()
                return (
                    False,
                    "Too many failed attempts. This OTP has been invalidated; please request a new one.",
                    None,
                )

            # 2. Correct code — check expiry
            if row["otp_code"] == otp_input:
                now = datetime.now(timezone.utc)
                created_at = datetime.fromisoformat(row["created_at"])
                if now - created_at < timedelta(minutes=_OTP_TTL_MINUTES):
                    return True, "", None
                return False, "OTP expired. Please request a new one.", None

            # 3. Wrong code — increment attempt counter
            conn.execute(
                "UPDATE otp_store SET attempts = attempts + 1 WHERE email = ?",
                (email,),
            )
            conn.commit()
            remaining = (_OTP_MAX_ATTEMPTS - 1) - attempts
            return False, f"Invalid OTP. {remaining} attempt(s) remaining.", None

    except Exception as exc:
        return False, f"Database error: {exc}", None
