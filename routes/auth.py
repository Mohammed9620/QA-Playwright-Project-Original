"""
routes/auth.py
--------------
Flask Blueprint for all authentication-related routes:
  /login, /logout, /signup, /admin/create_admin
"""

import sqlite3
from datetime import datetime, timezone

from flask import (
    Blueprint, render_template, request,
    redirect, url_for, session,
)
from werkzeug.security import generate_password_hash, check_password_hash

from db import DB_PATH
from otp_service import request_otp, verify_otp as otp_service_verify


auth = Blueprint("auth", __name__)


# ── Login ──────────────────────────────────────────────────────────────────────

@auth.route("/login", methods=["GET", "POST"])
def login():
    """Login page. GET renders the form; POST validates credentials and role, then creates session."""
    if "username" in session:
        return redirect(url_for("home"))

    # Read inactivity timeout or other errors passed via query parameters
    error = request.args.get("error")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        selected_role = request.form.get("role", "user").strip()

        if not username or not password:
            error = "Please enter both username and password."
        elif selected_role not in ["user", "admin"]:
            error = "Invalid role selected."
        else:
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    conn.row_factory = sqlite3.Row
                    row = conn.execute(
                        "SELECT id, username, password, role FROM users WHERE (username = ? OR email = ?)",
                        (username, username),
                    ).fetchone()

                if row:
                    if selected_role == "admin" and row["role"] == "user":
                        error = "Access Denied: This account does not have Admin privileges."
                    elif selected_role == "user" and row["role"] == "admin":
                        error = "Please use the Admin login section to sign in as an administrator."
                    else:
                        stored_pw = row["password"]
                        password_valid = False
                        if stored_pw.startswith("scrypt:") or stored_pw.startswith("pbkdf2:"):
                            password_valid = check_password_hash(stored_pw, password)
                        elif stored_pw == password:
                            # Transparently upgrade legacy plaintext password
                            password_valid = True
                            new_hash = generate_password_hash(password, method="scrypt")
                            try:
                                with sqlite3.connect(DB_PATH) as up_conn:
                                    up_conn.execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, row["id"]))
                                    up_conn.commit()
                            except Exception:
                                pass

                        if password_valid:
                            session.clear()
                            session["user_id"] = row["id"]
                            session["username"] = row["username"]
                            session["role"] = row["role"]
                            session["last_activity"] = datetime.now(timezone.utc).isoformat()
                            return redirect(url_for("home"))
                        else:
                            error = "Invalid username or password."
                else:
                    error = "Invalid username or password."
            except Exception as exc:
                error = f"Database error: {exc}"

    return render_template("login.html", error=error)


# ── Logout ─────────────────────────────────────────────────────────────────────

@auth.route("/logout")
def logout():
    """Logs the user out and clears the session."""
    session.clear()
    return redirect(url_for("auth.login"))


# ── Signup ─────────────────────────────────────────────────────────────────────

@auth.route("/signup", methods=["GET", "POST"])
def signup():
    """Signup wizard with OTP verification."""
    if "username" in session:
        return redirect(url_for("home"))

    step = session.get("signup_step", "email")
    email = session.get("signup_email", "")
    error = None
    info = None
    success_msg = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "restart":
            session.pop("signup_step", None)
            session.pop("signup_email", None)
            return redirect(url_for("auth.signup"))

        elif action == "send_otp":
            input_email = request.form.get("email", "").strip().lower()
            if not input_email:
                error = "Please enter a valid email address."
            else:
                ok, msg = request_otp(input_email)
                if ok:
                    session["signup_email"] = input_email
                    session["signup_step"] = "verify_otp"
                    step = "verify_otp"
                    email = input_email
                    success_msg = msg
                else:
                    error = msg

        elif action == "verify_otp":
            otp_input = request.form.get("otp_code", "").strip()
            if not email:
                error = "Session expired. Please restart."
                step = "email"
            elif not otp_input:
                error = "Please enter the verification code."
            else:
                verified, err_msg, _ = otp_service_verify(email, otp_input)
                if verified:
                    session["signup_step"] = "register"
                    step = "register"
                    info = "Email verified successfully! Please choose credentials."
                else:
                    error = err_msg

        elif action == "register":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not email or session.get("signup_step") != "register":
                error = "Invalid flow. Please start signup again."
                step = "email"
            elif not username or not password:
                error = "Please fill in all credential fields."
            else:
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        # Check if username is already taken
                        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
                        if exists:
                            error = "Username is already taken."
                        else:
                            cursor = conn.cursor()
                            hashed_pw = generate_password_hash(password, method="scrypt")
                            cursor.execute(
                                "INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, 'user')",
                                (email, username, hashed_pw)
                            )
                            new_user_id = cursor.lastrowid
                            cursor.execute("DELETE FROM otp_store WHERE email = ?", (email,))
                            conn.commit()

                            session.pop("signup_step", None)
                            session.pop("signup_email", None)

                            session.clear()
                            session["user_id"] = new_user_id
                            session["username"] = username
                            session["role"] = "user"
                            session["last_activity"] = datetime.now(timezone.utc).isoformat()
                            return redirect(url_for("home"))
                except Exception as exc:
                    error = f"Database error: {exc}"

    return render_template("signup.html", step=step, email=email, error=error, info=info, success_msg=success_msg)


# ── Create Admin ───────────────────────────────────────────────────────────────

@auth.route("/admin/create_admin", methods=["GET", "POST"])
def create_admin():
    """Admin creation page. Requires existing admin session."""
    if "username" not in session:
        return redirect(url_for("auth.login"))
    if session.get("role") != "admin":
        return "Access Denied: Admin privileges required.", 403

    step = session.get("create_admin_step", "email")
    email = session.get("create_admin_email", "")
    error = None
    info = None
    success_msg = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "restart":
            session.pop("create_admin_step", None)
            session.pop("create_admin_email", None)
            return redirect(url_for("auth.create_admin"))

        elif action == "send_otp":
            input_email = request.form.get("email", "").strip().lower()
            if not input_email:
                error = "Please enter a valid email address."
            else:
                ok, msg = request_otp(input_email)
                if ok:
                    session["create_admin_email"] = input_email
                    session["create_admin_step"] = "verify_otp"
                    step = "verify_otp"
                    email = input_email
                    success_msg = msg
                else:
                    error = msg

        elif action == "verify_otp":
            otp_input = request.form.get("otp_code", "").strip()
            if not email:
                error = "Session expired. Please restart."
                step = "email"
            elif not otp_input:
                error = "Please enter the verification code."
            else:
                verified, err_msg, _ = otp_service_verify(email, otp_input)
                if verified:
                    session["create_admin_step"] = "register"
                    step = "register"
                    info = "OTP verified! You can now set credentials for the new administrator."
                else:
                    error = err_msg

        elif action == "register":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not email or session.get("create_admin_step") != "register":
                error = "Invalid flow step. Please start over."
                step = "email"
            elif not username or not password:
                error = "Please fill in all credential fields."
            else:
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
                        if exists:
                            error = "Username is already taken."
                        else:
                            cursor = conn.cursor()
                            hashed_pw = generate_password_hash(password, method="scrypt")
                            cursor.execute(
                                "INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, 'admin')",
                                (email, username, hashed_pw)
                            )
                            cursor.execute("DELETE FROM otp_store WHERE email = ?", (email,))
                            conn.commit()

                            session.pop("create_admin_step", None)
                            session.pop("create_admin_email", None)

                            step = "email"
                            email = ""
                            success_msg = f"Successfully created new administrator profile '{username}'."
                except Exception as exc:
                    error = f"Database error: {exc}"

    return render_template("create_admin.html", step=step, email=email, error=error, info=info, success_msg=success_msg)
