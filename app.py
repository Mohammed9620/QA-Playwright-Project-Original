import os
import re
import json
import sqlite3
import subprocess
import threading
import time
import uuid
import secrets
import shutil
from collections import OrderedDict
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, send_file, Response, jsonify, session, redirect, url_for

app = Flask(__name__)
_configured_secret = os.environ.get("SECRET_KEY")
if not _configured_secret:
    app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
else:
    app.secret_key = _configured_secret
app.config['SESSION_PERMANENT'] = False


@app.before_request
def check_session_timeout():
    # Enforce session clears on browser exit
    session.permanent = False
    
    # Exclude static files and critical authentication endpoints
    if request.endpoint in ['static', 'login', 'signup', 'logout']:
        return
        
    if "username" in session:
        last_activity_str = session.get("last_activity")
        now = datetime.now(timezone.utc)
        if last_activity_str:
            try:
                last_activity = datetime.fromisoformat(last_activity_str)
                if now - last_activity > timedelta(minutes=30):
                    session.clear()
                    return redirect(url_for("login", error="Session expired due to inactivity."))
            except Exception:
                session.clear()
                return redirect(url_for("login"))
        session["last_activity"] = now.isoformat()

# ──────────────────────────────────────────────
#  Scan type → pytest file mapping
# ──────────────────────────────────────────────
SCAN_MAP = {
    "login":      [("main_test.py",       "Login Test")],
    "bruteforce": [("test_credentials.py","Credential Bruteforce Probe")],
    "api":        [("test_api.py",        "API Health Check")],
    "auth":       [("test_auth.py",       "Broken Authentication Check")],
    "full": [
        ("main_test.py",        "Login Test"),
        ("test_credentials.py", "Credential Bruteforce Probe"),
        ("test_api.py",         "API Health Check"),
        ("test_auth.py",        "Broken Authentication Check"),
    ],
}

SCAN_LABELS = {
    "login":      "Login Test",
    "bruteforce": "Credential Bruteforce Probe",
    "api":        "API Health Check",
    "auth":       "Broken Authentication Check",
    "full":       "Full Scan",
}


DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
REPORT_PATH = os.path.join(os.path.dirname(__file__), "report.html")

# Bounded in-memory store for finished scan results and auth params (LRU eviction)
class BoundedCache:
    def __init__(self, maxsize=100):
        self._cache = OrderedDict()
        self._lock = threading.Lock()
        self._maxsize = maxsize

    def set(self, key: str, val: dict):
        with self._lock:
            if len(self._cache) >= self._maxsize:
                self._cache.popitem(last=False)
            self._cache[key] = val

    def get(self, key: str):
        with self._lock:
            return self._cache.get(key)

    def pop(self, key: str, default=None):
        with self._lock:
            return self._cache.pop(key, default)

_scan_results = BoundedCache(maxsize=100)
_scan_creds = BoundedCache(maxsize=50)
_scan_lock = threading.Lock()


def ensure_db_schema():
    """Ensure database schema includes attempt tracking for brute-force rate-limiting."""
    try:
        if os.path.exists(DB_PATH):
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.cursor()
                cur.execute("PRAGMA table_info(otp_store)")
                cols = [col[1] for col in cur.fetchall()]
                if cols and "attempts" not in cols:
                    cur.execute("ALTER TABLE otp_store ADD COLUMN attempts INTEGER DEFAULT 0")
                    conn.commit()
    except Exception as e:
        print(f"[DB] Schema migration notice: {e}")


ensure_db_schema()



def parse_pytest_summary(output: str) -> dict:
    """Extract total / passed / failed counts from pytest terminal output."""
    summary = {"total": 0, "passed": 0, "failed": 0, "error": 0, "raw": ""}

    for line in output.splitlines():
        if re.search(r"\d+ (passed|failed|error)", line, re.IGNORECASE):
            summary["raw"] = line.strip()
            m_failed = re.search(r"(\d+) failed",  line, re.IGNORECASE)
            m_passed = re.search(r"(\d+) passed",  line, re.IGNORECASE)
            m_error  = re.search(r"(\d+) error",   line, re.IGNORECASE)
            summary["failed"] = int(m_failed.group(1)) if m_failed else 0
            summary["passed"] = int(m_passed.group(1)) if m_passed else 0
            summary["error"]  = int(m_error.group(1))  if m_error  else 0
            summary["total"]  = summary["passed"] + summary["failed"] + summary["error"]
            break

    return summary


def format_milestone_log(line: str, target_url: str) -> str | None:
    line_strip = line.strip()
    if not line_strip:
        return None

    # Only include lines printed by our test suite via [INFO], [PASS], [WARN], [FAIL], [ERROR]
    if not any(prefix in line_strip for prefix in ["[INFO]", "[PASS]", "[WARN]", "[FAIL]", "[ERROR]"]):
        return None

    # 1. Navigating to URL
    if "Navigated to:" in line_strip:
        m = re.search(r"Navigated to:\s*(\S+)", line_strip)
        url = m.group(1) if m else target_url
        return f"🌐 Opening URL: {url}"

    # GET / POST requests (for API tests)
    if "GET " in line_strip or "POST " in line_strip:
        clean = re.sub(r"^\[(?:INFO|PASS|WARN|FAIL|ERROR)\]\s*", "", line_strip)
        return f"🌐 {clean}"

    # Status / SLA checks (for API tests)
    if "Status:" in line_strip and "Elapsed:" in line_strip:
        clean = re.sub(r"^\[(?:INFO|PASS|WARN|FAIL|ERROR)\]\s*", "", line_strip)
        return f"📊 {clean}"

    # 2. Username locator search
    if "Entered username:" in line_strip:
        return "🔑 Entering username..."
    if "Entered username" in line_strip:
        return "🔎 Searching for Username Locator..."

    # 3. Password locator search
    if "Entered password:" in line_strip:
        return "🔒 Entering password..."
    if "Entered password" in line_strip:
        return "🔎 Searching for Password Locator..."

    # 4. Login button click
    if "Clicked the Login button" in line_strip:
        return "🔘 Clicking Login Button..."

    # 5. Assertions / Results
    if "[PASS]" in line_strip:
        msg = line_strip.replace("[PASS]", "").strip()
        return f"✅ {msg}"
    if "[WARN]" in line_strip:
        msg = line_strip.replace("[WARN]", "").strip()
        return f"⚠️ {msg}"
    if "[FAIL]" in line_strip:
        msg = line_strip.replace("[FAIL]", "").strip()
        return f"❌ {msg}"
    if "[ERROR]" in line_strip:
        msg = line_strip.replace("[ERROR]", "").strip()
        return f"❌ {msg}"

    # General fallback
    clean_line = re.sub(r"^\[(?:INFO|PASS|WARN|FAIL|ERROR)\]\s*", "", line_strip)
    return clean_line


# ──────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """
    Sanitizes and auto-completes incomplete URLs for test runs:
    - Strips leading/trailing whitespace.
    - Preserves existing protocols (http://, https://, etc.).
    - Appends '.com' if it's a single word without a domain suffix (excluding localhost).
    - Prepends 'https://' (or 'http://' for localhost) if a protocol is missing.
    """
    url = url.strip()
    if not url:
        return url

    # 1. If it already contains a protocol schema, leave it untouched
    if re.match(r'^[a-zA-Z]+://', url):
        return url

    # 2. Separate port if present to avoid appending domain suffix to it
    host_part = url
    port_part = ""
    if ":" in url:
        parts = url.split(":", 1)
        if parts[1].isdigit():
            host_part = parts[0]
            port_part = f":{parts[1]}"

    # 3. Append '.com' if it's a single word without any '.' (excluding localhost)
    if "." not in host_part and host_part.lower() != "localhost":
        host_part = f"{host_part}.com"

    # 4. Determine protocol (default to https://, default to http:// for local execution)
    protocol = "http://" if host_part.lower() == "localhost" else "https://"

    return f"{protocol}{host_part}{port_part}"


@app.route("/")
def home():
    """Dashboard — requires an active login session."""
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")


def send_otp_email(target_email, otp_code):
    """
    Sends an OTP verification code via Gmail SMTP server.
    Reads SMTP_EMAIL and SMTP_PASSWORD from environment variables.
    """
    smtp_email = os.environ.get("SMTP_EMAIL")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    
    # Fallback if not configured
    if not smtp_email or not smtp_password:
        print(f"\n[WARNING] SMTP credentials not set (SMTP_EMAIL/SMTP_PASSWORD). Falling back to console.")
        print(f"[MOCK EMAIL SERVICE] Sending OTP to {target_email}: {otp_code}\n")
        return True

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_email
        msg['To'] = target_email
        msg['Subject'] = "QA Automation Engine - Verification Code"

        body = f"Your verification code is: {otp_code}\nThis code will expire in 5 minutes."
        msg.attach(MIMEText(body, 'plain'))

        # Connect to Gmail SMTP on port 587
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.sendmail(smtp_email, target_email, msg.as_string())
        server.quit()
        print(f"[SMTP] Successfully sent OTP verification email to {target_email}")
        return True
    except Exception as e:
        print(f"[SMTP ERROR] Failed to send email to {target_email}: {e}")
        return False


DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")


@app.route("/login", methods=["GET", "POST"])
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



@app.route("/logout")
def logout():
    """Logs the user out and clears the session."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
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
            return redirect(url_for("signup"))

        elif action == "send_otp":
            input_email = request.form.get("email", "").strip().lower()
            if not input_email:
                error = "Please enter a valid email address."
            else:
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        # Check if email is already taken
                        user_exists = conn.execute("SELECT 1 FROM users WHERE email = ?", (input_email,)).fetchone()
                        if user_exists:
                            error = "Email address is already registered."
                        else:
                            # Check existing OTP generated within last 5 minutes
                            conn.row_factory = sqlite3.Row
                            row = conn.execute("SELECT otp_code, created_at FROM otp_store WHERE email = ?", (input_email,)).fetchone()

                            now = datetime.now(timezone.utc)
                            otp_code = None

                            if row:
                                try:
                                    created_at = datetime.fromisoformat(row["created_at"])
                                    if now - created_at < timedelta(minutes=5):
                                        otp_code = row["otp_code"]
                                except Exception:
                                    pass

                            if not otp_code:
                                otp_code = f"{secrets.randbelow(900000) + 100000}"
                                conn.execute(
                                    "INSERT OR REPLACE INTO otp_store (email, otp_code, created_at, attempts) VALUES (?, ?, ?, 0)",
                                    (input_email, otp_code, now.isoformat())
                                )
                                conn.commit()

                            if send_otp_email(input_email, otp_code):
                                session["signup_email"] = input_email
                                session["signup_step"] = "verify_otp"
                                step = "verify_otp"
                                email = input_email
                                success_msg = "OTP sent successfully! Please check your email."
                            else:
                                error = "Failed to send OTP verification email. Please try again later."
                except Exception as exc:
                    error = f"Database error: {exc}"

        elif action == "verify_otp":
            otp_input = request.form.get("otp_code", "").strip()
            if not email:
                error = "Session expired. Please restart."
                step = "email"
            elif not otp_input:
                error = "Please enter the verification code."
            else:
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        conn.row_factory = sqlite3.Row
                        row = conn.execute("SELECT otp_code, created_at, attempts FROM otp_store WHERE email = ?", (email,)).fetchone()

                        if row:
                            attempts = row["attempts"] if "attempts" in row.keys() else 0
                            if attempts >= 5:
                                conn.execute("DELETE FROM otp_store WHERE email = ?", (email,))
                                conn.commit()
                                error = "Too many failed attempts. This OTP has been invalidated; please request a new one."
                            elif row["otp_code"] == otp_input:
                                now = datetime.now(timezone.utc)
                                created_at = datetime.fromisoformat(row["created_at"])
                                if now - created_at < timedelta(minutes=5):
                                    session["signup_step"] = "register"
                                    step = "register"
                                    info = "Email verified successfully! Please choose credentials."
                                else:
                                    error = "OTP expired. Please request a new one."
                            else:
                                conn.execute("UPDATE otp_store SET attempts = attempts + 1 WHERE email = ?", (email,))
                                conn.commit()
                                remaining = 4 - attempts
                                error = f"Invalid OTP. {remaining} attempt(s) remaining."
                        else:
                            error = "No active OTP request found. Please request a new one."
                except Exception as exc:
                    error = f"Database error: {exc}"

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


@app.route("/admin/create_admin", methods=["GET", "POST"])
def create_admin():
    """Admin creation page. Requires existing admin session."""
    if "username" not in session:
        return redirect(url_for("login"))
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
            return redirect(url_for("create_admin"))

        elif action == "send_otp":
            input_email = request.form.get("email", "").strip().lower()
            if not input_email:
                error = "Please enter a valid email address."
            else:
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        user_exists = conn.execute("SELECT 1 FROM users WHERE email = ?", (input_email,)).fetchone()
                        if user_exists:
                            error = "Email address is already registered."
                        else:
                            # Check existing OTP generated within last 5 minutes
                            conn.row_factory = sqlite3.Row
                            row = conn.execute("SELECT otp_code, created_at FROM otp_store WHERE email = ?", (input_email,)).fetchone()

                            now = datetime.now(timezone.utc)
                            otp_code = None

                            if row:
                                try:
                                    created_at = datetime.fromisoformat(row["created_at"])
                                    if now - created_at < timedelta(minutes=5):
                                        otp_code = row["otp_code"]
                                except Exception:
                                    pass

                            if not otp_code:
                                otp_code = f"{secrets.randbelow(900000) + 100000}"
                                conn.execute(
                                    "INSERT OR REPLACE INTO otp_store (email, otp_code, created_at, attempts) VALUES (?, ?, ?, 0)",
                                    (input_email, otp_code, now.isoformat())
                                )
                                conn.commit()

                            if send_otp_email(input_email, otp_code):
                                session["create_admin_email"] = input_email
                                session["create_admin_step"] = "verify_otp"
                                step = "verify_otp"
                                email = input_email
                                success_msg = "OTP sent successfully! Please check your email."
                            else:
                                error = "Failed to send OTP verification email. Please try again later."
                except Exception as exc:
                    error = f"Database error: {exc}"

        elif action == "verify_otp":
            otp_input = request.form.get("otp_code", "").strip()
            if not email:
                error = "Session expired. Please restart."
                step = "email"
            elif not otp_input:
                error = "Please enter the verification code."
            else:
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        conn.row_factory = sqlite3.Row
                        row = conn.execute("SELECT otp_code, created_at, attempts FROM otp_store WHERE email = ?", (email,)).fetchone()

                        if row:
                            attempts = row["attempts"] if "attempts" in row.keys() else 0
                            if attempts >= 5:
                                conn.execute("DELETE FROM otp_store WHERE email = ?", (email,))
                                conn.commit()
                                error = "Too many failed attempts. This OTP has expired. Please request a new one."
                            elif row["otp_code"] == otp_input:
                                now = datetime.now(timezone.utc)
                                created_at = datetime.fromisoformat(row["created_at"])
                                if now - created_at < timedelta(minutes=5):
                                    session["create_admin_step"] = "register"
                                    step = "register"
                                    info = "OTP verified! You can now set credentials for the new administrator."
                                else:
                                    error = "OTP expired. Please request a new one."
                            else:
                                conn.execute("UPDATE otp_store SET attempts = attempts + 1 WHERE email = ?", (email,))
                                conn.commit()
                                remaining = 4 - attempts
                                error = f"Invalid OTP. {remaining} attempt(s) remaining."
                        else:
                            error = "No active OTP found. Please request a new one."
                except Exception as exc:
                    error = f"Database error: {exc}"

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


@app.route("/prepare_scan", methods=["POST"])
def prepare_scan():
    """Securely registers scan authentication parameters in memory before SSE connection."""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    session_id = data.get("session_id", str(uuid.uuid4()))
    _scan_creds.set(session_id, {
        "username": data.get("username", "").strip(),
        "password": data.get("password", "").strip(),
        "user_locator": data.get("user_locator", "").strip(),
        "pass_locator": data.get("pass_locator", "").strip(),
        "login_locator": data.get("login_locator", "").strip(),
    })
    return jsonify({"status": "ok", "session_id": session_id})


@app.route("/stream_scan")
def stream_scan():
    """
    Server-Sent Events endpoint.
    Streams real-time log lines and progress events, then a final 'done' event.
    """
    if "username" not in session:
        def unauth():
            yield "data: " + json.dumps({"type": "error", "message": "Authentication required. Please log in."}) + "\n\n"
        return Response(unauth(), mimetype="text/event-stream", status=401)

    target_url     = normalize_url(request.args.get("url", ""))
    scan_type      = request.args.get("scan_type", "login").strip()
    session_id     = request.args.get("session_id", str(uuid.uuid4()))
    scan_strategy  = request.args.get("scan_strategy", "external").strip()

    # Retrieve sensitive credentials from secure temporary server store if prepared
    prepared = _scan_creds.pop(session_id) or {}
    auth_username  = prepared.get("username") or request.args.get("username", "").strip()
    auth_password  = prepared.get("password") or request.args.get("password", "").strip()
    user_locator   = prepared.get("user_locator") or request.args.get("user_locator", "").strip()
    pass_locator   = prepared.get("pass_locator") or request.args.get("pass_locator", "").strip()
    login_locator  = prepared.get("login_locator") or request.args.get("login_locator", "").strip()

    if not target_url:
        def err():
            yield "data: " + json.dumps({"type": "error", "message": "No target URL provided."}) + "\n\n"
        return Response(err(), mimetype="text/event-stream")

    if scan_type not in SCAN_MAP:
        def err():
            yield "data: " + json.dumps({"type": "error", "message": f"Unknown scan type: {scan_type}"}) + "\n\n"
        return Response(err(), mimetype="text/event-stream")

    test_files = SCAN_MAP[scan_type]

    def generate():
        current_env = os.environ.copy()
        current_env["TARGET_URL"] = target_url

        # Pass authenticated scan credentials if provided
        if scan_strategy == "authenticated" and auth_username:
            current_env["TEST_USER"] = auth_username
            current_env["TEST_PASS"] = auth_password
        if user_locator:
            current_env["USER_LOCATOR"] = user_locator
        if pass_locator:
            current_env["PASS_LOCATOR"] = pass_locator
        if login_locator:
            current_env["LOGIN_LOCATOR"] = login_locator

        total_passed = 0
        total_failed = 0
        total_error  = 0
        report_generated = False
        session_report_path = os.path.join(REPORTS_DIR, f"report_{session_id}.html")

        # Emit initial preparing test environment milestone
        now = datetime.now()
        yield "data: " + json.dumps({
            "type": "log",
            "file": "system",
            "label": "System",
            "line": "Status: Preparing test environment...",
            "timestamp": now.strftime("%H:%M:%S")
        }) + "\n\n"

        # Emit a 'start' event listing all files that will run
        yield "data: " + json.dumps({
            "type": "start",
            "files": [{"file": f, "label": lbl} for f, lbl in test_files],
        }) + "\n\n"

        for i, (test_file, label) in enumerate(test_files):
            is_last = (i == len(test_files) - 1)
            file_start_time = time.monotonic()

            # Yield start milestone for this specific test suite
            now = datetime.now()
            yield "data: " + json.dumps({
                "type": "log",
                "file": test_file,
                "label": label,
                "line": f"Status: Starting test suite: {label}...",
                "timestamp": now.strftime("%H:%M:%S")
            }) + "\n\n"

            # Build command — only attach the HTML reporter on the last file
            cmd = ["python", "-u", "-m", "pytest", test_file, "-v", "-s"]
            if is_last:
                cmd += [f"--html={session_report_path}", "--self-contained-html"]

            try:
                # Use Popen for line-by-line streaming instead of subprocess.run
                proc = subprocess.Popen(
                    cmd,
                    env=current_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,  # line-buffered
                )

                output_lines = []
                for raw_line in proc.stdout:
                    line = raw_line.rstrip("\n").rstrip("\r")
                    output_lines.append(line)

                    # Only stream the custom milestones
                    milestone = format_milestone_log(line, target_url)
                    if milestone:
                        now = datetime.now()
                        yield "data: " + json.dumps({
                            "type": "log",
                            "file": test_file,
                            "label": label,
                            "line": f"Status: {milestone}",
                            "timestamp": now.strftime("%H:%M:%S"),
                        }) + "\n\n"

                proc.wait(timeout=300)
                output = "\n".join(output_lines)
                summary = parse_pytest_summary(output)

                total_passed += summary["passed"]
                total_failed += summary["failed"]
                total_error  += summary["error"]

                status = "passed" if summary["failed"] == 0 and summary["error"] == 0 else "failed"
                elapsed_s = round(time.monotonic() - file_start_time, 1)
                if is_last:
                    report_generated = os.path.exists(session_report_path)
                    if report_generated:
                        try:
                            shutil.copyfile(session_report_path, REPORT_PATH)
                        except Exception:
                            pass

                # Yield status outcome milestone for the suite
                now = datetime.now()
                if status == "passed":
                    yield "data: " + json.dumps({
                        "type": "log",
                        "file": test_file,
                        "label": label,
                        "line": f"Status: ✅ Test suite '{label}' passed ({elapsed_s}s).",
                        "timestamp": now.strftime("%H:%M:%S")
                    }) + "\n\n"
                else:
                    yield "data: " + json.dumps({
                        "type": "log",
                        "file": test_file,
                        "label": label,
                        "line": f"Status: ❌ Test suite '{label}' failed ({elapsed_s}s).",
                        "timestamp": now.strftime("%H:%M:%S")
                    }) + "\n\n"

                yield "data: " + json.dumps({
                    "type":      "progress",
                    "file":      test_file,
                    "label":     label,
                    "status":    status,
                    "passed":    summary["passed"],
                    "failed":    summary["failed"],
                    "error":     summary["error"],
                    "elapsed_s": elapsed_s,
                }) + "\n\n"

            except subprocess.TimeoutExpired:
                if proc and proc.poll() is None:
                    proc.kill()
                now = datetime.now()
                yield "data: " + json.dumps({
                    "type": "log",
                    "file": test_file,
                    "label": label,
                    "line": f"Status: ❌ Test suite '{label}' timed out.",
                    "timestamp": now.strftime("%H:%M:%S")
                }) + "\n\n"

                yield "data: " + json.dumps({
                    "type":   "progress",
                    "file":   test_file,
                    "label":  label,
                    "status": "timeout",
                    "passed": 0,
                    "failed": 0,
                    "error":  1,
                }) + "\n\n"
                total_error += 1

            except Exception as exc:
                now = datetime.now()
                yield "data: " + json.dumps({
                    "type": "log",
                    "file": test_file,
                    "label": label,
                    "line": f"Status: ❌ Execution failed: {str(exc)}",
                    "timestamp": now.strftime("%H:%M:%S")
                }) + "\n\n"

                yield "data: " + json.dumps({
                    "type":    "progress",
                    "file":    test_file,
                    "label":   label,
                    "status":  "error",
                    "message": str(exc),
                    "passed":  0,
                    "failed":  0,
                    "error":   1,
                }) + "\n\n"
                total_error += 1

        # Emit final summary log milestone
        now = datetime.now()
        if total_failed == 0 and total_error == 0:
            yield "data: " + json.dumps({
                "type": "log",
                "file": "summary",
                "label": "Summary",
                "line": f"Status: ✅ Scan complete - {total_passed} passed, {total_failed} failed.",
                "timestamp": now.strftime("%H:%M:%S")
            }) + "\n\n"
        else:
            yield "data: " + json.dumps({
                "type": "log",
                "file": "summary",
                "label": "Summary",
                "line": f"Status: ❌ Scan complete - {total_passed} passed, {total_failed} failed.",
                "timestamp": now.strftime("%H:%M:%S")
            }) + "\n\n"

        # Store final result so the frontend can fetch it
        final = {
            "scan_label":     SCAN_LABELS.get(scan_type, scan_type),
            "target_url":     target_url,
            "report_exists":  report_generated,
            "session_id":     session_id,
            "summary": {
                "total":  total_passed + total_failed + total_error,
                "passed": total_passed,
                "failed": total_failed,
                "error":  total_error,
            },
        }
        _scan_results.set(session_id, final)

        yield "data: " + json.dumps({
            "type":       "done",
            "session_id": session_id,
            **final,
        }) + "\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/scan_result/<session_id>")
def scan_result(session_id):
    """Return the stored scan result for a given session (used as fallback)."""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = _scan_results.get(session_id)
    if not data:
        return jsonify({"error": "No result found for this session."}), 404
    return jsonify(data)


@app.route("/results")
def results():
    """Render the results page; data comes from query-string params set by JS."""
    if "username" not in session:
        return redirect(url_for("login"))
    summary = {
        "total":  int(request.args.get("total",  0)),
        "passed": int(request.args.get("passed", 0)),
        "failed": int(request.args.get("failed", 0)),
        "error":  int(request.args.get("error",  0)),
    }
    return render_template(
        "results.html",
        scan_label=request.args.get("scan_label", "Scan"),
        target_url=request.args.get("target_url", ""),
        summary=summary,
        report_exists=request.args.get("report_exists", "0") == "1",
    )



def get_report_theme_css():
    """Return a <style> block + theme toggle script to inject into report.html."""
    return '''
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* ── Report Theme Override ── */
:root {
    --r-bg: #0a0710;
    --r-surface: #120b1c;
    --r-border: #32243f;
    --r-text: #f2edf5;
    --r-text-muted: #a79cae;
    --r-success: #22c55e;
    --r-danger: #ef4444;
    --r-warning: #eab308;
    --r-accent: #9b6ac4;
    --r-font: 'Inter', system-ui, sans-serif;
    --r-mono: 'JetBrains Mono', monospace;
}
[data-theme="light"] {
    --r-bg: #faf8fc;
    --r-surface: #ffffff;
    --r-border: #d9cde0;
    --r-text: #211629;
    --r-text-muted: #5f5268;
    --r-success: #16a34a;
    --r-danger: #dc2626;
    --r-warning: #ca8a04;
    --r-accent: #74479b;
}
body {
    font-family: var(--r-font) !important;
    font-size: 14px !important;
    background: var(--r-bg) !important;
    color: var(--r-text) !important;
    padding: 24px 32px !important;
    min-width: auto !important;
}
h1 { font-size: 20px !important; font-weight: 700 !important; color: var(--r-text) !important; margin-bottom: 4px !important; }
h2 { font-size: 15px !important; font-weight: 600 !important; color: var(--r-text) !important; }
p { color: var(--r-text-muted) !important; font-size: 13px !important; }
a { color: var(--r-accent) !important; }
table { border-collapse: collapse !important; }
#environment td { padding: 8px 12px !important; border: 1px solid var(--r-border) !important; color: var(--r-text) !important; font-size: 13px !important; }
#environment tr:nth-child(odd) { background: var(--r-surface) !important; }
#environment tr:nth-child(even) { background: var(--r-bg) !important; }
span.passed, .passed .col-result { color: var(--r-success) !important; }
span.failed, .failed .col-result, span.error, .error .col-result { color: var(--r-danger) !important; }
span.skipped, .skipped .col-result, span.xfailed, .xfailed .col-result { color: var(--r-warning) !important; }
#results-table { border: 1px solid var(--r-border) !important; color: var(--r-text) !important; font-size: 13px !important; }
#results-table th, #results-table td { padding: 8px 12px !important; border: 1px solid var(--r-border) !important; }
#results-table th { background: var(--r-surface) !important; font-weight: 600 !important; color: var(--r-text) !important; }
.logwrapper { background: var(--r-surface) !important; border: 1px solid var(--r-border) !important; border-radius: 4px !important; }
.logwrapper .log { font-family: var(--r-mono) !important; font-size: 12px !important; color: var(--r-text) !important; background: var(--r-surface) !important; border: none !important; padding: 12px !important; }
.logwrapper .log .error { color: var(--r-danger) !important; }
.logwrapper .logexpander { background: var(--r-bg) !important; color: var(--r-text-muted) !important; border-color: var(--r-border) !important; font-size: 12px !important; }
.logwrapper .logexpander:hover { color: var(--r-text) !important; border-color: var(--r-text-muted) !important; }
.summary__data { flex: none !important; }
.controls { flex-wrap: wrap !important; gap: 8px !important; }
.filters, .collapse { flex-wrap: wrap !important; }
.filters span { color: var(--r-text-muted) !important; font-size: 13px !important; }
.filters button, .collapse button { color: var(--r-accent) !important; font-size: 13px !important; }
.summary__reload__button { background-color: var(--r-success) !important; border-radius: 4px !important; }
.sortable.desc:after { border-color: var(--r-success) transparent transparent !important; }
.sortable.asc:after { border-color: transparent transparent var(--r-success) !important; }
.collapsible td:not(.col-links):hover::after { color: var(--r-text-muted) !important; }
.col-result:hover::after, .col-result.collapsed:hover::after { font-size: 11px !important; color: var(--r-text-muted) !important; }
#environment-header h2:hover::after, #environment-header.collapsed h2:hover::after { color: var(--r-text-muted) !important; font-size: 11px !important; }
/* Theme toggle button — hidden when inside iframe; parent dashboard owns the toggle */
.report-theme-toggle { position: fixed; top: 16px; right: 16px; z-index: 9999; background: var(--r-surface); border: 1px solid var(--r-border); color: var(--r-text-muted); width: 36px; height: 36px; border-radius: 6px; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 16px; transition: all 0.2s; }
.report-theme-toggle:hover { color: var(--r-text); border-color: var(--r-text-muted); }

/* Modern developer-tool report layer */
:root {
    --r-elevated:#181023; --r-border-muted:#24192f; --r-faint:#75697f;
    --r-success-bg:rgba(34,197,94,.1); --r-danger-bg:rgba(239,68,68,.1);
    --r-warning-bg:rgba(234,179,8,.1); --r-accent-bg:rgba(155,106,196,.12);
}
[data-theme="light"] {
    --r-elevated:#f1ebf5; --r-border-muted:#eee7f2; --r-faint:#7d6f86;
    --r-success-bg:rgba(22,163,74,.08); --r-danger-bg:rgba(220,38,38,.08);
    --r-warning-bg:rgba(202,138,4,.08); --r-accent-bg:rgba(116,71,155,.09);
}
* { box-sizing:border-box; }
html { background:var(--r-bg); color-scheme:dark; }
[data-theme="light"] { color-scheme:light; }
body { max-width:1280px; margin:0 auto !important; padding:28px 32px 48px !important; line-height:1.5; }
.report-header { position:relative; margin-bottom:18px; padding:20px 22px; background:var(--r-surface); border:1px solid var(--r-border); border-radius:10px; }
.report-header::before { content:""; position:absolute; top:0; left:22px; width:48px; height:2px; background:var(--r-accent); }
.report-header h1 { margin:0 48px 5px 0 !important; font-size:21px !important; letter-spacing:-.02em; }
.report-header p { margin:0 !important; font-size:12px !important; }
a { transition:color 160ms ease; }
a:hover { color:var(--r-text) !important; }
#environment-header { padding:14px 16px; background:var(--r-surface); border:1px solid var(--r-border); border-bottom:0; border-radius:8px 8px 0 0; cursor:pointer; }
#environment-header h2 { margin:0 !important; font-size:14px !important; }
#environment-header h2::before { content:"TECHNICAL METADATA"; display:block; margin-bottom:2px; color:var(--r-faint); font:500 9px/1.2 var(--r-mono); letter-spacing:.1em; }
#environment { width:100% !important; margin:0 0 18px !important; border:1px solid var(--r-border) !important; border-collapse:separate !important; border-spacing:0; background:var(--r-surface); }
#environment td { padding:10px 14px !important; border:0 !important; border-top:1px solid var(--r-border-muted) !important; font-size:12px !important; }
#environment td:first-child { width:150px; color:var(--r-text-muted) !important; font:500 11px/1.5 var(--r-mono); }
#environment tr { background:transparent !important; }
.summary { display:block !important; margin:0 0 18px !important; padding:18px !important; background:var(--r-surface); border:1px solid var(--r-border); border-radius:8px; }
.summary h2 { margin:0 0 4px !important; font-size:14px !important; }
.run-count { margin:0 0 14px !important; color:var(--r-text) !important; font:500 12px/1.5 var(--r-mono) !important; }
.summary p.filter { margin:0 0 8px !important; color:var(--r-faint) !important; font-size:11px !important; }
.controls { display:flex !important; align-items:flex-end; justify-content:space-between; flex-wrap:wrap !important; gap:12px !important; }
.filters { display:flex !important; flex-wrap:wrap !important; gap:7px !important; }
.filter-chip { position:relative; display:inline-flex; align-items:center; cursor:pointer; }
.filter-chip input { position:absolute; opacity:0; pointer-events:none; }
.filter-chip span { padding:6px 9px; border:1px solid var(--r-border); border-radius:6px; background:var(--r-elevated); color:var(--r-text-muted) !important; font:500 11px/1 var(--r-mono) !important; transition:background 160ms ease,border-color 160ms ease,opacity 160ms ease; }
.filter-chip:hover span { border-color:var(--r-accent); }
.filter-chip input:not(:checked)+span { opacity:.42; text-decoration:line-through; }
.filter-chip input:focus-visible+span { outline:2px solid var(--r-accent); outline-offset:2px; }
.filter-chip input:disabled+span { opacity:.45; cursor:not-allowed; }
.filter-chip span.passed { color:var(--r-success) !important; border-color:rgba(34,197,94,.28); background:var(--r-success-bg); }
.filter-chip span.failed,.filter-chip span.error { color:var(--r-danger) !important; border-color:rgba(239,68,68,.28); background:var(--r-danger-bg); }
.filter-chip span.skipped,.filter-chip span.xfailed,.filter-chip span.rerun,.filter-chip span.retried { color:var(--r-warning) !important; border-color:rgba(234,179,8,.25); background:var(--r-warning-bg); }
.filter-chip span.xpassed { color:var(--r-accent) !important; background:var(--r-accent-bg); }
.collapse { display:flex !important; flex-wrap:wrap !important; gap:7px !important; }
.collapse button { padding:6px 10px !important; border:1px solid var(--r-border) !important; border-radius:6px; background:var(--r-elevated) !important; color:var(--r-text-muted) !important; font:500 11px var(--r-font) !important; cursor:pointer; transition:color 160ms ease,border-color 160ms ease,background 160ms ease; }
.collapse button:hover { color:var(--r-text) !important; border-color:var(--r-accent) !important; }
.collapse button:focus-visible { outline:2px solid var(--r-accent); outline-offset:2px; }
.results-table-shell { width:100%; overflow-x:auto; border:1px solid var(--r-border); border-radius:8px; background:var(--r-surface); }
#results-table { width:100% !important; min-width:680px; margin:0 !important; border:0 !important; border-collapse:collapse !important; font-size:12px !important; }
#results-table th,#results-table td { padding:10px 12px !important; border:0 !important; border-bottom:1px solid var(--r-border-muted) !important; text-align:left; }
#results-table th { background:var(--r-elevated) !important; color:var(--r-text-muted) !important; font:600 10px/1.4 var(--r-font) !important; letter-spacing:.06em; text-transform:uppercase; }
#results-table tr.collapsible { background:var(--r-surface); transition:background 160ms ease; }
#results-table tr.collapsible:hover { background:var(--r-elevated); }
#results-table .col-result { width:110px; font-weight:700; }
#results-table .col-testId { min-width:300px; overflow-wrap:anywhere; font-family:var(--r-mono); }
#results-table .col-duration { width:110px; color:var(--r-text-muted); font-family:var(--r-mono); white-space:nowrap; }
#results-table .col-links { width:100px; }
.passed .col-result { color:var(--r-success) !important; }
.failed .col-result,.error .col-result { color:var(--r-danger) !important; }
.skipped .col-result,.xfailed .col-result,.rerun .col-result,.retried .col-result { color:var(--r-warning) !important; }
.extras-row td { padding:0 12px 12px !important; background:var(--r-bg); }
.logwrapper { margin-top:8px; border-radius:6px !important; }
.logwrapper .log { max-height:420px; overflow:auto; line-height:1.55; }
.report-theme-toggle { position:absolute; top:41px; right:max(32px,calc((100vw - 1280px)/2 + 32px)); width:34px; height:34px; border-radius:6px; transition:color 160ms ease,border-color 160ms ease,background 160ms ease; }
/* Hide the report-level toggle when rendered inside an iframe — the parent dashboard toggle is authoritative */
.report-theme-toggle.iframe-hidden { display:none !important; }
.report-theme-toggle:focus-visible { outline:2px solid var(--r-accent); outline-offset:2px; }
/* Refined report-control feedback; native pytest-html handlers stay untouched. */
.report-theme-toggle,.collapse button,.filter-chip span,.logwrapper .logexpander {
    transition:background-color 180ms ease-out,border-color 180ms ease-out,
               color 180ms ease-out,opacity 180ms ease-out,
               box-shadow 180ms ease-out,transform 160ms ease-out;
}
.report-theme-toggle:active,.collapse button:active,.filter-chip:active span,.logwrapper .logexpander:active { transform:translateY(1px); }
.logwrapper .logexpander:focus-visible { outline:2px solid var(--r-accent); outline-offset:2px; }
.collapse button:disabled { cursor:not-allowed; opacity:.5; }
@media (prefers-reduced-motion:reduce) {
    .report-theme-toggle,.collapse button,.filter-chip span,.logwrapper .logexpander { transition-duration:160ms; }
    .report-theme-toggle:active,.collapse button:active,.filter-chip:active span,.logwrapper .logexpander:active { transform:none; filter:brightness(.94); }
}
@media (max-width:700px) {
    body { padding:16px 12px 32px !important; }
    .report-header { padding:17px 16px; }
    .report-header h1 { font-size:18px !important; }
    .report-theme-toggle { top:29px; right:24px; }
    #environment td { display:block; width:100% !important; padding:8px 12px !important; }
    #environment td:first-child { padding-bottom:2px !important; border-bottom:0 !important; }
    #environment td+td { padding-top:2px !important; }
    .summary { padding:14px !important; }
    .controls { align-items:stretch; }
    .filters { width:100%; }
    .results-table-shell { overscroll-behavior-x:contain; }
}
</style>
<script>
(function() {
    var saved = localStorage.getItem("qa-theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    document.addEventListener("DOMContentLoaded", function() {
        var title = document.getElementById("title");
        var generated = title && title.nextElementSibling;
        if (title && generated && !title.parentElement.classList.contains("report-header")) {
            var header = document.createElement("header");
            header.className = "report-header";
            title.parentNode.insertBefore(header, title);
            header.appendChild(title);
            header.appendChild(generated);
        }
        document.querySelectorAll(".filters input.filter").forEach(function(input) {
            var status = input.nextElementSibling;
            if (!status || input.parentElement.classList.contains("filter-chip")) return;
            var chip = document.createElement("label");
            chip.className = "filter-chip";
            input.parentNode.insertBefore(chip, input);
            chip.appendChild(input);
            chip.appendChild(status);
        });
        var table = document.getElementById("results-table");
        if (table && !table.parentElement.classList.contains("results-table-shell")) {
            var shell = document.createElement("div");
            shell.className = "results-table-shell";
            table.parentNode.insertBefore(shell, table);
            shell.appendChild(table);
        }
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "report-theme-toggle";
        btn.setAttribute("aria-label", "Toggle report theme");
        btn.innerHTML = saved === "dark" ? "☀️" : "🌙";
        btn.title = "Toggle theme";
        // Auto-hide toggle when embedded in an iframe (parent dashboard owns the toggle)
        try { if (window.self !== window.top) btn.classList.add("iframe-hidden"); } catch(e) { btn.classList.add("iframe-hidden"); }
        btn.onclick = function() {
            var current = document.documentElement.getAttribute("data-theme");
            var next = current === "dark" ? "light" : "dark";
            document.documentElement.setAttribute("data-theme", next);
            localStorage.setItem("qa-theme", next);
            btn.innerHTML = next === "dark" ? "☀️" : "🌙";
        };
        document.body.appendChild(btn);
    });
})();
</script>
'''


@app.route("/view_report")
def view_report():
    """Serve report.html with injected theme CSS (opens in new tab)."""
    if "username" not in session:
        return redirect(url_for("login"))

    session_id = request.args.get("session_id")
    target_report = None
    if session_id:
        cand = os.path.join(REPORTS_DIR, f"report_{session_id}.html")
        if os.path.exists(cand):
            target_report = cand

    if not target_report and os.path.exists(REPORT_PATH):
        target_report = REPORT_PATH

    if not target_report or not os.path.exists(target_report):
        return "<h2>No report found. Please run a scan first.</h2>", 404

    with open(target_report, "r", encoding="utf-8") as f:
        html = f.read()

    # Inject theme CSS and toggle script before </head>
    theme_css = get_report_theme_css()
    html = html.replace("</head>", theme_css + "\n</head>")

    return html


@app.route("/download_report")
def download_report():
    """Force-download report.html."""
    if "username" not in session:
        return redirect(url_for("login"))

    session_id = request.args.get("session_id")
    target_report = None
    if session_id:
        cand = os.path.join(REPORTS_DIR, f"report_{session_id}.html")
        if os.path.exists(cand):
            target_report = cand

    if not target_report and os.path.exists(REPORT_PATH):
        target_report = REPORT_PATH

    if not target_report or not os.path.exists(target_report):
        return "<h2>No report found. Please run a scan first.</h2>", 404

    download_name = f"qa_report_{session_id}.html" if session_id else "qa_report.html"
    return send_file(target_report, as_attachment=True, download_name=download_name)



if __name__ == "__main__":
    app.run(debug=True, threaded=True)