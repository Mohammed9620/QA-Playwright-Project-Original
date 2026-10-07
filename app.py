"""
app.py
------
Flask application entry point for the QA Automation Engine.
Initializes Flask, configures session timeout, registers blueprints,
and defines the root dashboard route.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, render_template, request, session, redirect, url_for

from routes.auth import auth
from routes.scan import scan

app = Flask(__name__)
_configured_secret = os.environ.get("SECRET_KEY")
if not _configured_secret:
    app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
else:
    app.secret_key = _configured_secret
app.config['SESSION_PERMANENT'] = False

# Register blueprints without url_prefix so existing routes remain identical
app.register_blueprint(auth)
app.register_blueprint(scan)


@app.before_request
def check_session_timeout():
    # Enforce session clears on browser exit
    session.permanent = False

    # Exclude static files and critical authentication endpoints
    if request.endpoint in ['static', 'auth.login', 'auth.signup', 'auth.logout']:
        return

    if "username" in session:
        last_activity_str = session.get("last_activity")
        now = datetime.now(timezone.utc)
        if last_activity_str:
            try:
                last_activity = datetime.fromisoformat(last_activity_str)
                if now - last_activity > timedelta(minutes=30):
                    session.clear()
                    return redirect(url_for("auth.login", error="Session expired due to inactivity."))
            except Exception:
                session.clear()
                return redirect(url_for("auth.login"))
        session["last_activity"] = now.isoformat()


# ──────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────

@app.route("/")
def home():
    """Dashboard — requires an active login session."""
    if "username" not in session:
        return redirect(url_for("auth.login"))
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True, threaded=True)