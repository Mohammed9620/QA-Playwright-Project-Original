"""
routes/scan.py
--------------
Flask Blueprint for test scanning, SSE streaming, and test report generation:
  /prepare_scan, /stream_scan, /scan_result/<session_id>, /results,
  /view_report, /download_report
"""

import os
import json
import uuid
import subprocess
import time
import shutil
from datetime import datetime

from flask import (
    Blueprint, render_template, request,
    redirect, url_for, session, jsonify, Response,
)

from db import (
    REPORTS_DIR, REPORT_PATH,
    _scan_results, _scan_creds,
)
from scan_helpers import (
    SCAN_MAP, SCAN_LABELS,
    parse_pytest_summary, format_milestone_log, normalize_url,
)
from report_theme import get_report_theme_css

scan = Blueprint("scan", __name__)


# ── Scan Preparation ──────────────────────────────────────────────────────────

@scan.route("/prepare_scan", methods=["POST"])
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


# ── Scan Stream (SSE) ─────────────────────────────────────────────────────────

@scan.route("/stream_scan")
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
                        "line": f"Status: \u2705 Test suite '{label}' passed ({elapsed_s}s).",
                        "timestamp": now.strftime("%H:%M:%S")
                    }) + "\n\n"
                else:
                    yield "data: " + json.dumps({
                        "type": "log",
                        "file": test_file,
                        "label": label,
                        "line": f"Status: \u274c Test suite '{label}' failed ({elapsed_s}s).",
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
                    "line": f"Status: \u274c Test suite '{label}' timed out.",
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
                    "line": f"Status: \u274c Execution failed: {str(exc)}",
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
                "line": f"Status: \u2705 Scan complete - {total_passed} passed, {total_failed} failed.",
                "timestamp": now.strftime("%H:%M:%S")
            }) + "\n\n"
        else:
            yield "data: " + json.dumps({
                "type": "log",
                "file": "summary",
                "label": "Summary",
                "line": f"Status: \u274c Scan complete - {total_passed} passed, {total_failed} failed.",
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


# ── Scan Results & Reports ────────────────────────────────────────────────────

@scan.route("/scan_result/<session_id>")
def scan_result(session_id):
    """Return the stored scan result for a given session (used as fallback)."""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = _scan_results.get(session_id)
    if not data:
        return jsonify({"error": "No result found for this session."}), 404
    return jsonify(data)


@scan.route("/results")
def results():
    """Render the results page; data comes from query-string params set by JS."""
    if "username" not in session:
        return redirect(url_for("auth.login"))
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


@scan.route("/view_report")
def view_report():
    """Serve report.html with injected theme CSS (opens in new tab)."""
    if "username" not in session:
        return redirect(url_for("auth.login"))

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


@scan.route("/download_report")
def download_report():
    """Force-download report.html."""
    if "username" not in session:
        return redirect(url_for("auth.login"))

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

    download_name = f"qa_report_{session_id}.html" if session_id else "qa_report.html"
    return Response(html, mimetype="text/html", headers={"Content-Disposition": f"attachment; filename={download_name}"})
