"""
scan_helpers.py
---------------
Scan configuration constants and pure utility functions for the QA Automation
Engine.  No Flask imports; safe to import from any module without circular
dependency risk.

Exports:
  SCAN_MAP, SCAN_LABELS           – scan-type to test-file mappings.
  parse_pytest_summary(output)    – parse pytest terminal output into counts.
  format_milestone_log(line, url) – format a single log line for the SSE stream.
  normalize_url(url)              – sanitise / auto-complete a target URL.
"""

import re


# ── Scan type → pytest file mapping ───────────────────────────────────────────

SCAN_MAP = {
    "login":      [("main_test.py",        "Login Test")],
    "bruteforce": [("test_credentials.py", "Credential Bruteforce Probe")],
    "api":        [("test_api.py",         "API Health Check")],
    "auth":       [("test_auth.py",        "Broken Authentication Check")],
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


# ── Pytest output parser ───────────────────────────────────────────────────────

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


# ── SSE log formatter ──────────────────────────────────────────────────────────

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


# ── URL sanitiser ──────────────────────────────────────────────────────────────

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
