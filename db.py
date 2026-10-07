"""
db.py
-----
Shared database path constants, in-memory bounded caches, and the DB schema
migration helper for the QA Automation Engine.

Import DB_PATH, REPORTS_DIR, REPORT_PATH, BoundedCache, _scan_results,
_scan_creds, and _scan_lock from here instead of defining them in app.py.
"""

import os
import sqlite3
import threading
from collections import OrderedDict


# ── Path constants ─────────────────────────────────────────────────────────────

DB_PATH     = os.path.join(os.path.dirname(__file__), "users.db")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
REPORT_PATH = os.path.join(os.path.dirname(__file__), "report.html")

os.makedirs(REPORTS_DIR, exist_ok=True)


# ── Bounded in-memory LRU cache ────────────────────────────────────────────────

class BoundedCache:
    """Thread-safe LRU evicting dict with a fixed maximum size."""

    def __init__(self, maxsize: int = 100):
        self._cache: OrderedDict = OrderedDict()
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
_scan_creds   = BoundedCache(maxsize=50)
_scan_lock    = threading.Lock()


# ── Schema migration ───────────────────────────────────────────────────────────

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


# Run migration eagerly on first import (same behaviour as before)
ensure_db_schema()
