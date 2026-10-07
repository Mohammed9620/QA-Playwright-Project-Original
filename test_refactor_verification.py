"""
Test script verifying Flask blueprint routes, URL endpoints, and imports.
"""

import os
import re
from datetime import datetime, timezone, timedelta
import pytest
from app import app
from db import _scan_results, _scan_creds

def test_endpoints_registered():
    rules = {r.endpoint: r.rule for r in app.url_map.iter_rules()}
    
    # Expected auth endpoints
    assert "auth.login" in rules, "auth.login endpoint missing"
    assert "auth.logout" in rules, "auth.logout endpoint missing"
    assert "auth.signup" in rules, "auth.signup endpoint missing"
    assert "auth.create_admin" in rules, "auth.create_admin endpoint missing"
    
    # Expected scan endpoints
    assert "scan.prepare_scan" in rules, "scan.prepare_scan endpoint missing"
    assert "scan.stream_scan" in rules, "scan.stream_scan endpoint missing"
    assert "scan.scan_result" in rules, "scan.scan_result endpoint missing"
    assert "scan.results" in rules, "scan.results endpoint missing"
    assert "scan.view_report" in rules, "scan.view_report endpoint missing"
    assert "scan.download_report" in rules, "scan.download_report endpoint missing"
    
    # Expected app endpoints
    assert "home" in rules, "home endpoint missing"
    assert "static" in rules, "static endpoint missing"

def test_url_paths_preserved():
    rules = {r.endpoint: r.rule for r in app.url_map.iter_rules()}
    
    assert rules["auth.login"] == "/login"
    assert rules["auth.logout"] == "/logout"
    assert rules["auth.signup"] == "/signup"
    assert rules["auth.create_admin"] == "/admin/create_admin"
    assert rules["scan.prepare_scan"] == "/prepare_scan"
    assert rules["scan.stream_scan"] == "/stream_scan"
    assert rules["scan.scan_result"] == "/scan_result/<session_id>"
    assert rules["scan.results"] == "/results"
    assert rules["scan.view_report"] == "/view_report"
    assert rules["scan.download_report"] == "/download_report"
    assert rules["home"] == "/"

def test_no_old_endpoint_names_in_url_for():
    old_endpoints = {
        "login", "logout", "signup", "create_admin",
        "prepare_scan", "stream_scan", "scan_result", "results",
        "view_report", "download_report"
    }
    
    found_old = []
    
    for root, dirs, files in os.walk('.'):
        if any(p in root for p in ['.git', '.venv', '__pycache__', '.pytest_cache']):
            continue
        for f in files:
            if f.endswith(('.py', '.html')) and f != 'test_refactor_verification.py':
                p = os.path.join(root, f)
                with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
                    for idx, line in enumerate(fh, 1):
                        matches = re.findall(r'url_for\s*\(\s*["\']([^"\']+)["\']', line)
                        for m in matches:
                            if m in old_endpoints:
                                found_old.append(f"{p}:{idx}: url_for('{m}')")
                                
    assert not found_old, f"Found old endpoint names in url_for calls: {found_old}"

def test_unauthenticated_redirects():
    client = app.test_client()
    
    # Unauthenticated / should redirect to /login
    resp = client.get("/")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/login"

    # Unauthenticated /results should redirect to /login
    resp = client.get("/results")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/login"

    # Unauthenticated /view_report should redirect to /login
    resp = client.get("/view_report")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/login"

    # Unauthenticated /download_report should redirect to /login
    resp = client.get("/download_report")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/login"

    # /login should render 200
    resp = client.get("/login")
    assert resp.status_code == 200

    # /signup should render 200
    resp = client.get("/signup")
    assert resp.status_code == 200

def test_authenticated_access():
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = "testuser"
        sess["role"] = "user"
        sess["last_activity"] = datetime.now(timezone.utc).isoformat()

    # / should render 200 when authenticated
    resp = client.get("/")
    assert resp.status_code == 200

def test_session_inactivity_timeout():
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = "testuser"
        sess["role"] = "user"
        # 31 minutes ago
        past = datetime.now(timezone.utc) - timedelta(minutes=31)
        sess["last_activity"] = past.isoformat()

    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
    assert "error=Session+expired+due+to+inactivity" in resp.headers["Location"] or "Session%20expired" in resp.headers["Location"]

def test_scan_unauthorized_endpoints():
    client = app.test_client()
    
    # prepare_scan requires auth
    resp = client.post("/prepare_scan", json={"url": "http://example.com"})
    assert resp.status_code == 401

    # stream_scan requires auth
    resp = client.get("/stream_scan?url=http://example.com")
    assert resp.status_code == 401

    # scan_result requires auth
    resp = client.get("/scan_result/12345")
    assert resp.status_code == 401
