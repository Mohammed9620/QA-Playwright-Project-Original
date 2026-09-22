import os
import time
import requests
import pytest
from dotenv import load_dotenv


# ──────────────────────────────────────────────
#  Load environment variables from .env file
# ──────────────────────────────────────────────
_env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(_env_path)


# ──────────────────────────────────────────────
#  API Client Object: APIEndpoint
#  Follows the same structural pattern as LoginPage in main_test.py
# ──────────────────────────────────────────────
class APIEndpoint:
    """Encapsulates HTTP interactions with a target API endpoint."""

    def __init__(self, base_url: str, expected_status: int = 200, sla_ms: int = 3000):
        self.base_url        = base_url.rstrip("/")
        self.expected_status = expected_status
        self.sla_ms          = sla_ms
        self.session         = requests.Session()

    def get(self, path: str = "") -> dict:
        """Sends a GET request and returns a result dict with status, elapsed_ms, ok."""
        url = f"{self.base_url}/{path}".rstrip("/")
        print(f"[INFO] GET {url}")

        start    = time.monotonic()
        response = self.session.get(url, timeout=30, allow_redirects=True)
        elapsed  = (time.monotonic() - start) * 1000  # convert to ms

        print(f"[INFO] Status: {response.status_code} | Elapsed: {elapsed:.1f}ms")
        return {
            "url":        url,
            "status":     response.status_code,
            "elapsed_ms": elapsed,
            "headers":    dict(response.headers),
            "ok":         response.ok,
            "text":       response.text,
        }

    def post(self, path: str = "", payload: dict = None) -> dict:
        """Sends a POST request and returns a result dict."""
        url     = f"{self.base_url}/{path}".rstrip("/")
        payload = payload or {}
        print(f"[INFO] POST {url} | payload keys: {list(payload.keys())}")

        start    = time.monotonic()
        response = self.session.post(url, json=payload, timeout=30, allow_redirects=True)
        elapsed  = (time.monotonic() - start) * 1000

        print(f"[INFO] Status: {response.status_code} | Elapsed: {elapsed:.1f}ms")
        return {
            "url":        url,
            "status":     response.status_code,
            "elapsed_ms": elapsed,
            "headers":    dict(response.headers),
            "ok":         response.ok,
            "text":       response.text,
        }

    def close(self):
        self.session.close()


def get_api_endpoint() -> APIEndpoint:
    target_url = os.getenv("TARGET_URL")
    if not target_url:
        pytest.skip("[SKIP] TARGET_URL is not configured.")
    expected_status = int(os.getenv("API_EXPECTED_STATUS", "200"))
    sla_ms          = int(os.getenv("API_SLA_MS", "3000"))
    return APIEndpoint(base_url=target_url, expected_status=expected_status, sla_ms=sla_ms)



# ──────────────────────────────────────────────
#  pytest Test Functions
# ──────────────────────────────────────────────
def test_api_get_status():
    """Verifies that a GET request to the target URL returns the expected HTTP status code."""
    endpoint = get_api_endpoint()

    try:
        result = endpoint.get()
    except requests.exceptions.ConnectionError as exc:
        raise AssertionError(
            f"[FAIL] Could not connect to {endpoint.base_url}: {exc}"
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise AssertionError(
            f"[FAIL] Request to {endpoint.base_url} timed out: {exc}"
        ) from exc
    finally:
        endpoint.close()

    assert result["status"] == endpoint.expected_status, (
        f"[FAIL] Expected HTTP {endpoint.expected_status}, got {result['status']} "
        f"for URL: {result['url']}"
    )
    print(f"[PASS] GET status check passed — HTTP {result['status']}.")


def test_api_response_time_sla():
    """Verifies that the target endpoint responds within the configured SLA (default 3000ms)."""
    endpoint = get_api_endpoint()

    try:
        result = endpoint.get()
    except requests.exceptions.ConnectionError as exc:
        raise AssertionError(
            f"[FAIL] Could not connect to {endpoint.base_url}: {exc}"
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise AssertionError(
            f"[FAIL] Request timed out before SLA could be measured: {exc}"
        ) from exc
    finally:
        endpoint.close()

    assert result["elapsed_ms"] <= endpoint.sla_ms, (
        f"[FAIL] Response time {result['elapsed_ms']:.1f}ms exceeded SLA of {endpoint.sla_ms}ms "
        f"for URL: {result['url']}"
    )
    print(
        f"[PASS] Response time SLA passed — {result['elapsed_ms']:.1f}ms "
        f"(SLA: {endpoint.sla_ms}ms)."
    )

