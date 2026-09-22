import os
import re
import pytest
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright, Page, expect

# ──────────────────────────────────────────────
#  Load environment variables from .env file
# ──────────────────────────────────────────────
_env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(_env_path)

def get_credentials():
    target_url = os.getenv("TARGET_URL")
    test_user  = os.getenv("TEST_USER")
    test_pass  = os.getenv("TEST_PASS")
    if not all([target_url, test_user, test_pass]):
        pytest.skip(
            "[SKIP] One or more required environment variables are missing (TARGET_URL, TEST_USER, TEST_PASS)."
        )
    return target_url, test_user, test_pass



# ──────────────────────────────────────────────
#  Page Object: LoginPage
# ──────────────────────────────────────────────
class LoginPage:
    """Encapsulates all interactions with the login page.
    The target URL and credentials are injected at runtime from .env.
    """

    def __init__(self, page: Page, url: str):
        self.page = page
        self.url  = url

    # ── Locator Map ──────────────────────────────
    def Maps(self) -> dict:
        """Returns a dictionary of all locators used on the Login page."""
        return {
            "username_field": self.page.locator(os.getenv("USER_LOCATOR", "#user-name")),
            "password_field": self.page.locator(os.getenv("PASS_LOCATOR", "#password")),
            "login_button":   self.page.locator(os.getenv("LOGIN_LOCATOR", "#login-button")),
        }

    # ── Actions ──────────────────────────────────
    def navigate(self):
        """Opens the login page in the browser."""
        self.page.goto(self.url)
        print(f"[INFO] Navigated to: {self.url}")

    def login(self, username: str, password: str):
        """Fills in credentials and clicks the Login button."""
        locators = self.Maps()

        locators["username_field"].fill(username)
        print(f"[INFO] Entered username: {username}")

        locators["password_field"].fill(password)
        print(f"[INFO] Entered password: {'*' * len(password)}")

        locators["login_button"].click()
        print("[INFO] Clicked the Login button.")


# ──────────────────────────────────────────────
#  pytest Test Function
# ──────────────────────────────────────────────
def test_login():
    """Verifies that a valid user can log in and reach the inventory page."""
    target_url, test_user, test_pass = get_credentials()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Instantiate the page object — URL is injected from .env, not hardcoded
        login_page = LoginPage(page, url=target_url)

        # Execute the login flow — credentials come from .env
        login_page.navigate()
        login_page.login(username=test_user, password=test_pass)

        # Web-first wait for redirect
        expect(page).to_have_url(re.compile(r".*/inventory\.html"), timeout=8000)
        print(f"[INFO] Final URL: {page.url}")

        # ── Assertion ────────────────────────────────
        assert "/inventory.html" in page.url, (
            f"[FAIL] Login did not redirect to inventory page. "
            f"Actual URL: {page.url}"
        )
        print("[PASS] Assertion passed — inventory page loaded successfully.")

        browser.close()


# ──────────────────────────────────────────────
#  pytest Test Function — Negative Case
# ──────────────────────────────────────────────
def test_invalid_login():
    """Verifies that invalid credentials are rejected and an error is shown."""
    target_url, _, _ = get_credentials()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Reuse the LoginPage class with the same target URL from .env
        login_page = LoginPage(page, url=target_url)

        # Navigate and attempt login with deliberately wrong credentials
        login_page.navigate()
        login_page.login(username="invalid_user", password="wrong_pass")

        # Auto-retry web-first assertions
        error_banner = page.locator("[data-test='error']")
        expect(error_banner).to_be_visible(timeout=5000)
        expect(error_banner).to_contain_text("Username and password do not match", timeout=5000)

        print(f"[INFO] Final URL after invalid login: {page.url}")

        # ── Assertions ───────────────────────────────
        # 1. The page must NOT have navigated away from the login screen
        assert "/inventory.html" not in page.url, (
            "[FAIL] Invalid login unexpectedly redirected to inventory page."
        )

        error_text = error_banner.inner_text()
        print(f"[PASS] Error banner visible with message: '{error_text}'")

        browser.close()

