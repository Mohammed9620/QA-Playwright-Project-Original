"""
conftest.py — pytest-html report customization hooks.

Sets a custom report title so the injected theme CSS in app.py
displays a proper branded header.
"""
import pytest


@pytest.hookimpl(optionalhook=True)
def pytest_html_report_title(report):
    """Override the default pytest-html report title."""
    report.title = "QA Automation Engine — Test Report"
