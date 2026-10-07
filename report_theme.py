"""
report_theme.py
---------------
Provides the HTML/CSS/JS snippet that is injected into pytest-html test reports
to apply the custom QA-dashboard dark/light theme and the interactive theme-toggle
button.  Import ``get_report_theme_css`` from here and call it wherever report
HTML is served or downloaded.
"""


def get_report_theme_css():
    """Return a <style> block + theme toggle script to inject into report.html."""
    return '''
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* ── Report Theme Override ── */
:root {
    --r-bg: #0d0a08;
    --r-surface: #14100e;
    --r-card: #1a1614;
    --r-elevated: #1a1614;
    --r-border: rgba(255, 255, 255, 0.12);
    --r-border-muted: rgba(255, 255, 255, 0.08);
    --r-faint: rgba(255, 255, 255, 0.32);
    --r-text: #ffffff;
    --r-text-muted: rgba(255, 255, 255, 0.56);
    --r-success: #2FD59A;
    --r-danger: #FF5D6C;
    --r-warning: #F5B942;
    --r-accent: #2FD59A;
    --r-success-bg: rgba(47, 213, 154, 0.12);
    --r-danger-bg: rgba(255, 93, 108, 0.12);
    --r-warning-bg: rgba(245, 185, 66, 0.12);
    --r-accent-bg: rgba(47, 213, 154, 0.12);
    --r-font: -apple-system, BlinkMacSystemFont, "SF Pro Display", Inter, system-ui, sans-serif;
    --r-mono: 'JetBrains Mono', 'Fira Code', monospace;
    --r-radius: 16px;
    --dur-fast: 180ms;
    --dur-base: 300ms;
    --dur-slow: 500ms;
    --ease: cubic-bezier(0.32, 0.72, 0, 1);
    color-scheme: dark;
}
@media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {
        --r-bg: #f2f2f7;
        --r-surface: #ffffff;
        --r-card: #ffffff;
        --r-elevated: #f2f2f5;
        --r-border: rgba(0, 0, 0, 0.12);
        --r-border-muted: rgba(0, 0, 0, 0.06);
        --r-faint: rgba(28, 28, 30, 0.32);
        --r-text: #1c1c1e;
        --r-text-muted: rgba(28, 28, 30, 0.56);
        --r-success: #12A36F;
        --r-danger: #E03B4B;
        --r-warning: #D97706;
        --r-accent: #12A36F;
        --r-success-bg: rgba(18, 163, 111, 0.1);
        --r-danger-bg: rgba(224, 59, 75, 0.1);
        --r-warning-bg: rgba(217, 119, 6, 0.1);
        --r-accent-bg: rgba(18, 163, 111, 0.1);
        color-scheme: light;
    }
}
[data-theme="light"] {
    --r-bg: #f2f2f7;
    --r-surface: #ffffff;
    --r-card: #ffffff;
    --r-elevated: #f2f2f5;
    --r-border: rgba(0, 0, 0, 0.12);
    --r-border-muted: rgba(0, 0, 0, 0.06);
    --r-faint: rgba(28, 28, 30, 0.32);
    --r-text: #1c1c1e;
    --r-text-muted: rgba(28, 28, 30, 0.56);
    --r-success: #12A36F;
    --r-danger: #E03B4B;
    --r-warning: #D97706;
    --r-accent: #12A36F;
    --r-success-bg: rgba(18, 163, 111, 0.1);
    --r-danger-bg: rgba(224, 59, 75, 0.1);
    --r-warning-bg: rgba(217, 119, 6, 0.1);
    --r-accent-bg: rgba(18, 163, 111, 0.1);
    color-scheme: light;
}
* { box-sizing: border-box; }
html { background: var(--r-bg); }
body {
    font-family: var(--r-font) !important;
    font-size: 14px !important;
    background: var(--r-bg) !important;
    color: var(--r-text) !important;
    padding: 24px 32px !important;
    min-width: auto !important;
    max-width: 1280px;
    margin: 0 auto !important;
    line-height: 1.5;
}
h1 { font-size: 20px !important; font-weight: 700 !important; color: var(--r-text) !important; margin: 0 48px 5px 0 !important; letter-spacing: -0.02em; }
h2 { font-size: 15px !important; font-weight: 600 !important; color: var(--r-text) !important; margin: 0 !important; }
p { color: var(--r-text-muted) !important; font-size: 13px !important; margin: 0 !important; }
a { color: var(--r-accent) !important; transition: color var(--dur-fast) var(--ease); }
a:hover { color: var(--r-text) !important; }
table { border-collapse: collapse !important; width: 100% !important; }

.report-header {
    position: relative;
    margin-bottom: 18px;
    padding: 20px 24px;
    background: var(--r-surface);
    border: 1px solid var(--r-border);
    border-radius: var(--r-radius);
}
.report-header::before {
    content: "";
    position: absolute;
    top: 0;
    left: 24px;
    width: 48px;
    height: 2px;
    background: var(--r-accent);
}

#environment-header {
    padding: 16px 20px;
    background: var(--r-surface);
    border: 1px solid var(--r-border);
    border-bottom: 0;
    border-radius: var(--r-radius) var(--r-radius) 0 0;
    cursor: pointer;
}
#environment-header h2 {
    font-size: 14px !important;
    font-weight: 600 !important;
}

#environment {
    width: 100% !important;
    margin: 0 0 18px !important;
    border: 1px solid var(--r-border) !important;
    border-collapse: separate !important;
    border-spacing: 0;
    border-radius: 0 0 var(--r-radius) var(--r-radius);
    overflow: hidden;
    background: var(--r-surface);
}
#environment td {
    padding: 10px 16px !important;
    border: 0 !important;
    border-top: 1px solid var(--r-border-muted) !important;
    font-size: 13px !important;
    color: var(--r-text) !important;
    font-family: var(--r-font) !important;
}
#environment td:first-child {
    width: 160px;
    color: var(--r-text-muted) !important;
    font: 500 12px/1.5 var(--r-font) !important;
}
#environment tr { background: transparent !important; }

.summary {
    display: block !important;
    margin: 0 0 18px !important;
    padding: 20px !important;
    background: var(--r-surface);
    border: 1px solid var(--r-border);
    border-radius: var(--r-radius);
}
.summary h2 { margin: 0 0 6px !important; font-size: 14px !important; }
.run-count { margin: 0 0 14px !important; color: var(--r-text) !important; font: 500 13px/1.5 var(--r-font) !important; }
.summary p.filter { margin: 0 0 10px !important; color: var(--r-faint) !important; font-size: 12px !important; }
.controls { display: flex !important; align-items: flex-end; justify-content: space-between; flex-wrap: wrap !important; gap: 12px !important; }
.filters { display: flex !important; flex-wrap: wrap !important; gap: 8px !important; }
.filter-chip { position: relative; display: inline-flex; align-items: center; cursor: pointer; }
.filter-chip input { position: absolute; opacity: 0; pointer-events: none; }
.filter-chip span {
    padding: 6px 12px;
    border: 1px solid var(--r-border);
    border-radius: 999px;
    background: var(--r-elevated);
    color: var(--r-text-muted) !important;
    font: 500 12px/1 var(--r-font) !important;
    transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease), opacity var(--dur-fast) var(--ease);
}
.filter-chip:hover span { border-color: var(--r-accent); }
.filter-chip input:not(:checked)+span { opacity: 0.4; text-decoration: line-through; }
.filter-chip input:focus-visible+span { outline: 2px solid var(--r-accent); outline-offset: 2px; }
.filter-chip input:disabled+span { opacity: 0.45; cursor: not-allowed; }
.filter-chip span.passed { color: var(--r-success) !important; border-color: rgba(47,213,154,0.3); background: var(--r-success-bg); }
.filter-chip span.failed, .filter-chip span.error { color: var(--r-danger) !important; border-color: rgba(255,93,108,0.3); background: var(--r-danger-bg); }
.filter-chip span.skipped, .filter-chip span.xfailed, .filter-chip span.rerun, .filter-chip span.retried { color: var(--r-warning) !important; border-color: rgba(245,185,66,0.3); background: var(--r-warning-bg); }
.filter-chip span.xpassed { color: var(--r-accent) !important; background: var(--r-accent-bg); }

.collapse { display: flex !important; flex-wrap: wrap !important; gap: 8px !important; }
.collapse button {
    padding: 6px 12px !important;
    border: 1px solid var(--r-border) !important;
    border-radius: 999px !important;
    background: var(--r-elevated) !important;
    color: var(--r-text-muted) !important;
    font: 500 12px var(--r-font) !important;
    cursor: pointer;
    transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
}
.collapse button:hover { color: var(--r-text) !important; border-color: var(--r-accent) !important; }
.collapse button:focus-visible { outline: 2px solid var(--r-accent); outline-offset: 2px; }

.results-table-shell {
    width: 100%;
    overflow-x: auto;
    border: 1px solid var(--r-border);
    border-radius: var(--r-radius);
    background: var(--r-surface);
}
#results-table {
    width: 100% !important;
    min-width: 680px;
    margin: 0 !important;
    border: 0 !important;
    border-collapse: collapse !important;
    font-size: 13px !important;
}
#results-table th, #results-table td {
    padding: 12px 14px !important;
    border: 0 !important;
    border-bottom: 1px solid var(--r-border-muted) !important;
    text-align: left;
}
#results-table th {
    background: var(--r-elevated) !important;
    color: var(--r-text-muted) !important;
    font: 600 12px/1.4 var(--r-font) !important;
    letter-spacing: normal;
    text-transform: none;
}
#results-table tr.collapsible { background: var(--r-surface); transition: background var(--dur-fast) var(--ease); }
#results-table tr.collapsible:hover { background: var(--r-elevated); }
#results-table .col-result { width: 110px; font-weight: 600; }
#results-table .col-testId { min-width: 300px; overflow-wrap: anywhere; font-family: var(--r-font); }
#results-table .col-duration { width: 110px; color: var(--r-text-muted); font-family: var(--r-mono); white-space: nowrap; font-size: 12px; }
#results-table .col-links { width: 100px; }
.passed .col-result { color: var(--r-success) !important; }
.failed .col-result, .error .col-result { color: var(--r-danger) !important; }
.skipped .col-result, .xfailed .col-result, .rerun .col-result, .retried .col-result { color: var(--r-warning) !important; }

.extras-row td { padding: 0 14px 14px !important; background: var(--r-bg); }
.logwrapper { margin-top: 8px; border-radius: 8px !important; border: 1px solid var(--r-border) !important; background: var(--r-surface) !important; }
.logwrapper .log { max-height: 420px; overflow: auto; line-height: 1.55; font-family: var(--r-mono) !important; font-size: 12px !important; color: var(--r-text) !important; padding: 12px !important; }
.logwrapper .log .error { color: var(--r-danger) !important; }
.logwrapper .logexpander { background: var(--r-elevated) !important; color: var(--r-text-muted) !important; border-color: var(--r-border) !important; font-size: 12px !important; border-radius: 6px !important; }

.report-theme-toggle {
    position: absolute;
    top: 24px;
    right: max(32px, calc((100vw - 1280px)/2 + 32px));
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: var(--r-surface);
    border: 1px solid var(--r-border);
    color: var(--r-text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
}
.report-theme-toggle.iframe-hidden { display: none !important; }
.report-theme-toggle:focus-visible { outline: 2px solid var(--r-accent); outline-offset: 2px; }

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { transition-duration: 0.01s !important; animation-duration: 0.01s !important; }
}
@media (max-width: 700px) {
    body { padding: 16px 12px 32px !important; }
    .report-header { padding: 16px; }
    .report-header h1 { font-size: 18px !important; }
    .report-theme-toggle { top: 20px; right: 20px; }
    #environment td { display: block; width: 100% !important; padding: 8px 12px !important; }
    #environment td:first-child { padding-bottom: 2px !important; border-bottom: 0 !important; }
    #environment td+td { padding-top: 2px !important; }
    .summary { padding: 14px !important; }
    .controls { align-items: stretch; }
    .filters { width: 100%; }
    .results-table-shell { overscroll-behavior-x: contain; }
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
