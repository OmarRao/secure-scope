"""
SecureScope smoke tests — fast, network-free QA checks.

Covers: module imports, the secrets engine, the shared PDF report HTML builder,
CWE→ATT&CK mapping, and that the Flask app object initialises. Run with:

    pip install pytest && python -m pytest -q
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_core_modules_import():
    import analyzer  # noqa: F401
    import secrets_scanner  # noqa: F401
    import dependency_scanner  # noqa: F401
    import report_html  # noqa: F401
    import pdf_report  # noqa: F401
    import live_intel  # noqa: F401


def test_flask_app_initialises():
    import ui.server as server
    assert server.app is not None
    assert server.socketio is not None
    assert server.REPORTS_DIR.exists()


def test_cwe_to_attack_mapping():
    import analyzer
    assert isinstance(analyzer.CWE_TO_ATTACK, dict)
    assert "CWE-89" in analyzer.CWE_TO_ATTACK  # SQL injection is always mapped


def test_secrets_scanner_detects_and_shapes():
    import secrets_scanner
    d = tempfile.mkdtemp()
    Path(d, "config.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'db = "postgres://user:p4ssw0rd@host:5432/db"\n'
        'api_key = "changeme"  # placeholder, must be ignored\n',
        encoding="utf-8",
    )
    res = secrets_scanner.scan_repo(d, include_history=False, entropy_check=True)
    dd = res.to_dict()
    # required keys the report template consumes
    for k in ("total_findings", "critical_count", "high_count", "files_scanned", "findings"):
        assert k in dd
    assert dd["total_findings"] >= 2  # AWS key + postgres URI
    assert dd["critical_count"] >= 1
    for f in dd["findings"]:
        for key in ("severity", "category", "file", "line", "blast_radius"):
            assert key in f
    # placeholder value must not be flagged
    assert not any("changeme" in (f.get("description", "") or "") for f in dd["findings"])


def test_secrets_pattern_categories():
    import secrets_scanner
    cats = secrets_scanner.list_pattern_categories()
    assert isinstance(cats, list) and len(cats) >= 5
    assert all("category" in c and "count" in c for c in cats)


def test_report_html_builder():
    from report_html import build_html
    data = {
        "repo": "https://github.com/OmarRao/analyzer",
        "summary": {},
        "findings": [
            {"severity": "ERROR", "cwe": "CWE-89", "rule_id": "a.b.sql-injection",
             "file": "app/db.py", "line_start": 10, "message": "SQL injection"},
            {"severity": "WARNING", "cwe": "CWE-79", "rule_id": "a.b.xss",
             "file": "app/views.py", "line_start": 20, "message": "XSS"},
        ],
        "dependency_vulns": [{"package": "flask", "vuln_id": "CVE-x"}],
    }
    html, owner, slug = build_html(data)
    assert owner == "OmarRao" and slug == "analyzer"
    assert "Static Analysis" in html
    assert "Composite Risk Score" in html
    assert "OmarRao/analyzer" in html


def test_security_headers_and_secret_key():
    import ui.server as server
    # No hardcoded secret key in source
    assert server.app.secret_key != "secreview-ui-key"
    assert server.app.secret_key  # some key is set
    client = server.app.test_client()
    r = client.get("/")
    for h in ("X-Content-Type-Options", "X-Frame-Options",
              "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"):
        assert h in r.headers, f"missing security header: {h}"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src" in r.headers["Content-Security-Policy"]


def test_report_html_escapes_untrusted_repo():
    from report_html import build_html
    html, _, _ = build_html({"repo": "https://github.com/x/<script>", "findings": [], "dependency_vulns": []})
    assert "<script>" not in html.split("</head>")[-1]  # repo name is escaped in body
