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


def test_exploit_intel_enrich_offline():
    """EPSS/KEV enrichment shapes vulns correctly, with feeds stubbed out."""
    import exploit_intel as ei
    ei.epss_scores = lambda cves: {
        "CVE-2021-44228": {"epss": 0.99999, "pct": 1.0},
        "CVE-2020-8203": {"epss": 0.05, "pct": 0.91},
    }
    ei.kev_set = lambda: {"CVE-2021-44228"}
    deps = {"vulnerabilities": [
        {"package_name": "lodash", "aliases": ["CVE-2020-8203"], "vuln_id": "",
         "severity": "HIGH", "cvss_score": 7.4},
        {"package_name": "log4j", "aliases": ["CVE-2021-44228"], "vuln_id": "GHSA-x",
         "severity": "CRITICAL", "cvss_score": 10.0},
    ]}
    out = ei.enrich_deps(deps)
    assert out["kev_count"] == 1
    assert abs(out["max_epss"] - 0.99999) < 1e-6
    # KEV + highest EPSS must sort first
    top = out["vulnerabilities"][0]
    assert top["package_name"] == "log4j"
    assert top["kev"] is True
    assert top["epss"] == 0.99999


def test_exploit_intel_graceful_on_empty():
    import exploit_intel as ei
    out = ei.enrich_deps({"vulnerabilities": []})
    assert out["kev_count"] == 0 and out["max_epss"] == 0.0
    assert ei.enrich_deps(None) is None


def test_reachability_annotate_offline():
    """Reachability marks imported packages True, unused False, other-eco None."""
    import reachability as rr
    import tempfile, os
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "app.py"), "w") as fh:
        fh.write("import flask\nfrom requests import get\n")
    deps = {"vulnerabilities": [
        {"package_name": "flask", "ecosystem": "PyPI", "severity": "HIGH", "cvss_score": 7.0, "epss": 0.1, "kev": False},
        {"package_name": "unused-lib", "ecosystem": "PyPI", "severity": "CRITICAL", "cvss_score": 9.0, "epss": 0.2, "kev": False},
        {"package_name": "golib", "ecosystem": "Go", "severity": "HIGH", "cvss_score": 7.5, "epss": 0.3, "kev": False},
    ]}
    out = rr.annotate(deps, d)
    by = {v["package_name"]: v for v in out["vulnerabilities"]}
    assert by["flask"]["reachable"] is True and by["flask"]["reachable_files"] >= 1
    assert by["unused-lib"]["reachable"] is False
    assert by["golib"]["reachable"] is None
    assert out["reachable_count"] == 1
    # Reachable flask should sort ahead of the unreachable critical.
    assert out["vulnerabilities"][0]["package_name"] == "flask"


def test_dep_fix_bump_and_plan_offline():
    import dep_fix_pr as d
    new, ch = d.bump_requirements_txt("flask==2.0.0\nrequests>=2.20  # x\n", "flask", "3.1.3")
    assert ch and "flask==3.1.3" in new
    pj = '{"dependencies": {"lodash": "^4.0.0"}}'
    new, ch = d.bump_package_json(pj, "lodash", "4.17.21")
    import json as _j
    assert ch and _j.loads(new)["dependencies"]["lodash"] == "4.17.21"
    assert d._best_fixed(["1.2.0", "1.10.0", "1.9.0"]) == "1.10.0"
    vulns = [
        {"ecosystem": "PyPI", "package_name": "flask", "package_version": "2.0.0",
         "file_path": "/w/requirements.txt", "fixed_versions": ["3.1.3"], "primary_cve": "CVE-1",
         "kev": True, "epss": 0.9, "reachable": True},
        {"ecosystem": "Go", "package_name": "golib", "file_path": "/w/go.mod",
         "fixed_versions": ["1.1"], "primary_cve": "CVE-2"},
    ]
    plan = d.plan_fixes(vulns, "/w")
    assert [e["package"] for e in plan["fixable"]] == ["flask"]
    assert plan["fixable"][0]["fixed"] == "3.1.3"
    assert plan["manual"][0]["package"] == "golib"
    body = d.build_pr_body(plan, 1)
    assert "flask" in body and "KEV" in body


def test_compliance_mapping_shape():
    from compliance import build_compliance_posture
    posture = build_compliance_posture([
        {"cwe": "CWE-79", "rule_id": "r1"},
        {"cwe": "CWE-89", "rule_id": "r2"},
    ])
    assert posture.mapped_findings == 2
    assert posture.owasp  # at least one OWASP category mapped
    import dataclasses
    d = dataclasses.asdict(posture)
    assert "coverage_pct" in d and "pci_dss" in d


def test_sbom_generates_cyclonedx():
    from sbom import generate_sbom
    import json as _json

    class _R:
        dependency_vulns = [{
            "ecosystem": "python", "package": "flask", "version": "2.0.1",
            "vuln_id": "CVE-2023-30861", "severity": "HIGH",
            "fix_versions": ["2.3.2"], "description": "x",
        }]
        repo_url = "https://github.com/OmarRao/secure-scope"

    out = os.path.join(tempfile.gettempdir(), "ss_test.cyclonedx.json")
    generate_sbom(_R(), out)
    bom = _json.loads(Path(out).read_text(encoding="utf-8"))
    os.unlink(out)
    assert bom["bomFormat"] == "CycloneDX"
    assert len(bom["components"]) >= 1
