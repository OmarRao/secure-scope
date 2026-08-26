# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

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


def test_multi_platform_repo_parsing():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ui"))
    from github_info import parse_repo_url, repo_host
    assert repo_host("https://github.com/OmarRao/analyzer") == "github"
    assert repo_host("https://gitlab.com/group/project") == "gitlab"
    assert repo_host("https://bitbucket.org/team/repo") == "bitbucket"
    assert parse_repo_url("https://gitlab.com/group/project") == ("group", "project")
    assert parse_repo_url("git@github.com:foo/bar.git") == ("foo", "bar")
    assert parse_repo_url("https://example.com/not/a/repo") is None


def test_watch_diff_cves():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from watch_check import diff_cves, to_markdown
    current = {
        "CVE-2021-44228": {"package": "log4j", "severity": "CRITICAL", "kev": True, "epss": 0.97},
        "CVE-2023-1": {"package": "x", "severity": "LOW", "kev": False, "epss": 0.01},
        "CVE-OLD": {"package": "y", "severity": "HIGH", "kev": False, "epss": 0.2},
    }
    new = diff_cves(["CVE-OLD"], current)
    assert [a["cve"] for a in new] == ["CVE-2021-44228", "CVE-2023-1"]  # KEV first, then EPSS
    assert diff_cves(current.keys(), current) == []  # nothing new
    md = to_markdown({"generated_at": "now", "repos": [{"repo": "https://github.com/o/r", "new": new, "error": None}], "alert_count": 2, "kev_count": 1})
    assert "CVE-2021-44228" in md and "log4j" in md


def test_rate_check_sliding_window():
    import sys
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "ui"))
    import server

    orig_limit, orig_window, orig_hits = server._RATE_LIMIT, server._RATE_WINDOW, server._rate_hits
    try:
        server._RATE_LIMIT = 3
        server._RATE_WINDOW = 600
        server._rate_hits = server.collections.defaultdict(list)

        # First 3 are allowed, 4th is blocked with a retry hint.
        assert [server._rate_check("1.2.3.4")[0] for _ in range(3)] == [True, True, True]
        blocked, retry = server._rate_check("1.2.3.4")
        assert blocked is False and retry > 0
        # A different IP is unaffected.
        assert server._rate_check("9.9.9.9")[0] is True

        # Disabled (<=0) always fails open.
        server._RATE_LIMIT = 0
        assert all(server._rate_check("1.2.3.4")[0] for _ in range(20))
    finally:
        server._RATE_LIMIT, server._RATE_WINDOW, server._rate_hits = orig_limit, orig_window, orig_hits


def test_badge_score_slug_and_svg():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from badge import compute_score, badge_slug, grade_color, render_svg, badge_for

    # Scoring: errors*10 + warnings*3 + dep_vulns*8, capped, with grade bands.
    low = {"by_severity": {"WARNING": 1}, "dependency_vulns": 0}
    crit = {"by_severity": {"ERROR": 8}, "dependency_vulns": 3}
    assert compute_score(low) == (3, "LOW", "#4c1")
    s, g, c = compute_score(crit)
    assert s == 100 and g == "CRITICAL"
    assert compute_score({}) == (0, "LOW", "#4c1")

    # Slug is stable and Firestore-safe (no slashes) across URL forms.
    assert badge_slug("https://github.com/o/r") == badge_slug("http://github.com/o/r.git")
    assert "/" not in badge_slug("git@github.com:o/r.git")

    assert grade_color("HIGH") == "#fe7d37"
    assert grade_color("nonsense") == "#9f9f9f"

    svg = render_svg("security", "LOW 3", "#4c1")
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>") and "LOW 3" in svg
    assert "CRITICAL 100" in badge_for(crit)


def test_upload_safe_extract():
    import sys, io, zipfile, tempfile, shutil
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from upload_scan import safe_extract_zip, write_snippet, UploadError

    # Happy path: a normal small zip extracts.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "import os\nos.system('x')\n")
        z.writestr("sub/util.py", "y = 1\n")
    d = tempfile.mkdtemp()
    try:
        assert safe_extract_zip(buf.getvalue(), d) == 2
        assert (Path(d) / "app.py").exists() and (Path(d) / "sub" / "util.py").exists()
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # Zip-slip is rejected.
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../../escape.py", "pwned")
    d2 = tempfile.mkdtemp()
    try:
        try:
            safe_extract_zip(evil.getvalue(), d2)
            assert False, "zip-slip should have been rejected"
        except UploadError:
            pass
    finally:
        shutil.rmtree(d2, ignore_errors=True)

    # Snippet + guards.
    d3 = tempfile.mkdtemp()
    try:
        p = write_snippet("print('hi')", "test.py", d3)
        assert Path(p).exists()
        try:
            write_snippet("", "x.py", d3); assert False
        except UploadError:
            pass
    finally:
        shutil.rmtree(d3, ignore_errors=True)

    # Not a zip.
    try:
        safe_extract_zip(b"not a zip", tempfile.mkdtemp()); assert False
    except UploadError:
        pass


def test_pr_event_parsing():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from pr_comment import parse_pr_event

    event = {
        "action": "opened", "number": 7,
        "repository": {"full_name": "o/r", "clone_url": "https://github.com/o/r.git"},
        "pull_request": {"base": {"ref": "main"}, "head": {"ref": "feature-x"}},
    }
    info = parse_pr_event(event)
    assert info["repo_full"] == "o/r" and info["pr_number"] == 7
    assert info["base_branch"] == "main" and info["head_branch"] == "feature-x"

    # Non-actionable actions and non-PR events are ignored.
    assert parse_pr_event({**event, "action": "labeled"}) is None
    assert parse_pr_event({"repository": {"full_name": "o/r"}}) is None
    assert parse_pr_event({}) is None
    # Missing PR number is rejected.
    assert parse_pr_event({"action": "opened", "pull_request": {"base": {"ref": "main"}},
                           "repository": {"full_name": "o/r"}}) is None


def test_diff_scan_classify():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from diff_scan import classify_findings, finding_fingerprint, classification_markdown

    def mk(rule, file, snippet, line):
        return {"rule_id": rule, "file": file, "code_snippet": snippet,
                "line_start": line, "severity": "ERROR"}

    # Same finding shifted by lines → same fingerprint (not new/fixed).
    shifted_base = mk("sqli", "app.py", "  query(x)  ", 10)
    shifted_head = mk("sqli", "app.py", "query(x)", 42)
    assert finding_fingerprint(shifted_base) == finding_fingerprint(shifted_head)

    base = [shifted_base, mk("xss", "old.py", "render(y)", 5)]     # xss will be fixed
    head = [shifted_head, mk("cmdi", "new.py", "os.system(z)", 3)]  # cmdi is new
    cls = classify_findings(base, head)
    assert cls["counts"] == {"new": 1, "fixed": 1, "pre_existing": 1}
    assert cls["new"][0]["rule_id"] == "cmdi"
    assert cls["fixed"][0]["rule_id"] == "xss"
    assert cls["pre_existing"][0]["rule_id"] == "sqli"

    # Empty inputs are safe; markdown renders the counts.
    assert classify_findings([], [])["counts"] == {"new": 0, "fixed": 0, "pre_existing": 0}
    md = classification_markdown(cls, "main")
    assert "New" in md and "cmdi" in md


def test_attack_paths_build():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from attack_path import build_attack_paths, _is_injection

    deps = {"vulnerabilities": [
        {"package_name": "log4j", "primary_cve": "CVE-2021-44228", "severity": "CRITICAL",
         "kev": True, "epss": 0.97, "reachable": True, "reachable_files": 3, "ecosystem": "PyPI"},
        {"package_name": "leftpad", "vuln_id": "GHSA-x", "severity": "LOW",
         "kev": False, "epss": 0.01, "reachable": False, "ecosystem": "npm"},
    ]}
    secrets = {"findings": [{"type": "AWS Access Key", "file": "config.py", "line": 12}]}
    findings = [{"rule_id": "python.sqli", "message": "SQL injection", "severity": "ERROR",
                 "cwe": "CWE-89", "file": "app.py", "line_start": 40}]

    chains = build_attack_paths(deps, secrets, findings)
    ids = [c["id"] for c in chains]
    # The reachable KEV dep, the injection, the secret, and a combined chain all appear.
    assert any("log4j" in i for i in ids)
    assert any(i.startswith("secret-") for i in ids)
    assert any(i.startswith("inj-") for i in ids)
    assert "combined-kill-chain" in ids
    # The low, unreachable, non-KEV dep is NOT an attack path.
    assert not any("leftpad" in i for i in ids)
    # Combined/critical chain sorts to the top; every step cites evidence.
    assert chains[0]["severity"] == "CRITICAL"
    for c in chains:
        assert c["steps"] and all(s.get("evidence") for s in c["steps"])
    # Injection classifier recognises CWE + keyword forms.
    assert _is_injection({"cwe": "CWE-79"})
    assert _is_injection({"message": "possible SSRF here"})
    assert _is_injection({"cwe": "CWE-16", "message": "misconfig"}) is None
    # Empty inputs are safe.
    assert build_attack_paths() == []


def test_report_template_and_pdf_render_attack_paths():
    import sys
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    # Jinja template compiles (catches section syntax errors).
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(str(root / "ui" / "templates")))
    env.get_template("report.html")  # raises TemplateSyntaxError on bad markup
    # PDF builder accepts attack_paths without error and includes the section.
    from report_html import build_html
    result = build_html({
        "repo": "https://github.com/o/r", "findings": [], "summary": {},
        "attack_paths": [{"id": "x", "title": "Full kill-chain", "severity": "CRITICAL",
                          "likelihood": "High", "summary": "demo",
                          "steps": [{"stage": "Entry", "title": "t", "detail": "d", "evidence": "e"}]}],
    })
    html = result[0] if isinstance(result, tuple) else result
    assert "Attack Paths" in html and "Full kill-chain" in html


def test_firebase_auth_fails_open_when_unconfigured():
    import sys
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "ui"))
    import server

    orig_ready = server._fb_ready
    try:
        server._fb_ready = None  # force a fresh probe
        # No FIREBASE_CREDENTIALS in the test env → dormant, never raises.
        assert server._firebase_ready() is False
        assert server.verify_id_token("") is None
        assert server.verify_id_token("not.a.real.token") is None
        # With no creds, enforcement is off → anonymous scans allowed.
        assert server._auth_enforced() is False
        # Simulate creds present: enforcement follows unless explicitly disabled.
        server._fb_ready = True
        assert server._auth_enforced() is True
    finally:
        server._fb_ready = orig_ready
