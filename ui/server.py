"""
Flask web server for the Security Review UI.
Accepts GitHub URLs, runs the scan pipeline, streams progress, returns rich report.

v2.0.0 additions:
  - /api/threat-feed        — full threat intelligence feed (threat_intel.py)
  - /api/threat/<id>        — single threat detail
  - /api/yara/rules         — list of available YARA rule files
  - /api/prevention-guide   — categorised prevention best practices
  - start_yara_scan (Socket.IO) — streams YARA scan progress and results

v3.0.0 additions:
  - /api/secrets/patterns   — list all secret pattern categories
  - start_secrets_scan (Socket.IO) — streams secrets scan progress and results
    Accepts: { repo_path, include_history, entropy_check }
    Emits:   secrets_progress { pct, message }
             secrets_complete { SecretScanResult dict }
             secrets_error    { message }

v4.0.0 additions:
  - /api/deps/ecosystems     — list supported package ecosystems
  - start_deps_scan (Socket.IO) — streams dependency vulnerability scan via OSV.dev
    Accepts: { repo_path }
    Emits:   deps_progress { pct, message }
             deps_complete  { DepScanResult dict }
             deps_error     { message }

v6.0.0 additions:
  - /api/iac/frameworks      — list supported IaC frameworks
  - start_iac_scan (Socket.IO) — streams IaC misconfiguration scan
    Accepts: { repo_path }
    Emits:   iac_progress { pct, message }
             iac_complete  { IaCScanResult dict }
             iac_error     { message }
"""

import logging
import os
import re
import sys
import json
import threading
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

# Add parent dir so we can import analyzer, advisor, threat_intel, yara_scanner, etc.
sys.path.insert(0, str(Path(__file__).parent.parent))

from ui.github_info import fetch_repo_info, parse_repo_url

# ── Import threat intelligence and YARA scanner modules ───────────────────────
# These are imported at module level; if they fail the server still starts and
# returns a 503 on the affected endpoints rather than crashing entirely.
try:
    from threat_intel import build_feed, get_threat_by_id, get_prevention_guide
    _THREAT_INTEL_AVAILABLE = True
except ImportError as _ti_err:
    _THREAT_INTEL_AVAILABLE = False
    _ti_err_msg = str(_ti_err)

try:
    from yara_scanner import list_rules, scan_path as yara_scan_path
    _YARA_AVAILABLE = True
except ImportError as _ya_err:
    _YARA_AVAILABLE = False
    _ya_err_msg = str(_ya_err)

# ── Import secrets scanner (v3.0.0) ──────────────────────────────────────────
try:
    from secrets_scanner import scan_repo as secrets_scan_repo, list_pattern_categories
    _SECRETS_AVAILABLE = True
except ImportError as _sec_err:
    _SECRETS_AVAILABLE = False
    _sec_module_unavailable_msg = str(_sec_err)  # import error message, not a secret

# ── Import dependency scanner (v4.0.0) ───────────────────────────────────────
try:
    from dependency_scanner import scan_repo as deps_scan_repo
    _DEPS_AVAILABLE = True
except ImportError as _dep_err:
    _DEPS_AVAILABLE = False
    _dep_err_msg = str(_dep_err)

# ── Import IaC scanner (v6.0.0) ──────────────────────────────────────────────
try:
    from iac_scanner import scan_repo as iac_scan_repo, list_frameworks as iac_list_frameworks
    _IAC_AVAILABLE = True
except ImportError as _iac_err:
    _IAC_AVAILABLE = False
    _iac_err_msg = str(_iac_err)

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
# Session signing key — from the environment, else a per-process random key.
# Never hardcode a secret in source.
import secrets as _secrets
app.secret_key = os.environ.get("SECRET_KEY") or _secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ── Security response headers (defence-in-depth / anti-disclosure) ─────────────
@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    # Content-Security-Policy: restrict where scripts/styles/data may load from
    # and where the page may connect, limiting injection & data-exfiltration.
    # 'unsafe-inline'/'unsafe-eval' are required by the inline app scripts and
    # the Firebase SDK; the source allowlist still constrains third parties.
    resp.headers.setdefault("Content-Security-Policy", "; ".join([
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.socket.io https://www.gstatic.com https://apis.google.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' data: https://fonts.gstatic.com",
        "img-src 'self' data: https:",
        "connect-src 'self' wss: https://cdn.socket.io https://*.googleapis.com "
        "https://*.firebaseio.com https://*.firebaseapp.com https://securetoken.googleapis.com "
        "https://identitytoolkit.googleapis.com https://firestore.googleapis.com "
        "https://www.googleapis.com https://api.ransomware.live https://www.cisa.gov",
        "frame-src 'self' https://*.firebaseapp.com https://accounts.google.com https://apis.google.com",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'self'",
    ]))
    # Allow the GitHub Pages front-end to fetch rendered reports cross-origin so
    # they can be stored durably (Firestore). Reports are already public by URL,
    # so a cross-origin GET exposes nothing new.
    try:
        if request.path.startswith("/report/"):
            resp.headers.setdefault("Access-Control-Allow-Origin", "*")
    except Exception:
        pass
    return resp

# Log key tool availability at startup so Render logs show exactly what's present
import shutil as _shutil
for _tool in ("semgrep", "git", "docker"):
    _loc = _shutil.which(_tool)
    logging.getLogger(__name__).info("tool check: %s → %s", _tool, _loc or "NOT FOUND")

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Active scan jobs: sid -> status dict
_jobs: dict[str, dict] = {}

# History file (local fallback when Gist is unavailable)
_HISTORY_FILE = REPORTS_DIR / "scan_history.jsonl"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


# ── Threat Intelligence REST endpoints ───────────────────────────────────────

@app.route("/api/threat-feed")
def api_threat_feed():
    """
    GET /api/threat-feed

    Returns the full threat intelligence feed as JSON, including:
      - recent_threats: threats active in last 90 days sorted by severity
      - top_variants:   top 10 most active variants with detection counts
      - prevention_guide: categorised prevention best practices
      - resilience:     data protection and resilience recommendations
      - total_tracked:  total threat count in the database

    Returns HTTP 503 if threat_intel module failed to import.
    """
    if not _THREAT_INTEL_AVAILABLE:
        logger.error("Threat intelligence module unavailable: %s", _ti_err_msg)
        return jsonify({"error": "Threat intelligence module unavailable"}), 503

    try:
        # Build the full feed — this is fast (in-memory computation only)
        feed = build_feed(days=90, top_n=10)
        return jsonify(feed.to_dict())
    except Exception as exc:
        logger.exception("Error building threat feed")
        return jsonify({"error": "Failed to build threat feed"}), 500


@app.route("/api/live-intel")
def api_live_intel():
    """
    GET /api/live-intel

    Returns live threat intelligence pulled from external public sources
    (CISA KEV + ransomware.live), cached server-side. Best-effort — degrades
    gracefully and returns an empty item list if upstreams are unavailable.
    """
    try:
        from live_intel import get_live_feed
        return jsonify(get_live_feed())
    except Exception:
        logger.exception("Error fetching live intel")
        return jsonify({"generated_at": "", "sources": [], "items": [], "live": False})


@app.route("/api/threat/<threat_id>")
def api_threat_detail(threat_id: str):
    """
    GET /api/threat/<threat_id>

    Returns full detail for a single threat by its ID (e.g. 'lockbit-3').

    Returns HTTP 404 if the threat ID is not found.
    Returns HTTP 503 if threat_intel module failed to import.
    """
    if not _THREAT_INTEL_AVAILABLE:
        logger.error("Threat intelligence module unavailable: %s", _ti_err_msg)
        return jsonify({"error": "Threat intelligence module unavailable"}), 503

    try:
        threat = get_threat_by_id(threat_id)
        if threat is None:
            return jsonify({"error": f"Threat '{threat_id}' not found"}), 404
        return jsonify(threat)
    except Exception as exc:
        logger.exception("Error fetching threat detail for %s", threat_id)
        return jsonify({"error": "Failed to fetch threat detail"}), 500


@app.route("/api/prevention-guide")
def api_prevention_guide():
    """
    GET /api/prevention-guide

    Returns the full categorised prevention guide as JSON.
    Optionally accepts ?category=Ransomware|APT|Malware|Exploit to filter.

    Returns HTTP 503 if threat_intel module failed to import.
    """
    if not _THREAT_INTEL_AVAILABLE:
        logger.error("Threat intelligence module unavailable: %s", _ti_err_msg)
        return jsonify({"error": "Threat intelligence module unavailable"}), 503

    try:
        # Optional category filter from query string
        category = request.args.get("category")
        guide = get_prevention_guide(category=category)
        return jsonify(guide)
    except Exception as exc:
        logger.exception("Error fetching prevention guide")
        return jsonify({"error": "Failed to fetch prevention guide"}), 500


@app.route("/api/yara/rules")
def api_yara_rules():
    """
    GET /api/yara/rules

    Returns metadata for all available YARA rule files, including
    display name, filename, and rule count.

    Returns HTTP 503 if yara_scanner module failed to import.
    """
    if not _YARA_AVAILABLE:
        logger.error("YARA scanner module unavailable: %s", _ya_err_msg)
        return jsonify({"error": "YARA scanner module unavailable"}), 503

    try:
        rules = list_rules()
        return jsonify(rules)
    except Exception as exc:
        logger.exception("Error listing YARA rules")
        return jsonify({"error": "Failed to list YARA rules"}), 500


@app.route("/api/secrets/patterns")
def api_secrets_patterns():
    """
    GET /api/secrets/patterns

    Returns all available secret detection pattern categories with provider
    names and pattern counts. Used to populate the Secrets Scanner panel UI.

    Returns HTTP 503 if secrets_scanner module failed to import.
    """
    if not _SECRETS_AVAILABLE:
        logger.error("Secrets scanner module unavailable: %s", _sec_module_unavailable_msg)  # nosemgrep: python-logger-credential-disclosure -- logs an import-error string, not a credential
        return jsonify({"error": "Secrets scanner module unavailable"}), 503
    try:
        return jsonify(list_pattern_categories())
    except Exception as exc:
        logger.exception("Error listing secret pattern categories")
        return jsonify({"error": "Failed to list secret pattern categories"}), 500


@app.route("/report/<filename>")
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)


@app.route("/report/<path:filename>/pdf")
def download_pdf(filename):
    """Generate and stream a PDF for the given report JSON."""
    # Sanitise the requested report name. secure_filename() strips every path
    # separator and traversal sequence, leaving a safe basename — this is the
    # primary defence against path injection (e.g. "../../etc/passwd").
    from werkzeug.utils import secure_filename
    stripped = filename.replace("_ui.html", "").replace(".html", "").replace(".json", "")
    base = secure_filename(stripped)
    if not base or not re.fullmatch(r"[A-Za-z0-9._-]+", base):
        return jsonify({"error": "Invalid report name"}), 400

    reports_root = REPORTS_DIR.resolve()
    json_path = (reports_root / f"{base}.json").resolve()
    # Defence-in-depth: the resolved path must stay inside the reports dir.
    if reports_root != json_path.parent:
        return jsonify({"error": "Invalid report path"}), 400
    if not json_path.exists():
        return jsonify({"error": "Report JSON not found"}), 404

    try:
        import json as _json
        from pdf_report import generate as gen_pdf
        report_data = _json.loads(json_path.read_text(encoding="utf-8"))
        pdf_bytes = gen_pdf(report_data)
        from flask import Response
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="securescope_{base}.pdf"',
                "Content-Length": str(len(pdf_bytes)),
            }
        )
    except Exception:
        # Log details server-side; never leak exception text to the client.
        logger.exception("PDF generation failed for %s", base)
        return jsonify({"error": "PDF generation failed. Please try again."}), 500


@app.route("/reports")
def list_reports():
    files = sorted(REPORTS_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    reports = []
    for f in files[:20]:
        try:
            data = json.loads(f.read_text())
            reports.append({
                "filename": f.stem,
                "repo": data.get("repo", ""),
                "total": data.get("summary", {}).get("total_findings", 0),
                "errors": data.get("summary", {}).get("by_severity", {}).get("ERROR", 0),
                "generated_at": data.get("generated_at", ""),
            })
        except Exception:
            pass
    return jsonify(reports)


# ── Socket.IO scan flow ────────────────────────────────────────────────────────

@socketio.on("start_scan")
def handle_scan(data):
    repo_url = data.get("repo_url", "").strip()
    run_sandbox = data.get("sandbox", False)
    run_advisor = data.get("advisor", False)
    llm_provider = data.get("llm_provider", "anthropic") or "anthropic"
    llm_api_key = data.get("llm_api_key", "") or ""
    auto_fix = data.get("auto_fix", False)
    gh_token = data.get("gh_token", "") or os.environ.get("GITHUB_TOKEN", "")
    # Secret-scanner options (from the Secret Detection modal); default on.
    secret_include_history = data.get("secret_include_history", False)
    secret_entropy_check = data.get("secret_entropy_check", True)
    # Deep scan adds the heavier Semgrep supply-chain pack + full git-history
    # secret scan. Fast (default) keeps the core packs and working-tree secrets.
    deep_scan = data.get("deep_scan", False)
    if deep_scan:
        secret_include_history = True
    sid = request.sid

    if not repo_url or not parse_repo_url(repo_url):
        emit("error", {"message": "Invalid repository URL. Use a GitHub, GitLab, or Bitbucket URL like https://github.com/owner/repo"})
        return

    def run():
        with app.app_context():
            try:
                _emit(sid, "progress", {"step": "github_info", "message": "📋 Fetching repository information...", "pct": 5})
                gh_info = fetch_repo_info(repo_url)

                _emit(sid, "github_info", gh_info)
                _emit(sid, "progress", {"step": "clone", "message": "📥 Cloning repository...", "pct": 15})

                from analyzer import clone_repo, run_semgrep, check_dependency_vulns, AnalysisResult
                import tempfile, shutil

                workdir = tempfile.mkdtemp(prefix="secreview_")
                try:
                    clone_repo(repo_url, workdir)
                    result = AnalysisResult(repo_url=repo_url, repo_path=workdir)

                    # ── Run scanners SEQUENTIALLY ────────────────────────────────
                    # On a small (≈0.5 CPU / 512 MB) host, running the CPU/memory-
                    # heavy scanners concurrently starves them and is *slower*, so
                    # each step runs in turn with the full instance. Speed comes
                    # from doing less work in Fast mode (fewer Semgrep packs, no
                    # git-history secret scan) — see run_semgrep / secret options.
                    fast_mode = not deep_scan

                    _emit(sid, "progress", {"step": "semgrep", "message": "🔍 Running Semgrep static analysis...", "pct": 35})
                    result.findings = run_semgrep(workdir, fast_mode)

                    # Dependency CVEs — prefer the fast OSV scanner and derive the
                    # basic dependency_vulns list from it (same keys the report
                    # expects). Only fall back to the slower pip-audit/npm-audit
                    # path when the OSV scanner is unavailable. This removes a
                    # redundant, slow dependency resolution pass.
                    _emit(sid, "progress", {"step": "deps", "message": "📦 Scanning dependencies for CVEs via OSV.dev...", "pct": 60})
                    deps_result = None
                    if _DEPS_AVAILABLE:
                        try:
                            deps_result = deps_scan_repo(repo_path=workdir, progress_cb=None)
                        except Exception:
                            logger.exception("dependency scan failed")
                    if deps_result is not None:
                        try:
                            result.dependency_vulns = [
                                {"ecosystem": v.get("ecosystem", ""),
                                 "package": v.get("package_name", ""),
                                 "version": v.get("package_version", ""),
                                 "vuln_id": v.get("vuln_id", "") or v.get("primary_cve", ""),
                                 "description": v.get("summary", ""),
                                 "fix_versions": v.get("fixed_versions", []) or []}
                                for v in deps_result.to_dict().get("vulnerabilities", [])
                            ]
                        except Exception:
                            logger.exception("mapping OSV deps to dependency_vulns failed")
                            result.dependency_vulns = []
                    else:
                        result.dependency_vulns = check_dependency_vulns(workdir)

                    # Exploitability enrichment (EPSS + CISA KEV) — prioritise the
                    # dependency CVEs by real-world exploit likelihood. Best-effort:
                    # never blocks or fails the scan if the feeds are unreachable.
                    deps_dict = None
                    if deps_result is not None:
                        _emit(sid, "progress", {"step": "exploit", "message": "🎯 Enriching CVEs with EPSS, CISA KEV & reachability...", "pct": 66})
                        try:
                            from exploit_intel import enrich_deps
                            deps_dict = enrich_deps(deps_result.to_dict())
                        except Exception:
                            logger.exception("EPSS/KEV enrichment failed")
                            deps_dict = deps_result.to_dict()
                        # Reachability — demote CVEs in packages the code never imports.
                        try:
                            from reachability import annotate as _annotate_reach
                            deps_dict = _annotate_reach(deps_dict, workdir)
                        except Exception:
                            logger.exception("reachability analysis failed")

                    _emit(sid, "progress", {"step": "secrets", "message": "🔑 Scanning for hardcoded secrets and credentials...", "pct": 70})
                    secrets_result = None
                    if _SECRETS_AVAILABLE:
                        try:
                            secrets_result = secrets_scan_repo(
                                repo_path=workdir, include_history=secret_include_history,
                                entropy_check=secret_entropy_check, progress_cb=None)
                        except Exception:
                            logger.exception("secrets scan failed")

                    _emit(sid, "progress", {"step": "iac", "message": "🏗️ Scanning IaC for cloud misconfigurations...", "pct": 78})
                    iac_result = None
                    if _IAC_AVAILABLE:
                        try:
                            iac_result = iac_scan_repo(repo_path=workdir, progress_cb=None)
                        except Exception:
                            logger.exception("IaC scan failed")

                    # ── Optional Docker sandbox (heavy; off by default) ──────────
                    obs = None
                    if run_sandbox:
                        _emit(sid, "progress", {"step": "sandbox", "message": "🐳 Running Docker sandbox...", "pct": 82})
                        from sandbox import run_in_sandbox
                        obs = run_in_sandbox(workdir)

                    # ── AI fix advisor (needs Semgrep findings) ──────────────────
                    enriched = None
                    if run_advisor and (llm_api_key or os.environ.get("ANTHROPIC_API_KEY") or llm_provider == "ollama" or llm_provider == "none"):
                        _emit(sid, "progress", {"step": "advisor", "message": f"🤖 Generating AI fix advisories for {min(len(result.findings),20)} findings...", "pct": 85})
                        from advisor import enrich_findings
                        enriched = enrich_findings(result, obs, provider=llm_provider, api_key=llm_api_key, max_findings=20)

                    _emit(sid, "progress", {"step": "report", "message": "Analysing ransomware indicators...", "pct": 88})

                    from ransomware import detect as ransomware_detect
                    findings_dicts = enriched or [f.to_dict() for f in result.findings]
                    rw_report = ransomware_detect(findings_dicts, workdir)

                    # ── Compliance mapping + license scan + SBOM ─────────────────
                    # All three are cheap and reuse existing, tested modules.
                    _emit(sid, "progress", {"step": "compliance", "message": "📋 Mapping to PCI/NIST/OWASP, scanning licenses & building SBOM...", "pct": 89})
                    compliance_data = None
                    try:
                        from compliance import build_compliance_posture
                        import dataclasses as _dc
                        # Normalise "CWE-79: XSS" → "CWE-79" so it maps cleanly.
                        def _norm_cwe(f):
                            c = f.get("cwe") or ""
                            m = re.search(r"CWE-\d+", c)
                            return {**f, "cwe": m.group(0) if m else c}
                        compliance_data = _dc.asdict(
                            build_compliance_posture([_norm_cwe(f) for f in findings_dicts]))
                    except Exception:
                        logger.exception("compliance mapping failed")

                    license_data = None
                    try:
                        from license_scanner import scan_licenses
                        license_data = scan_licenses(workdir)
                    except Exception:
                        logger.exception("license scan failed")

                    sbom_data = None
                    try:
                        from sbom import generate_sbom
                        import uuid as _uuid, json as _json_sbom
                        result.repo_url = repo_url
                        _sbom_path = str(REPORTS_DIR / f"sbom_{_uuid.uuid4().hex}.cyclonedx.json")
                        generate_sbom(result, _sbom_path)
                        sbom_data = _json_sbom.loads(Path(_sbom_path).read_text(encoding="utf-8"))
                        try:
                            Path(_sbom_path).unlink()
                        except OSError:
                            pass
                    except Exception:
                        logger.exception("SBOM generation failed")

                    # ── Supply-chain risk + OpenSSF Scorecard + container ────────
                    _emit(sid, "progress", {"step": "supplychain", "message": "🔗 Checking typosquatting, dependency confusion & project health...", "pct": 90})
                    supply_chain_data = None
                    try:
                        from supply_chain import check_dependency_confusion, check_typosquatting
                        supply_chain_data = (check_dependency_confusion(workdir) or []) + (check_typosquatting(workdir) or [])
                    except Exception:
                        logger.exception("supply-chain checks failed")

                    scorecard_data = None
                    try:
                        from scorecard import run_scorecard
                        scorecard_data = run_scorecard(repo_url)
                    except Exception:
                        logger.exception("OpenSSF Scorecard failed")

                    container_data = None
                    try:
                        from trivy_scanner import scan_dockerfile
                        _cv = scan_dockerfile(workdir)
                        container_data = [v.to_dict() for v in _cv] if _cv else []
                    except Exception:
                        logger.exception("container scan failed")

                    _emit(sid, "progress", {"step": "report", "message": "Building report...", "pct": 92})

                    from report import to_json, to_html
                    from datetime import datetime
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    repo_slug = repo_url.rstrip("/").split("/")[-1]
                    json_path = str(REPORTS_DIR / f"{repo_slug}_{ts}.json")
                    html_path = str(REPORTS_DIR / f"{repo_slug}_{ts}.html")

                    to_json(result, obs, enriched, json_path)

                    # Enrich the saved JSON with governance data so the PDF (built
                    # from this JSON) can render the compliance + license summaries.
                    try:
                        import json as _json_enrich
                        _jd = _json_enrich.loads(Path(json_path).read_text(encoding="utf-8"))
                        _jd["compliance"] = compliance_data
                        _jd["licenses"] = license_data
                        _jd["sbom_components"] = len(sbom_data.get("components", [])) if sbom_data else 0
                        Path(json_path).write_text(_json_enrich.dumps(_jd), encoding="utf-8")
                    except Exception:
                        logger.exception("enriching report JSON failed")

                    # Build the rich UI report (separate from the basic one)
                    report_data = {
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
                        "repo_url": repo_url,
                        "repo_slug": repo_slug,
                        "ts": ts,
                        "gh_info": gh_info,
                        "summary": result.summary(),
                        "findings": findings_dicts,
                        "dependency_vulns": result.dependency_vulns,
                        "ransomware": rw_report,
                        "secrets": secrets_result.to_dict() if secrets_result else None,
                        "deps": deps_dict if deps_dict is not None else (deps_result.to_dict() if deps_result else None),
                        "iac": iac_result.to_dict() if iac_result else None,
                        "compliance": compliance_data,
                        "licenses": license_data,
                        "sbom": sbom_data,
                        "supply_chain": supply_chain_data,
                        "scorecard": scorecard_data,
                        "container": container_data,
                        "runtime": {
                            "exit_code": obs.exit_code if obs else None,
                            "suspicious_behaviors": obs.suspicious_behaviors if obs else [],
                            "outbound_connections": obs.outbound_connections if obs else [],
                            "processes_spawned": obs.processes_spawned[:20] if obs else [],
                            "stdout": (obs.stdout or "")[:3000] if obs else "",
                        } if obs else None,
                    }

                    # Save rich HTML report
                    rich_html = Path(REPORTS_DIR / f"{repo_slug}_{ts}_ui.html")
                    rich_html.write_text(
                        render_template("report.html", **report_data),
                        encoding="utf-8"
                    )

                    # ── Gist upload ───────────────────────────────────────
                    gist_url = ""
                    if gh_token:
                        _emit(sid, "progress", {"step": "done", "message": "☁️ Uploading report to Gist...", "pct": 95})
                        try:
                            from gist_storage import upload_report, append_history_record, build_history_record
                            gist_url = upload_report(rich_html.read_text(encoding="utf-8"), repo_slug, ts)
                            rec = build_history_record(repo_url, repo_slug, ts, result.summary(), gist_url)
                            # Local history fallback
                            with open(_HISTORY_FILE, "a", encoding="utf-8") as hf:
                                import json as _json
                                hf.write(_json.dumps(rec) + "\n")
                            # Gist history index
                            append_history_record(rec)
                        except Exception as _ge:
                            logger.warning("Gist/history upload failed: %s", _ge)

                    # ── Auto-fix PR ───────────────────────────────────────
                    fix_pr_url = ""
                    if auto_fix and gh_token and findings_dicts:
                        _emit(sid, "progress", {"step": "done", "message": "🔧 Creating fix PR...", "pct": 97})
                        try:
                            from autofix import create_fix_pr
                            fix_pr_url = create_fix_pr(repo_url, gh_token, workdir, findings_dicts, ts)
                        except Exception as _fe:
                            logger.warning("Auto-fix PR failed: %s", _fe)

                    _emit(sid, "progress", {"step": "done", "message": "✅ Scan complete!", "pct": 100})
                    _emit(sid, "scan_complete", {
                        "report_url": f"/report/{repo_slug}_{ts}_ui.html",
                        "json_url":   f"/report/{repo_slug}_{ts}.json",
                        "gist_url":   gist_url,
                        "fix_pr_url": fix_pr_url,
                        "summary":    result.summary(),
                        "repo_slug":  repo_slug,
                        "ts":         ts,
                    })

                finally:
                    shutil.rmtree(workdir, ignore_errors=True)

            except Exception as e:
                logger.exception("Scan pipeline error for sid %s", sid)
                _emit(sid, "error", {"message": f"Scan failed: {type(e).__name__}: {e}"})

    t = threading.Thread(target=run, daemon=True)
    t.start()


# ── Socket.IO YARA scan flow ──────────────────────────────────────────────────

@socketio.on("start_yara_scan")
def handle_yara_scan(data):
    """
    Socket.IO event: start_yara_scan

    Accepts payload: { target_path: str, rule_names: list[str] (optional) }

    Streams progress via 'yara_progress' events:
        { pct: float, current_file: str, matches_so_far: int }

    Emits 'yara_complete' with the full YaraScanResult dict when done.
    Emits 'yara_error' if the module is unavailable or an exception occurs.
    """
    # Capture the Socket.IO session ID so we can emit back to this client
    sid = request.sid
    target_path = data.get("target_path", "").strip()
    rule_names = data.get("rule_names") or None  # None = use all rules

    # Validate that the target path was provided
    if not target_path:
        _emit(sid, "yara_error", {"message": "target_path is required"})
        return

    # Check YARA scanner module availability
    if not _YARA_AVAILABLE:
        logger.error("YARA scanner module unavailable: %s", _ya_err_msg)
        _emit(sid, "yara_error", {"message": "YARA scanner module unavailable"})
        return

    def run_yara():
        """Worker thread: performs the YARA scan and streams progress events."""
        try:
            # Mutable counter shared between the progress callback and the outer scope
            match_counter = [0]

            def progress_cb(pct: float, current_file: str):
                """
                Called by yara_scanner.scan_path as each file is processed.
                Emits a progress event to the connected client.
                """
                # Emit progress: percentage, current file, and running match count
                _emit(sid, "yara_progress", {
                    "pct": round(pct, 1),
                    "current_file": current_file,
                    "matches_so_far": match_counter[0],
                })

            # Perform the scan — this may take seconds to minutes depending on path size
            result = yara_scan_path(
                target_path=target_path,
                rule_names=rule_names,
                progress_cb=progress_cb,
            )

            # Update match count from result before emitting completion
            match_counter[0] = len(result.matches)

            # Emit the complete scan result
            _emit(sid, "yara_complete", result.to_dict())

        except Exception as exc:
            logger.exception("YARA scan error for sid %s", sid)
            _emit(sid, "yara_error", {"message": "YARA scan failed. Check server logs for details."})

    # Run the scan in a background thread so Socket.IO remains responsive
    t = threading.Thread(target=run_yara, daemon=True)
    t.start()


# ── Socket.IO Secrets Scan flow (v3.0.0) ─────────────────────────────────────

@socketio.on("start_secrets_scan")
def handle_secrets_scan(data):
    """
    Socket.IO event: start_secrets_scan

    Accepts payload:
        {
          repo_path:       str   — absolute path to a locally cloned repo,
                                   OR a GitHub URL (will be cloned to a temp dir)
          include_history: bool  — scan git commit history (default True)
          entropy_check:   bool  — enable high-entropy detection (default True)
        }

    Streams:
        secrets_progress { pct: float, message: str }

    Emits on completion:
        secrets_complete { SecretScanResult dict }

    Emits on error:
        secrets_error { message: str }
    """
    sid = request.sid
    repo_path = data.get("repo_path", "").strip()
    include_history = bool(data.get("include_history", True))
    entropy_check = bool(data.get("entropy_check", True))

    if not repo_path:
        _emit(sid, "secrets_error", {"message": "repo_path is required"})
        return

    if not _SECRETS_AVAILABLE:
        logger.error("Secrets scanner module unavailable: %s", _sec_module_unavailable_msg)  # nosemgrep: python-logger-credential-disclosure -- logs an import-error string, not a credential
        _emit(sid, "secrets_error", {"message": "Secrets scanner module unavailable"})
        return

    def run_secrets():
        """Worker thread: runs secrets scan with progress streaming."""
        import tempfile, shutil

        cloned_dir = None
        scan_target = repo_path

        try:
            # If the user supplied a GitHub URL, clone it to a temp directory
            is_url = repo_path.startswith("http://") or repo_path.startswith("https://")
            if is_url:
                _emit(sid, "secrets_progress", {"pct": 2, "message": "📥 Cloning repository..."})
                from analyzer import clone_repo
                cloned_dir = tempfile.mkdtemp(prefix="secreview_secrets_")
                clone_repo(repo_path, cloned_dir)
                scan_target = cloned_dir

            def progress_cb(pct: float, message: str):
                _emit(sid, "secrets_progress", {"pct": round(pct, 1), "message": message})

            result = secrets_scan_repo(
                repo_path=scan_target,
                include_history=include_history,
                entropy_check=entropy_check,
                progress_cb=progress_cb,
            )

            _emit(sid, "secrets_complete", result.to_dict())

        except Exception as exc:
            logger.exception("Secrets scan error for sid %s", sid)  # nosemgrep: python-logger-credential-disclosure -- logs a socket id, not a credential
            _emit(sid, "secrets_error", {"message": "Secrets scan failed. Check server logs for details."})
        finally:
            if cloned_dir:
                shutil.rmtree(cloned_dir, ignore_errors=True)

    t = threading.Thread(target=run_secrets, daemon=True)
    t.start()


# ── Dependency Vulnerability Scan (v4.0.0) ────────────────────────────────────

@app.route("/api/deps/ecosystems")
def api_deps_ecosystems():
    return jsonify(["PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io", "Packagist"])


@socketio.on("start_deps_scan")
def handle_deps_scan(data):
    sid = request.sid
    if not _DEPS_AVAILABLE:
        logger.error("Dependency scanner module unavailable: %s", _dep_err_msg)
        _emit(sid, "deps_error", {"message": "Dependency scanner module unavailable"})
        return

    repo_path = (data or {}).get("repo_path", "").strip()
    if not repo_path:
        _emit(sid, "deps_error", {"message": "No repo_path provided."})
        return

    import shutil
    import tempfile

    cloned_dir = None

    def run_deps():
        nonlocal cloned_dir
        scan_target = repo_path
        is_url = repo_path.startswith("http://") or repo_path.startswith("https://")
        try:
            if is_url:
                _emit(sid, "deps_progress", {"pct": 2, "message": "📥 Cloning repository..."})
                from analyzer import clone_repo
                cloned_dir = tempfile.mkdtemp(prefix="secreview_deps_")
                clone_repo(repo_path, cloned_dir)
                scan_target = cloned_dir

            def progress_cb(pct: float, message: str):
                _emit(sid, "deps_progress", {"pct": round(pct, 1), "message": message})

            result = deps_scan_repo(repo_path=scan_target, progress_cb=progress_cb)
            _emit(sid, "deps_complete", result.to_dict())

        except Exception as exc:
            logger.exception("Dependency scan error for sid %s", sid)
            _emit(sid, "deps_error", {"message": "Dependency scan failed. Check server logs for details."})
        finally:
            if cloned_dir:
                shutil.rmtree(cloned_dir, ignore_errors=True)

    t = threading.Thread(target=run_deps, daemon=True)
    t.start()


@app.route("/api/dep-fix-pr", methods=["POST"])
def api_dep_fix_pr():
    """POST {repo_url, github_token} — open a PR that upgrades vulnerable deps.

    Re-clones the target and rescans server-side (never trusts client-supplied
    findings), enriches with EPSS/KEV + reachability, then bumps each affected
    manifest to the lowest CVE-clearing version and opens a single PR. The token
    is used only for this request and never stored or logged.
    """
    import re as _re
    import shutil
    import tempfile
    from datetime import datetime

    data = request.get_json(silent=True) or {}
    repo_url = (data.get("repo_url") or "").strip()
    gh_token = (data.get("github_token") or "").strip()

    if not _re.match(r"^https://github\.com/[^/]+/[^/]+/?$", repo_url.rstrip("/") + "/"):
        return jsonify({"ok": False, "reason": "A valid https://github.com/owner/repo URL is required."}), 400
    if not gh_token:
        return jsonify({"ok": False, "reason": "A GitHub token with write access to the repo is required."}), 400
    if not _DEPS_AVAILABLE:
        return jsonify({"ok": False, "reason": "Dependency scanner unavailable on this server."}), 503

    workdir = tempfile.mkdtemp(prefix="secreview_fixpr_")
    try:
        from analyzer import clone_repo
        clone_repo(repo_url, workdir)
        deps_result = deps_scan_repo(repo_path=workdir, progress_cb=None)
        deps = deps_result.to_dict()
        try:
            from exploit_intel import enrich_deps
            deps = enrich_deps(deps)
        except Exception:
            logger.exception("fix-pr: enrichment failed")
        try:
            from reachability import annotate as _annotate
            deps = _annotate(deps, workdir)
        except Exception:
            logger.exception("fix-pr: reachability failed")

        vulns = deps.get("vulnerabilities", []) or []
        if not vulns:
            return jsonify({"ok": False, "reason": "No dependency CVEs found — nothing to fix."})

        from dep_fix_pr import create_dep_fix_pr
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        result = create_dep_fix_pr(repo_url, gh_token, workdir, vulns, ts)
        return jsonify(result)
    except Exception:
        logger.exception("dep-fix-pr failed")
        return jsonify({"ok": False, "reason": "Fix-PR generation failed. Check server logs."}), 500
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ── IaC Misconfiguration Scan (v6.0.0) ───────────────────────────────────────

@app.route("/api/iac/frameworks")
def api_iac_frameworks():
    """GET /api/iac/frameworks — list all supported IaC frameworks."""
    if not _IAC_AVAILABLE:
        logger.error("IaC scanner module unavailable: %s", _iac_err_msg)
        return jsonify({"error": "IaC scanner module unavailable"}), 503
    try:
        return jsonify(iac_list_frameworks())
    except Exception as exc:
        logger.exception("Error listing IaC frameworks")
        return jsonify({"error": "Failed to list IaC frameworks"}), 500


@socketio.on("start_iac_scan")
def handle_iac_scan(data):
    """
    Socket.IO event: start_iac_scan

    Accepts payload: { repo_path: str }
    Streams:  iac_progress { pct, message }
    Emits:    iac_complete  { IaCScanResult dict }
              iac_error     { message }
    """
    sid = request.sid
    if not _IAC_AVAILABLE:
        logger.error("IaC scanner module unavailable: %s", _iac_err_msg)
        _emit(sid, "iac_error", {"message": "IaC scanner module unavailable"})
        return

    repo_path = (data or {}).get("repo_path", "").strip()
    if not repo_path:
        _emit(sid, "iac_error", {"message": "No repo_path provided."})
        return

    import shutil
    import tempfile

    cloned_dir = None

    def run_iac():
        nonlocal cloned_dir
        scan_target = repo_path
        is_url = repo_path.startswith("http://") or repo_path.startswith("https://")
        try:
            if is_url:
                _emit(sid, "iac_progress", {"pct": 2, "message": "📥 Cloning repository..."})
                from analyzer import clone_repo
                cloned_dir = tempfile.mkdtemp(prefix="secreview_iac_")
                clone_repo(repo_path, cloned_dir)
                scan_target = cloned_dir

            def progress_cb(pct: float, message: str):
                _emit(sid, "iac_progress", {"pct": round(pct, 1), "message": message})

            result = iac_scan_repo(repo_path=scan_target, progress_cb=progress_cb)
            _emit(sid, "iac_complete", result.to_dict())

        except Exception as exc:
            logger.exception("IaC scan error for sid %s", sid)
            _emit(sid, "iac_error", {"message": "IaC scan failed. Check server logs for details."})
        finally:
            if cloned_dir:
                shutil.rmtree(cloned_dir, ignore_errors=True)

    t = threading.Thread(target=run_iac, daemon=True)
    t.start()


# ── v8.0.0 API endpoints ─────────────────────────────────────────────────────

@app.route("/api/trend")
def api_trend():
    """
    GET /api/trend?repo=URL

    Returns trend JSON records for the given repo URL.
    Records are read from {REPORTS_DIR}/trend.jsonl.
    """
    repo_url = request.args.get("repo", "").strip()
    if not repo_url:
        return jsonify({"error": "repo parameter is required"}), 400
    try:
        from trend import load_trend
        records = load_trend(repo_url, str(REPORTS_DIR))
        return jsonify(records)
    except Exception as exc:
        logger.exception("Error loading trend for %s", repo_url)
        return jsonify({"error": "Failed to load trend data"}), 500


@app.route("/api/suppress", methods=["POST"])
def api_suppress():
    """
    POST /api/suppress
    Body: {"rule_id": str, "file": str, "reason": str, "repo_path": str}

    Adds a false-positive suppression to the given repo's .secscope-suppressions.json.
    """
    body = request.get_json(silent=True) or {}
    rule_id = body.get("rule_id", "").strip()
    file_path = body.get("file", "").strip()
    reason = body.get("reason", "").strip()
    repo_path = body.get("repo_path", "").strip()

    if not all([rule_id, file_path, reason, repo_path]):
        return jsonify({"error": "rule_id, file, reason, and repo_path are required"}), 400

    try:
        from false_positives import save_suppression
        save_suppression(repo_path, rule_id, file_path, reason, suppressed_by="ui-user")
        return jsonify({"status": "suppressed", "rule_id": rule_id, "file": file_path})
    except Exception as exc:
        logger.exception("Error adding suppression")
        return jsonify({"error": "Failed to save suppression"}), 500


@app.route("/api/history")
def api_history():
    """GET /api/history — return last 50 scan records (Gist or local fallback)."""
    records = []
    # Try Gist first
    if os.environ.get("GITHUB_TOKEN"):
        try:
            from gist_storage import load_history_from_gist
            records = load_history_from_gist()
        except Exception:
            pass
    # Local fallback
    if not records and _HISTORY_FILE.exists():
        import json as _json
        lines = _HISTORY_FILE.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            line = line.strip()
            if line:
                try:
                    records.append(_json.loads(line))
                except Exception:
                    pass
    return jsonify(records[:50])


@app.route("/webhook/github", methods=["POST"])
def github_webhook():
    """POST /webhook/github — receive GitHub pull_request events and trigger scans."""
    import hashlib, hmac as _hmac
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if secret:
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + _hmac.new(secret.encode(), request.data, hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig_header, expected):
            return jsonify({"error": "Invalid signature"}), 401

    event = request.headers.get("X-GitHub-Event", "")
    if event != "pull_request":
        return jsonify({"status": "ignored", "event": event}), 200

    payload = request.get_json(silent=True) or {}
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return jsonify({"status": "ignored", "action": action}), 200

    pr = payload.get("pull_request", {})
    repo_url = pr.get("head", {}).get("repo", {}).get("clone_url", "").replace(".git", "")
    if not repo_url.startswith("https://github.com/"):
        repo_url = "https://github.com/" + payload.get("repository", {}).get("full_name", "")
    pr_number = payload.get("number")
    pr_html_url = pr.get("html_url", "")
    repo_full = payload.get("repository", {}).get("full_name", "")
    head_sha = pr.get("head", {}).get("sha", "")

    def _scan_and_comment():
        with app.app_context():
            try:
                from analyzer import clone_repo, run_semgrep, AnalysisResult
                import tempfile, shutil as _sh
                workdir = tempfile.mkdtemp(prefix="webhook_")
                try:
                    clone_repo(repo_url, workdir)
                    result = AnalysisResult(repo_url=repo_url, repo_path=workdir)
                    result.findings = run_semgrep(workdir)
                    summary = result.summary()
                    # Post PR review comment
                    gh_token = os.environ.get("GITHUB_TOKEN", "")
                    if gh_token and repo_full and pr_number:
                        from github import Github as _GH
                        gh = _GH(gh_token)
                        repo_obj = gh.get_repo(repo_full)
                        pr_obj = repo_obj.get_pull(pr_number)
                        crit = summary.get("critical", 0)
                        warn = summary.get("warnings", 0)
                        score = summary.get("risk_score", 0)
                        icon = "🔴" if crit > 0 else "🟡" if warn > 0 else "🟢"
                        body = (
                            f"## {icon} SecureScope Security Scan — PR #{pr_number}\n\n"
                            f"| Metric | Value |\n|--------|-------|\n"
                            f"| Risk Score | **{score}/100** |\n"
                            f"| Critical Findings | **{crit}** |\n"
                            f"| Warnings | **{warn}** |\n"
                            f"| Commit | `{head_sha[:7]}` |\n\n"
                            f"[View full scan on SecureScope](https://secure-scope.onrender.com)"
                        )
                        pr_obj.create_issue_comment(body)
                finally:
                    _sh.rmtree(workdir, ignore_errors=True)
            except Exception as exc:
                logger.exception("Webhook scan failed for %s PR#%s", repo_full, pr_number)

    threading.Thread(target=_scan_and_comment, daemon=True).start()
    return jsonify({"status": "scan_started", "pr": pr_number}), 202


def _emit(sid, event, data):
    """
    Helper: emit a Socket.IO event to a specific session ID.

    Args:
        sid:   Target Socket.IO session ID.
        event: Event name string.
        data:  JSON-serialisable payload dict.
    """
    socketio.emit(event, data, to=sid)


if __name__ == "__main__":
    print("\nSecurity Review UI")
    print("   Open: http://localhost:5001\n")
    port = int(os.environ.get("PORT", 5001))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
