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
"""

import os
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
    _sec_err_msg = str(_sec_err)

# ── Import dependency scanner (v4.0.0) ───────────────────────────────────────
try:
    from dependency_scanner import scan_repo as deps_scan_repo
    _DEPS_AVAILABLE = True
except ImportError as _dep_err:
    _DEPS_AVAILABLE = False
    _dep_err_msg = str(_dep_err)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "secreview-ui-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Active scan jobs: sid -> status dict
_jobs: dict[str, dict] = {}


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
        # Return a graceful error so the UI can display a fallback message
        return jsonify({"error": f"Threat intelligence module unavailable: {_ti_err_msg}"}), 503

    try:
        # Build the full feed — this is fast (in-memory computation only)
        feed = build_feed(days=90, top_n=10)
        return jsonify(feed.to_dict())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/threat/<threat_id>")
def api_threat_detail(threat_id: str):
    """
    GET /api/threat/<threat_id>

    Returns full detail for a single threat by its ID (e.g. 'lockbit-3').

    Returns HTTP 404 if the threat ID is not found.
    Returns HTTP 503 if threat_intel module failed to import.
    """
    if not _THREAT_INTEL_AVAILABLE:
        return jsonify({"error": f"Threat intelligence module unavailable: {_ti_err_msg}"}), 503

    try:
        threat = get_threat_by_id(threat_id)
        if threat is None:
            return jsonify({"error": f"Threat '{threat_id}' not found"}), 404
        return jsonify(threat)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/prevention-guide")
def api_prevention_guide():
    """
    GET /api/prevention-guide

    Returns the full categorised prevention guide as JSON.
    Optionally accepts ?category=Ransomware|APT|Malware|Exploit to filter.

    Returns HTTP 503 if threat_intel module failed to import.
    """
    if not _THREAT_INTEL_AVAILABLE:
        return jsonify({"error": f"Threat intelligence module unavailable: {_ti_err_msg}"}), 503

    try:
        # Optional category filter from query string
        category = request.args.get("category")
        guide = get_prevention_guide(category=category)
        return jsonify(guide)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/yara/rules")
def api_yara_rules():
    """
    GET /api/yara/rules

    Returns metadata for all available YARA rule files, including
    display name, filename, and rule count.

    Returns HTTP 503 if yara_scanner module failed to import.
    """
    if not _YARA_AVAILABLE:
        return jsonify({"error": f"YARA scanner module unavailable: {_ya_err_msg}"}), 503

    try:
        rules = list_rules()
        return jsonify(rules)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/secrets/patterns")
def api_secrets_patterns():
    """
    GET /api/secrets/patterns

    Returns all available secret detection pattern categories with provider
    names and pattern counts. Used to populate the Secrets Scanner panel UI.

    Returns HTTP 503 if secrets_scanner module failed to import.
    """
    if not _SECRETS_AVAILABLE:
        return jsonify({"error": f"Secrets scanner unavailable: {_sec_err_msg}"}), 503
    try:
        return jsonify(list_pattern_categories())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/report/<filename>")
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)


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
    sid = request.sid

    if not repo_url or not parse_repo_url(repo_url):
        emit("error", {"message": "Invalid GitHub URL. Please use https://github.com/owner/repo"})
        return

    def run():
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
                _emit(sid, "progress", {"step": "semgrep", "message": "🔍 Running Semgrep security scan...", "pct": 35})

                result = AnalysisResult(repo_url=repo_url, repo_path=workdir)
                result.findings = run_semgrep(workdir)
                _emit(sid, "progress", {"step": "deps", "message": "📦 Checking dependency CVEs...", "pct": 50})
                result.dependency_vulns = check_dependency_vulns(workdir)

                obs = None
                if run_sandbox:
                    _emit(sid, "progress", {"step": "sandbox", "message": "🐳 Running Docker sandbox...", "pct": 60})
                    from sandbox import run_in_sandbox
                    obs = run_in_sandbox(workdir)

                enriched = None
                if run_advisor and (llm_api_key or os.environ.get("ANTHROPIC_API_KEY") or llm_provider == "ollama" or llm_provider == "none"):
                    _emit(sid, "progress", {"step": "advisor", "message": f"🤖 Generating AI fix advisories for {min(len(result.findings),20)} findings...", "pct": 75})
                    from advisor import enrich_findings
                    enriched = enrich_findings(result, obs, provider=llm_provider, api_key=llm_api_key, max_findings=20)

                # ── Secrets Detection (v3.0.0) ────────────────────────────────
                _emit(sid, "progress", {"step": "secrets", "message": "🔑 Scanning for hardcoded secrets and credentials...", "pct": 78})
                secrets_result = None
                if _SECRETS_AVAILABLE:
                    try:
                        secrets_result = secrets_scan_repo(
                            repo_path=workdir,
                            include_history=True,
                            entropy_check=True,
                            progress_cb=None,
                        )
                    except Exception as _sec_exc:
                        pass

                # ── Dependency Vulnerability Scan (v4.0.0) ───────────────────
                _emit(sid, "progress", {"step": "deps", "message": "📦 Scanning dependencies for CVEs via OSV.dev...", "pct": 82})
                deps_result = None
                if _DEPS_AVAILABLE:
                    try:
                        deps_result = deps_scan_repo(
                            repo_path=workdir,
                            progress_cb=None,
                        )
                    except Exception as _dep_exc:
                        pass  # non-fatal

                _emit(sid, "progress", {"step": "report", "message": "Analysing ransomware indicators...", "pct": 85})

                from ransomware import detect as ransomware_detect
                findings_dicts = enriched or [f.to_dict() for f in result.findings]
                rw_report = ransomware_detect(findings_dicts, workdir)

                _emit(sid, "progress", {"step": "report", "message": "Building report...", "pct": 90})

                from report import to_json, to_html
                from datetime import datetime
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                repo_slug = repo_url.rstrip("/").split("/")[-1]
                json_path = str(REPORTS_DIR / f"{repo_slug}_{ts}.json")
                html_path = str(REPORTS_DIR / f"{repo_slug}_{ts}.html")

                to_json(result, obs, enriched, json_path)

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
                    "deps": deps_result.to_dict() if deps_result else None,
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

                _emit(sid, "progress", {"step": "done", "message": "✅ Scan complete!", "pct": 100})
                _emit(sid, "scan_complete", {
                    "report_url": f"/report/{repo_slug}_{ts}_ui.html",
                    "json_url":   f"/report/{repo_slug}_{ts}.json",
                    "summary":    result.summary(),
                    "repo_slug":  repo_slug,
                    "ts":         ts,
                })

            finally:
                shutil.rmtree(workdir, ignore_errors=True)

        except Exception as e:
            import traceback
            _emit(sid, "error", {"message": str(e), "trace": traceback.format_exc()})

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
        _emit(sid, "yara_error", {"message": f"YARA scanner module unavailable: {_ya_err_msg}"})
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
            import traceback
            # Emit structured error so the UI can display it
            _emit(sid, "yara_error", {
                "message": str(exc),
                "trace": traceback.format_exc(),
            })

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
        _emit(sid, "secrets_error", {"message": f"Secrets scanner unavailable: {_sec_err_msg}"})
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
            import traceback
            _emit(sid, "secrets_error", {
                "message": str(exc),
                "trace": traceback.format_exc(),
            })
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
        _emit(sid, "deps_error", {"message": f"Dependency scanner unavailable: {_dep_err_msg}"})
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
            import traceback
            _emit(sid, "deps_error", {
                "message": str(exc),
                "trace": traceback.format_exc(),
            })
        finally:
            if cloned_dir:
                shutil.rmtree(cloned_dir, ignore_errors=True)

    t = threading.Thread(target=run_deps, daemon=True)
    t.start()


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
    socketio.run(app, host="0.0.0.0", port=5001, debug=False, allow_unsafe_werkzeug=True)
