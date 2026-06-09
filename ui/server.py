"""
Flask web server for the Security Review UI.
Accepts GitHub URLs, runs the scan pipeline, streams progress, returns rich report.
"""

import os
import sys
import json
import threading
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

# Add parent dir so we can import analyzer, advisor, etc.
sys.path.insert(0, str(Path(__file__).parent.parent))

from ui.github_info import fetch_repo_info, parse_repo_url

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
    return render_template("index.html")


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
                if run_advisor and os.environ.get("ANTHROPIC_API_KEY"):
                    _emit(sid, "progress", {"step": "advisor", "message": f"🤖 Generating AI fix advisories for {min(len(result.findings),20)} findings...", "pct": 75})
                    from advisor import enrich_findings
                    enriched = enrich_findings(result, obs, max_findings=20)

                _emit(sid, "progress", {"step": "report", "message": "📊 Building report...", "pct": 90})

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
                    "findings": enriched or [f.to_dict() for f in result.findings],
                    "dependency_vulns": result.dependency_vulns,
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


def _emit(sid, event, data):
    socketio.emit(event, data, to=sid)


if __name__ == "__main__":
    print("\n🔒 Security Review UI")
    print("   Open: http://localhost:5001\n")
    socketio.run(app, host="0.0.0.0", port=5001, debug=False, allow_unsafe_werkzeug=True)
