"""
OpenSSF Scorecard integration.
Prefers the local scorecard CLI if installed; falls back to the REST API.
"""

import json
import re
import subprocess
import shutil
import requests


def run_scorecard(repo_url: str) -> dict:
    """
    Fetch OpenSSF Scorecard results for a GitHub repository.

    Tries the scorecard CLI first (if installed), then falls back to the
    public REST API at https://api.securityscorecards.dev.

    Returns a dict:
        {
          "score": float,          # 0-10
          "checks": [
              {"name": str, "score": int, "reason": str},
              ...
          ],
          "date": str,             # ISO date string
          "source": "cli"|"api",
        }
    On failure returns {"score": None, "checks": [], "date": None, "error": str}.
    """
    # ── Try CLI first ───────────────────────────────────────────────────────────
    if shutil.which("scorecard"):
        try:
            proc = subprocess.run(
                ["scorecard", f"--repo={repo_url}", "--format=json"],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(proc.stdout)
            return _parse_cli_output(data)
        except Exception as exc:
            pass  # fall through to API

    # ── REST API fallback ───────────────────────────────────────────────────────
    m = re.search(r"github\.com[:/]([^/]+)/([^/.]+)", repo_url)
    if not m:
        return {"score": None, "checks": [], "date": None, "error": "Cannot parse repo URL"}

    owner, repo = m.group(1), m.group(2).replace(".git", "")
    api_url = f"https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"
    try:
        resp = requests.get(api_url, timeout=30)
        if resp.status_code != 200:
            return {"score": None, "checks": [], "date": None,
                    "error": f"Scorecard API returned HTTP {resp.status_code}"}
        return _parse_api_output(resp.json())
    except Exception as exc:
        return {"score": None, "checks": [], "date": None, "error": str(exc)}


def _parse_cli_output(data: dict) -> dict:
    checks = []
    for c in data.get("checks", []):
        checks.append({
            "name": c.get("name", ""),
            "score": c.get("score", -1),
            "reason": c.get("reason", ""),
        })
    return {
        "score": data.get("score"),
        "checks": checks,
        "date": data.get("date", ""),
        "source": "cli",
    }


def _parse_api_output(data: dict) -> dict:
    checks = []
    for c in data.get("checks", []):
        checks.append({
            "name": c.get("name", ""),
            "score": c.get("score", -1),
            "reason": c.get("reason", ""),
        })
    return {
        "score": data.get("score"),
        "checks": checks,
        "date": data.get("date", ""),
        "source": "api",
    }


def scorecard_to_html(scorecard_data: dict) -> str:
    """Render scorecard results as an HTML table section."""
    if not scorecard_data or scorecard_data.get("score") is None:
        err = scorecard_data.get("error", "No scorecard data available") if scorecard_data else "No scorecard data available"
        return f'<div class="sec" id="scorecard"><h2>OpenSSF Scorecard</h2><p style="color:#888">{err}</p></div>'

    score = scorecard_data["score"]
    date = scorecard_data.get("date", "")
    source = scorecard_data.get("source", "api")

    score_color = "#388e3c" if score >= 7 else ("#f57c00" if score >= 4 else "#d32f2f")

    rows = ""
    for c in scorecard_data.get("checks", []):
        s = c["score"]
        if s < 0:
            sc = "N/A"
            sc_color = "#888"
        else:
            sc = str(s)
            sc_color = "#388e3c" if s >= 7 else ("#f57c00" if s >= 4 else "#d32f2f")
        rows += (
            f"<tr>"
            f"<td>{c['name']}</td>"
            f"<td style='font-weight:bold;color:{sc_color}'>{sc}</td>"
            f"<td style='font-size:12px'>{c.get('reason','')}</td>"
            f"</tr>"
        )

    return f"""
<div class="sec" id="scorecard">
  <h2>OpenSSF Scorecard</h2>
  <p>
    Overall score:
    <strong style="color:{score_color};font-size:20px">{score}/10</strong>
    &nbsp;&nbsp;
    <span style="color:#888;font-size:12px">Source: {source} / {date}</span>
  </p>
  <table>
    <thead><tr><th>Check</th><th>Score</th><th>Reason</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
