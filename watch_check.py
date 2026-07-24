"""
Continuous dependency-CVE monitor for watched repositories.

Reads a maintainer-curated watchlist (watchlist.json), scans each repo's
dependencies via OSV.dev, enriches with EPSS + CISA KEV, and diffs the result
against the last saved state (watch_state.json). Any *newly appearing* CVE is an
alert — KEV-listed ones are flagged as priority.

Designed to run on a schedule from GitHub Actions with zero external infra:
state lives in watch_state.json (committed back by the workflow) and alerts are
raised as GitHub Issues using the built-in GITHUB_TOKEN. No database, no secrets.

Usage:
    python watch_check.py            # scan watchlist, update state, write alerts
    python watch_check.py --dry-run  # scan but do not write state
"""

import json
import os
import sys
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
WATCHLIST = ROOT / "watchlist.json"
STATE = ROOT / "watch_state.json"
ALERTS = ROOT / "watch_alerts.json"


def _load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def current_cves(repo_url: str) -> dict:
    """Scan a repo and return {cve_id: {package, severity, kev, epss}}."""
    from analyzer import clone_repo
    from dependency_scanner import scan_repo as deps_scan_repo
    from exploit_intel import enrich_deps

    workdir = tempfile.mkdtemp(prefix="watch_")
    try:
        clone_repo(repo_url, workdir)
        deps = enrich_deps(deps_scan_repo(repo_path=workdir, progress_cb=None).to_dict())
        out = {}
        for v in deps.get("vulnerabilities", []) or []:
            cid = v.get("primary_cve") or v.get("vuln_id")
            if not cid:
                continue
            out[cid] = {
                "package": v.get("package_name", ""),
                "severity": v.get("severity", "UNKNOWN"),
                "kev": bool(v.get("kev")),
                "epss": round(float(v.get("epss", 0.0) or 0.0), 4),
            }
        return out
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def diff_cves(prev_ids, current: dict) -> list:
    """Return alert records for CVEs present now but not in prev_ids.

    prev_ids: iterable of previously-known CVE IDs.
    current:  {cve_id: {package, severity, kev, epss}} from current_cves().
    KEV-listed and high-EPSS alerts sort first.
    """
    prev = set(prev_ids or [])
    new = [{"cve": cid, **meta} for cid, meta in current.items() if cid not in prev]
    new.sort(key=lambda a: (1 if a.get("kev") else 0, a.get("epss", 0.0)), reverse=True)
    return new


def run(dry_run: bool = False) -> dict:
    watchlist = _load(WATCHLIST, [])
    state = _load(STATE, {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    result = {"generated_at": now, "repos": []}

    for repo in watchlist:
        repo = repo.strip()
        if not repo:
            continue
        entry = {"repo": repo, "new": [], "error": None}
        try:
            cur = current_cves(repo)
            prev_ids = (state.get(repo) or {}).get("cves", [])
            entry["new"] = diff_cves(prev_ids, cur)
            entry["total_cves"] = len(cur)
            state[repo] = {"cves": sorted(cur.keys()), "checked_at": now}
        except Exception as exc:
            entry["error"] = str(exc)[:200]
        result["repos"].append(entry)

    result["alert_count"] = sum(len(r["new"]) for r in result["repos"])
    result["kev_count"] = sum(1 for r in result["repos"] for a in r["new"] if a.get("kev"))

    if not dry_run:
        STATE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        ALERTS.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    # Expose a flag for the workflow (whether to open an issue).
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as f:
            f.write(f"alert_count={result['alert_count']}\n")
            f.write(f"kev_count={result['kev_count']}\n")

    return result


def to_markdown(result: dict) -> str:
    """Render a run result as a GitHub Issue body."""
    lines = [f"## SecureScope watch — new dependency CVEs", "",
             f"_Scan at {result.get('generated_at','')}_", ""]
    any_new = False
    for r in result["repos"]:
        if r.get("error"):
            lines.append(f"- ⚠️ `{r['repo']}` — scan error: {r['error']}")
            continue
        if not r["new"]:
            continue
        any_new = True
        lines.append(f"### {r['repo'].replace('https://', '')}")
        lines.append("| CVE | Package | Severity | KEV | EPSS |")
        lines.append("|---|---|---|---|---|")
        for a in r["new"]:
            kev = "🔴 yes" if a.get("kev") else "—"
            lines.append(f"| {a['cve']} | `{a.get('package','')}` | {a.get('severity','')} | {kev} | {a.get('epss',0)*100:.0f}% |")
        lines.append("")
    if not any_new:
        lines.append("_No new CVEs since the last check._")
    return "\n".join(lines)


if __name__ == "__main__":
    res = run(dry_run="--dry-run" in sys.argv)
    print(to_markdown(res))
    print(f"\nalert_count={res['alert_count']} kev_count={res['kev_count']}")
