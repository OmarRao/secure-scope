# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Continuous dependency-CVE monitor for watched repositories.

Reads a maintainer-curated watchlist (watchlist.json), scans each repo's
dependencies via OSV.dev, enriches with EPSS + CISA KEV, and diffs the result
against the last saved state (watch_state.json). Two things raise an alert:
  - a *newly appearing* CVE (KEV-listed ones flagged as priority), and
  - an *escalation* of an already-present CVE — it was added to CISA KEV since
    the last run, or its EPSS exploit probability jumped sharply.
The saved state keeps per-CVE KEV/EPSS so drift can be detected run-to-run.

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


_EPSS_JUMP = 0.20  # absolute EPSS increase (20 pts) that warrants a drift alert


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


def _prev_ids(entry) -> set:
    """Previously-known CVE ids from a saved state entry (dict or legacy list)."""
    cves = (entry or {}).get("cves")
    if isinstance(cves, dict):
        return set(cves.keys())
    if isinstance(cves, list):
        return set(cves)
    return set()


def _prev_meta(entry) -> dict:
    """Per-CVE {kev, epss} from a saved state entry; empty for the legacy list format."""
    cves = (entry or {}).get("cves")
    return cves if isinstance(cves, dict) else {}


def diff_escalations(prev_meta: dict, current: dict) -> list:
    """Alert records for *already-known* CVEs whose risk escalated since last run.

    An escalation is a CVE that was present before and has since been added to
    CISA KEV (now actively exploited) or whose EPSS jumped by >= _EPSS_JUMP.
    Brand-new CVEs are not escalations — diff_cves handles those.
    """
    out = []
    for cid, meta in (current or {}).items():
        prev = (prev_meta or {}).get(cid)
        if not prev:
            continue
        reasons = []
        if meta.get("kev") and not prev.get("kev"):
            reasons.append("added to CISA KEV")
        try:
            delta = float(meta.get("epss", 0) or 0) - float(prev.get("epss", 0) or 0)
        except (TypeError, ValueError):
            delta = 0.0
        if delta >= _EPSS_JUMP:
            reasons.append(f"EPSS +{round(delta * 100)} pts")
        if reasons:
            out.append({"cve": cid, **meta, "escalation": "; ".join(reasons)})
    out.sort(key=lambda a: (1 if a.get("kev") else 0, a.get("epss", 0.0)), reverse=True)
    return out


def run(dry_run: bool = False) -> dict:
    watchlist = _load(WATCHLIST, [])
    state = _load(STATE, {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    result = {"generated_at": now, "repos": []}

    for repo in watchlist:
        repo = repo.strip()
        if not repo:
            continue
        entry = {"repo": repo, "new": [], "escalations": [], "error": None}
        try:
            cur = current_cves(repo)
            saved = state.get(repo)
            entry["new"] = diff_cves(_prev_ids(saved), cur)
            entry["escalations"] = diff_escalations(_prev_meta(saved), cur)
            entry["total_cves"] = len(cur)
            # Persist per-CVE meta so future runs can detect KEV/EPSS drift.
            state[repo] = {
                "cves": {cid: {"kev": bool(m.get("kev")), "epss": m.get("epss", 0.0)}
                         for cid, m in cur.items()},
                "checked_at": now,
            }
        except Exception as exc:
            entry["error"] = str(exc)[:200]
        result["repos"].append(entry)

    new_count = sum(len(r["new"]) for r in result["repos"])
    esc_count = sum(len(r.get("escalations", [])) for r in result["repos"])
    result["new_count"] = new_count
    result["escalation_count"] = esc_count
    # alert_count drives whether the workflow opens an issue — new CVEs *and*
    # escalations of existing ones both count.
    result["alert_count"] = new_count + esc_count
    result["kev_count"] = sum(
        1 for r in result["repos"] for a in (r["new"] + r.get("escalations", [])) if a.get("kev"))

    if not dry_run:
        STATE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        ALERTS.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    # Expose flags for the workflow (whether to open an issue).
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as f:
            f.write(f"alert_count={result['alert_count']}\n")
            f.write(f"kev_count={result['kev_count']}\n")
            f.write(f"new_count={new_count}\n")
            f.write(f"escalation_count={esc_count}\n")

    return result


def to_markdown(result: dict) -> str:
    """Render a run result as a GitHub Issue body."""
    lines = [f"## SecureScope watch — dependency CVE drift", "",
             f"_Scan at {result.get('generated_at','')}_", ""]
    any_alert = False
    for r in result["repos"]:
        if r.get("error"):
            lines.append(f"- ⚠️ `{r['repo']}` — scan error: {r['error']}")
            continue
        new = r.get("new") or []
        esc = r.get("escalations") or []
        if not new and not esc:
            continue
        any_alert = True
        lines.append(f"### {r['repo'].replace('https://', '')}")
        if new:
            lines.append("**🆕 New CVEs**")
            lines.append("| CVE | Package | Severity | KEV | EPSS |")
            lines.append("|---|---|---|---|---|")
            for a in new:
                kev = "🔴 yes" if a.get("kev") else "—"
                lines.append(f"| {a['cve']} | `{a.get('package','')}` | {a.get('severity','')} | {kev} | {a.get('epss',0)*100:.0f}% |")
            lines.append("")
        if esc:
            lines.append("**⚠️ Escalations (already-present CVEs now more dangerous)**")
            lines.append("| CVE | Package | Change | KEV | EPSS |")
            lines.append("|---|---|---|---|---|")
            for a in esc:
                kev = "🔴 yes" if a.get("kev") else "—"
                lines.append(f"| {a['cve']} | `{a.get('package','')}` | {a.get('escalation','')} | {kev} | {a.get('epss',0)*100:.0f}% |")
            lines.append("")
    if not any_alert:
        lines.append("_No new CVEs or escalations since the last check._")
    return "\n".join(lines)


if __name__ == "__main__":
    res = run(dry_run="--dry-run" in sys.argv)
    print(to_markdown(res))
    print(f"\nalert_count={res['alert_count']} new={res.get('new_count',0)} "
          f"escalations={res.get('escalation_count',0)} kev_count={res['kev_count']}")
