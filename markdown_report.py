"""
Markdown report generator for SecureScope.
Produces a compact summary suitable for posting as a PR comment.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def to_markdown(
    result,
    path: str,
    secret_findings: Optional[list] = None,
    iac_findings: Optional[list] = None,
) -> str:
    """
    Write a compact Markdown security summary to *path*.

    Args:
        result:          AnalysisResult from analyzer.py
        path:            File path to write the .md file to
        secret_findings: List of secret dicts from secret_scanner.scan_secrets()
        iac_findings:    List of IaC dicts from iac_scanner.scan_iac()

    Returns:
        The path that was written.
    """
    summary = result.summary()
    by_sev = summary.get("by_severity", {})
    total = summary.get("total_findings", 0)
    cve_count = summary.get("dependency_vulns", 0)
    secret_count = len(secret_findings) if secret_findings else 0
    iac_count = len(iac_findings) if iac_findings else 0

    scan_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    repo_url = getattr(result, "repo_url", "unknown")

    # Severity badge helpers
    def _badge(label: str, count: int) -> str:
        return f"**{label}:** {count}"

    severity_line = " | ".join(
        _badge(k, v) for k, v in by_sev.items() if v > 0
    ) or "None"

    # Top 5 critical/error findings
    findings_raw = [f.to_dict() if hasattr(f, "to_dict") else f for f in result.findings]
    priority = [
        f for f in findings_raw
        if f.get("severity") in ("CRITICAL", "ERROR")
    ][:5]

    top_findings_md = ""
    if priority:
        top_findings_md = "\n### Top Findings\n\n| Rule | Location | Message |\n|------|----------|---------|\n"
        for f in priority:
            rule = f.get("rule_id", "—")
            loc = f"{f.get('file', '')}:{f.get('line_start', '')}"
            msg = (f.get("message", "") or "")[:100]
            msg = msg.replace("|", "\\|")
            top_findings_md += f"| `{rule}` | `{loc}` | {msg} |\n"

    lines = [
        f"## SecureScope Security Report",
        f"",
        f"**Repository:** {repo_url}  ",
        f"**Scan date:** {scan_date}",
        f"",
        f"### Finding Counts",
        f"",
        f"| Category | Count |",
        f"|----------|-------|",
        f"| Total static findings | {total} |",
        f"| {' | '.join(f'{k}: {v}' for k, v in by_sev.items() if v > 0) or 'No findings'} | |",
        f"| Dependency CVEs | {cve_count} |",
        f"| Hardcoded secrets | {secret_count} |",
        f"| IaC policy violations | {iac_count} |",
        f"",
        severity_line and f"> Severity breakdown: {severity_line}" or "",
        top_findings_md,
    ]

    # Remove blank lines caused by empty entries
    md = "\n".join(line for line in lines if line is not None)

    safe_path = os.path.abspath(path)
    Path(safe_path).write_text(md, encoding="utf-8")
    print(f"[+] Markdown report: {safe_path}")
    return path


def post_pr_comment(
    repo_url: str,
    github_token: str,
    md_path: str,
    pr_number: Optional[int] = None,
) -> bool:
    """
    Post the Markdown file contents as a comment on a GitHub PR.

    If pr_number is None, finds the latest open PR via the GitHub API.
    Returns True on success, False otherwise.
    """
    if not _HAS_REQUESTS:
        print("[!] 'requests' not installed — cannot post PR comment")
        return False

    # Parse owner/repo from URL
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?$', repo_url.rstrip("/"))
    if not m:
        print(f"[!] Cannot parse owner/repo from URL: {repo_url}")
        return False

    owner, repo = m.group(1), m.group(2)
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    # Resolve PR number
    if pr_number is None:
        api = f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open&sort=updated&direction=desc&per_page=1"
        try:
            resp = _requests.get(api, headers=headers, timeout=15)
            resp.raise_for_status()
            prs = resp.json()
            if not prs:
                print("[!] No open PRs found — skipping PR comment")
                return False
            pr_number = prs[0]["number"]
        except Exception as exc:
            print(f"[!] Failed to fetch open PRs: {exc}")
            return False

    # Read markdown content
    try:
        body = Path(md_path).read_text(encoding="utf-8")
    except Exception as exc:
        print(f"[!] Could not read markdown file {md_path}: {exc}")
        return False

    # Post comment
    api = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    try:
        resp = _requests.post(api, headers=headers, json={"body": body}, timeout=15)
        resp.raise_for_status()
        print(f"[+] PR comment posted to {repo_url}/pull/{pr_number}")
        return True
    except Exception as exc:
        print(f"[!] Failed to post PR comment: {exc}")
        return False
