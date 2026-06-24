"""
Auto-create GitHub Issues for SecureScope findings.
Uses the GitHub REST API via requests.
"""

import re
import requests
from typing import Optional


SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}

# Label colours per severity
_LABEL_COLORS = {
    "error":   "d32f2f",
    "warning": "f57c00",
    "info":    "1976d2",
    "security": "e11d48",
}


def _parse_owner_repo(repo_url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL."""
    m = re.search(r"github\.com[:/]([^/]+)/([^/.]+)", repo_url)
    if not m:
        raise ValueError(f"Cannot parse GitHub owner/repo from: {repo_url}")
    return m.group(1), m.group(2).replace(".git", "")


def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _ensure_label(api_base: str, headers: dict, name: str, color: str) -> None:
    """Create a label if it doesn't already exist; ignore 422 (already exists)."""
    resp = requests.post(
        f"{api_base}/labels",
        json={"name": name, "color": color},
        headers=headers,
        timeout=15,
    )
    # 422 = already exists — that's fine
    if resp.status_code not in (201, 422):
        pass  # best-effort; don't raise


def _get_open_issues(api_base: str, headers: dict) -> list[dict]:
    """Fetch all open issues (paginated)."""
    issues = []
    url = f"{api_base}/issues"
    params: dict = {"state": "open", "per_page": 100, "page": 1}
    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            break
        page = resp.json()
        if not page:
            break
        issues.extend(page)
        if len(page) < 100:
            break
        params["page"] += 1
    return issues


def _is_duplicate(rule_id: str, file_path: str, open_issues: list[dict]) -> Optional[dict]:
    """Return existing issue dict if rule_id+file already has an open issue."""
    needle = f"[SecureScope] {rule_id}:"
    for issue in open_issues:
        title = issue.get("title", "")
        body = issue.get("body", "") or ""
        if title.startswith(needle) and file_path in body:
            return issue
    return None


def create_issues_for_findings(
    repo_url: str,
    github_token: str,
    findings: list,
    severity_threshold: str = "ERROR",
) -> list[dict]:
    """
    Create GitHub Issues for findings at or above severity_threshold.

    Args:
        repo_url:           GitHub repo URL (https://github.com/owner/repo).
        github_token:       Personal access token with repo scope.
        findings:           List of finding dicts (output of Finding.to_dict()).
        severity_threshold: Minimum severity to create issues for ("ERROR", "WARNING", "INFO").

    Returns:
        List of {"issue_number": N, "url": "...", "status": "created"|"exists"} dicts.
    """
    results: list[dict] = []

    try:
        owner, repo = _parse_owner_repo(repo_url)
    except ValueError as exc:
        print(f"[github_issues] {exc}")
        return results

    api_base = f"https://api.github.com/repos/{owner}/{repo}"
    headers = _gh_headers(github_token)
    threshold_val = SEVERITY_ORDER.get(severity_threshold.upper(), 0)

    # Pre-fetch open issues for deduplication
    open_issues = _get_open_issues(api_base, headers)

    # Ensure base labels exist
    _ensure_label(api_base, headers, "security", _LABEL_COLORS["security"])
    _ensure_label(api_base, headers, "error",   _LABEL_COLORS["error"])
    _ensure_label(api_base, headers, "warning", _LABEL_COLORS["warning"])
    _ensure_label(api_base, headers, "info",    _LABEL_COLORS["info"])

    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if SEVERITY_ORDER.get(sev, 99) > threshold_val:
            continue

        rule_id = f.get("rule_id", "unknown")
        msg = f.get("message", "")
        file_path = f.get("file", "")
        line_start = f.get("line_start", 0)
        cwe = f.get("cwe") or ""
        technique = f.get("attack_technique") or ""
        fix = f.get("fix_suggestion") or ""

        # Deduplication check
        existing = _is_duplicate(rule_id, file_path, open_issues)
        if existing:
            results.append({
                "issue_number": existing["number"],
                "url": existing["html_url"],
                "status": "exists",
            })
            continue

        title = f"[SecureScope] {rule_id}: {msg[:80]}"

        body_lines = [
            f"## SecureScope Finding: `{rule_id}`",
            "",
            f"**Severity:** {sev}",
            f"**File:** `{file_path}` (line {line_start})",
            "",
            "### Description",
            msg,
            "",
        ]
        if cwe:
            body_lines += [f"**CWE:** [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html)", ""]
        if technique:
            body_lines += [f"**ATT&CK Technique:** [{technique}](https://attack.mitre.org/techniques/{technique.replace('.','/')})", ""]
        if fix:
            body_lines += ["### Fix Suggestion", "```", fix, "```", ""]
        body_lines += ["---", "*Created automatically by SecureScope v8.0.0*"]

        labels = ["security", sev.lower()]
        if cwe:
            labels.append(cwe)
            # Ensure CWE label exists (no-op if already there)
            _ensure_label(api_base, headers, cwe, "7c3aed")

        try:
            resp = requests.post(
                f"{api_base}/issues",
                json={"title": title, "body": "\n".join(body_lines), "labels": labels},
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 201:
                data = resp.json()
                results.append({
                    "issue_number": data["number"],
                    "url": data["html_url"],
                    "status": "created",
                })
            else:
                print(f"[github_issues] Failed to create issue for {rule_id}: HTTP {resp.status_code}")
        except Exception as exc:
            print(f"[github_issues] Error creating issue for {rule_id}: {exc}")

    return results
