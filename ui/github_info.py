"""
Fetches rich GitHub repository metadata for the report header section.
"""

import os
import re
import requests
from datetime import datetime, timezone
from typing import Optional


GH_API = "https://api.github.com"


def _headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def parse_repo_url(url: str) -> Optional[tuple[str, str]]:
    """Extract (owner, repo) from any GitHub URL."""
    m = re.search(r"github\.com[:/]([^/]+)/([^/\s\.]+)", url)
    return (m.group(1), m.group(2)) if m else None


def fetch_repo_info(repo_url: str) -> dict:
    """Return a rich dict of GitHub repo metadata."""
    parsed = parse_repo_url(repo_url)
    if not parsed:
        return {"error": "Invalid GitHub URL"}

    owner, repo = parsed
    h = _headers()

    info = {}

    # ── Core repo data ────────────────────────────────────────────
    r = requests.get(f"{GH_API}/repos/{owner}/{repo}", headers=h, timeout=10)
    if r.status_code != 200:
        return {"error": f"GitHub API error {r.status_code}"}
    d = r.json()

    info.update({
        "owner":        owner,
        "repo":         repo,
        "full_name":    d.get("full_name"),
        "description":  d.get("description") or "No description provided.",
        "url":          d.get("html_url"),
        "homepage":     d.get("homepage"),
        "stars":        d.get("stargazers_count", 0),
        "forks":        d.get("forks_count", 0),
        "watchers":     d.get("watchers_count", 0),
        "open_issues":  d.get("open_issues_count", 0),
        "default_branch": d.get("default_branch", "main"),
        "language":     d.get("language") or "Unknown",
        "license":      d.get("license", {}).get("spdx_id") if d.get("license") else "None",
        "topics":       d.get("topics", []),
        "size_kb":      d.get("size", 0),
        "archived":     d.get("archived", False),
        "private":      d.get("private", False),
        "created_at":   _fmt_date(d.get("created_at")),
        "updated_at":   _fmt_date(d.get("updated_at")),
        "pushed_at":    _fmt_date(d.get("pushed_at")),
        "avatar_url":   d.get("owner", {}).get("avatar_url"),
        "owner_type":   d.get("owner", {}).get("type"),
    })

    # ── Languages breakdown ────────────────────────────────────────
    lr = requests.get(f"{GH_API}/repos/{owner}/{repo}/languages", headers=h, timeout=10)
    if lr.ok:
        langs = lr.json()
        total = sum(langs.values()) or 1
        info["languages"] = {k: round(v / total * 100, 1) for k, v in sorted(langs.items(), key=lambda x: -x[1])}
    else:
        info["languages"] = {}

    # ── Recent commits ─────────────────────────────────────────────
    cr = requests.get(f"{GH_API}/repos/{owner}/{repo}/commits?per_page=7", headers=h, timeout=10)
    if cr.ok:
        info["recent_commits"] = [{
            "sha":     c["sha"][:7],
            "message": c["commit"]["message"].splitlines()[0][:72],
            "author":  c["commit"]["author"].get("name", "unknown"),
            "date":    _fmt_date(c["commit"]["author"].get("date")),
        } for c in cr.json()]
    else:
        info["recent_commits"] = []

    # ── Contributors ───────────────────────────────────────────────
    contr = requests.get(f"{GH_API}/repos/{owner}/{repo}/contributors?per_page=8", headers=h, timeout=10)
    if contr.ok:
        info["contributors"] = [{
            "login":       c.get("login"),
            "contributions": c.get("contributions"),
            "avatar":      c.get("avatar_url"),
            "url":         c.get("html_url"),
        } for c in contr.json() if isinstance(c, dict)]
    else:
        info["contributors"] = []

    # ── File tree (top level) ─────────────────────────────────────
    tr = requests.get(f"{GH_API}/repos/{owner}/{repo}/contents", headers=h, timeout=10)
    if tr.ok:
        info["file_tree"] = [{"name": f["name"], "type": f["type"], "size": f.get("size", 0)} for f in tr.json()]
    else:
        info["file_tree"] = []

    return info


def _fmt_date(iso: Optional[str]) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y")
    except Exception:
        return iso
