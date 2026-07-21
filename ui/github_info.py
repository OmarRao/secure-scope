"""
Fetches repository metadata for the report header — across GitHub, GitLab and
Bitbucket. GitHub gets the richest data (commits, contributors, file tree);
GitLab and Bitbucket get best-effort core metadata. Every path degrades
gracefully to a minimal dict so a scan is never blocked by a metadata hiccup.
"""

import os
import re
import urllib.parse
import requests
from datetime import datetime
from typing import Optional


GH_API = "https://api.github.com"
GL_API = "https://gitlab.com/api/v4"
BB_API = "https://api.bitbucket.org/2.0"

_HOSTS = {"github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket"}


def _split(url: str) -> Optional[dict]:
    """Parse a repo URL from any supported host → {host, path, owner, repo}."""
    if not url:
        return None
    m = re.search(r"(github\.com|gitlab\.com|bitbucket\.org)[:/]+(.+)", url.strip(), re.I)
    if not m:
        return None
    host = _HOSTS[m.group(1).lower()]
    path = m.group(2).split("?")[0].split("#")[0].strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return None
    return {"host": host, "path": path, "owner": parts[0], "repo": parts[-1]}


def parse_repo_url(url: str) -> Optional[tuple[str, str]]:
    """Extract (owner, repo) from a GitHub/GitLab/Bitbucket URL (or None)."""
    s = _split(url)
    return (s["owner"], s["repo"]) if s else None


def repo_host(url: str) -> Optional[str]:
    """Return 'github' | 'gitlab' | 'bitbucket' | None for a repo URL."""
    s = _split(url)
    return s["host"] if s else None


def _headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _base(s: dict) -> dict:
    """Minimal, template-safe metadata dict used as the fallback for every host."""
    return {
        "host": s["host"], "owner": s["owner"], "repo": s["repo"],
        "full_name": f'{s["owner"]}/{s["repo"]}',
        "description": "No description provided.",
        "url": f'https://{ {"github":"github.com","gitlab":"gitlab.com","bitbucket":"bitbucket.org"}[s["host"]] }/{s["path"]}',
        "homepage": None, "stars": 0, "forks": 0, "watchers": 0, "open_issues": 0,
        "default_branch": "main", "language": "Unknown", "license": "None",
        "topics": [], "size_kb": 0, "archived": False, "private": False,
        "created_at": "—", "updated_at": "—", "pushed_at": "—",
        "avatar_url": None, "owner_type": None,
        "languages": {}, "recent_commits": [], "contributors": [], "file_tree": [],
    }


def fetch_repo_info(repo_url: str) -> dict:
    """Return repo metadata for the report header (host-aware, best-effort)."""
    s = _split(repo_url)
    if not s:
        return {"error": "Invalid repository URL"}
    info = _base(s)
    try:
        if s["host"] == "github":
            return _github(s, info)
        if s["host"] == "gitlab":
            return _gitlab(s, info)
        if s["host"] == "bitbucket":
            return _bitbucket(s, info)
    except Exception:
        pass  # network/API hiccup — fall back to the minimal dict
    return info


# ── GitHub (rich) ────────────────────────────────────────────────────────────

def _github(s: dict, info: dict) -> dict:
    owner, repo = s["owner"], s["repo"]
    h = _headers()
    r = requests.get(f"{GH_API}/repos/{owner}/{repo}", headers=h, timeout=10)
    if r.status_code != 200:
        return info  # minimal fallback (e.g. rate-limited / private)
    d = r.json()
    info.update({
        "full_name": d.get("full_name") or info["full_name"],
        "description": d.get("description") or info["description"],
        "url": d.get("html_url") or info["url"],
        "homepage": d.get("homepage"),
        "stars": d.get("stargazers_count", 0), "forks": d.get("forks_count", 0),
        "watchers": d.get("watchers_count", 0), "open_issues": d.get("open_issues_count", 0),
        "default_branch": d.get("default_branch", "main"),
        "language": d.get("language") or "Unknown",
        "license": d.get("license", {}).get("spdx_id") if d.get("license") else "None",
        "topics": d.get("topics", []), "size_kb": d.get("size", 0),
        "archived": d.get("archived", False), "private": d.get("private", False),
        "created_at": _fmt_date(d.get("created_at")), "updated_at": _fmt_date(d.get("updated_at")),
        "pushed_at": _fmt_date(d.get("pushed_at")),
        "avatar_url": d.get("owner", {}).get("avatar_url"),
        "owner_type": d.get("owner", {}).get("type"),
    })
    lr = requests.get(f"{GH_API}/repos/{owner}/{repo}/languages", headers=h, timeout=10)
    if lr.ok:
        langs = lr.json(); total = sum(langs.values()) or 1
        info["languages"] = {k: round(v / total * 100, 1) for k, v in sorted(langs.items(), key=lambda x: -x[1])}
    cr = requests.get(f"{GH_API}/repos/{owner}/{repo}/commits?per_page=7", headers=h, timeout=10)
    if cr.ok:
        info["recent_commits"] = [{
            "sha": c["sha"][:7], "message": c["commit"]["message"].splitlines()[0][:72],
            "author": c["commit"]["author"].get("name", "unknown"),
            "date": _fmt_date(c["commit"]["author"].get("date")),
        } for c in cr.json()]
    contr = requests.get(f"{GH_API}/repos/{owner}/{repo}/contributors?per_page=8", headers=h, timeout=10)
    if contr.ok:
        info["contributors"] = [{
            "login": c.get("login"), "contributions": c.get("contributions"),
            "avatar": c.get("avatar_url"), "url": c.get("html_url"),
        } for c in contr.json() if isinstance(c, dict)]
    tr = requests.get(f"{GH_API}/repos/{owner}/{repo}/contents", headers=h, timeout=10)
    if tr.ok:
        info["file_tree"] = [{"name": f["name"], "type": f["type"], "size": f.get("size", 0)} for f in tr.json()]
    return info


# ── GitLab (core metadata) ───────────────────────────────────────────────────

def _gitlab(s: dict, info: dict) -> dict:
    pid = urllib.parse.quote(s["path"], safe="")
    r = requests.get(f"{GL_API}/projects/{pid}", timeout=10)
    if not r.ok:
        return info
    d = r.json()
    info.update({
        "full_name": d.get("path_with_namespace") or info["full_name"],
        "description": d.get("description") or info["description"],
        "url": d.get("web_url") or info["url"],
        "stars": d.get("star_count", 0), "forks": d.get("forks_count", 0),
        "default_branch": d.get("default_branch") or "main",
        "created_at": _fmt_date(d.get("created_at")),
        "pushed_at": _fmt_date(d.get("last_activity_at")),
        "avatar_url": d.get("avatar_url"),
    })
    lr = requests.get(f"{GL_API}/projects/{pid}/languages", timeout=10)
    if lr.ok and isinstance(lr.json(), dict):
        info["languages"] = {k: round(v, 1) for k, v in sorted(lr.json().items(), key=lambda x: -x[1])}
        if info["languages"]:
            info["language"] = next(iter(info["languages"]))
    return info


# ── Bitbucket (core metadata) ────────────────────────────────────────────────

def _bitbucket(s: dict, info: dict) -> dict:
    r = requests.get(f'{BB_API}/repositories/{s["owner"]}/{s["repo"]}', timeout=10)
    if not r.ok:
        return info
    d = r.json()
    info.update({
        "full_name": d.get("full_name") or info["full_name"],
        "description": d.get("description") or info["description"],
        "url": (d.get("links", {}).get("html", {}) or {}).get("href") or info["url"],
        "default_branch": (d.get("mainbranch", {}) or {}).get("name") or "main",
        "language": d.get("language") or "Unknown",
        "created_at": _fmt_date(d.get("created_on")),
        "pushed_at": _fmt_date(d.get("updated_on")),
        "private": d.get("is_private", False),
    })
    return info


def _fmt_date(iso: Optional[str]) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%b %d, %Y")
    except Exception:
        return iso
