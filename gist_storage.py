"""
Persistent report storage via GitHub Gists.

Reports are uploaded as secret Gists so they survive Render redeployments.
A separate "index" Gist accumulates scan history records.
"""
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_INDEX_GIST_DESC = "SecureScope — scan history index"


def _github():
    from github import Github
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError("GITHUB_TOKEN env var not set")
    return Github(token)


def upload_report(html_content: str, repo_slug: str, ts: str) -> str:
    """Upload HTML report as a secret Gist. Returns the Gist HTML URL."""
    try:
        gh = _github()
        user = gh.get_user()
        filename = f"securescope_{repo_slug}_{ts}.html"
        gist = user.create_gist(
            public=False,
            files={filename: {"content": html_content}},
            description=f"SecureScope report — {repo_slug} {ts}",
        )
        logger.info("Report uploaded to Gist: %s", gist.html_url)
        return gist.html_url
    except Exception as exc:
        logger.warning("Gist upload failed: %s", exc)
        return ""


def _get_or_create_index_gist(gh):
    """Return the history index Gist (creates it if it doesn't exist)."""
    user = gh.get_user()
    for gist in user.get_gists():
        if gist.description == _INDEX_GIST_DESC:
            return gist
    # Create new index gist
    gist = user.create_gist(
        public=False,
        files={"scan_history.jsonl": {"content": ""}},
        description=_INDEX_GIST_DESC,
    )
    return gist


def append_history_record(record: dict) -> None:
    """Append one scan record to the history Gist index."""
    try:
        gh = _github()
        gist = _get_or_create_index_gist(gh)
        existing = gist.files.get("scan_history.jsonl")
        current = existing.content if existing and existing.content else ""
        updated = current.rstrip("\n") + "\n" + json.dumps(record) + "\n"
        gist.edit(files={"scan_history.jsonl": {"content": updated.lstrip("\n")}})
        logger.info("History record appended to index Gist")
    except Exception as exc:
        logger.warning("History Gist update failed: %s", exc)


def load_history_from_gist() -> list[dict]:
    """Load all scan history records from the index Gist."""
    try:
        gh = _github()
        gist = _get_or_create_index_gist(gh)
        raw = gist.files.get("scan_history.jsonl")
        if not raw or not raw.content:
            return []
        records = []
        for line in raw.content.splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return list(reversed(records))  # newest first
    except Exception as exc:
        logger.warning("History Gist load failed: %s", exc)
        return []


def build_history_record(
    repo_url: str,
    repo_slug: str,
    ts: str,
    summary: dict,
    gist_url: str,
) -> dict:
    return {
        "repo_url": repo_url,
        "repo_slug": repo_slug,
        "ts": ts,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": summary.get("total_findings", 0),
        "critical": summary.get("critical", 0),
        "warnings": summary.get("warnings", 0),
        "risk_score": summary.get("risk_score", 0),
        "gist_url": gist_url,
    }
