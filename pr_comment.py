# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Pull-request review bot.

On a GitHub `pull_request` event, scan the PR's HEAD and base ref, classify the
findings as new / fixed / pre-existing (see diff_scan), and post a single
summary comment back on the PR. Uses the standard GitHub REST API with a token
(the webhook server passes GITHUB_TOKEN); no GitHub App registration required.

Everything is best-effort and fail-safe: a missing token, an unsupported event,
or an API hiccup logs and returns without raising, so it can never wedge the
webhook server.
"""

import json
import urllib.request
import urllib.error

_GH_API = "https://api.github.com"
_ACTIONABLE = {"opened", "synchronize", "reopened", "ready_for_review"}


def parse_pr_event(event: dict) -> dict | None:
    """Extract the fields we need from a `pull_request` webhook payload.

    Returns a dict {repo_full, repo_url, pr_number, base_branch, head_branch,
    action} or None if this event isn't a reviewable pull request.
    """
    if not isinstance(event, dict):
        return None
    pr = event.get("pull_request") or {}
    if not pr:
        return None
    action = event.get("action", "")
    if action and action not in _ACTIONABLE:
        return None
    repo = event.get("repository") or {}
    repo_full = repo.get("full_name") or ""
    repo_url = repo.get("clone_url") or (f"https://github.com/{repo_full}.git" if repo_full else "")
    pr_number = event.get("number") or pr.get("number")
    base_branch = (pr.get("base") or {}).get("ref") or "main"
    head_branch = (pr.get("head") or {}).get("ref") or ""
    if not (repo_full and pr_number):
        return None
    return {
        "repo_full": repo_full, "repo_url": repo_url, "pr_number": int(pr_number),
        "base_branch": base_branch, "head_branch": head_branch, "action": action,
    }


def post_pr_comment(repo_full: str, pr_number: int, body: str, token: str) -> bool:
    """Post a comment on a PR (issues comments API). Returns True on success."""
    if not token:
        print("[pr] no GitHub token — skipping PR comment")
        return False
    url = f"{_GH_API}/repos/{repo_full}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "SecureScope-PR-Bot",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        print(f"[pr] comment failed: HTTP {e.code}")
        return False
    except Exception as e:
        print(f"[pr] comment failed: {e}")
        return False


def review_pull_request(info: dict, token: str | None) -> dict:
    """Scan + classify a PR and post the summary comment. Returns a small result."""
    from analyzer import analyze_pr_classified
    from diff_scan import classification_markdown

    out = {"repo": info.get("repo_full"), "pr": info.get("pr_number"),
           "commented": False, "counts": {}}
    try:
        result = analyze_pr_classified(info["repo_url"], base_branch=info["base_branch"])
        cls = result.finding_classes or {"counts": {}}
        out["counts"] = cls.get("counts", {})
        body = classification_markdown(cls, info["base_branch"])
        body += "\n\n<sub>🛡️ Posted by SecureScope</sub>"
        out["commented"] = post_pr_comment(
            info["repo_full"], info["pr_number"], body, token or "")
    except Exception as e:
        print(f"[pr] review failed: {e}")
    return out
