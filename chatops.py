# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
ChatOps: a Slack slash command (/scan) that kicks off a SecureScope scan and
returns a summary back to the channel.

Setup (one-time, requires a Slack app):
  1. Create a Slack app → Slash Commands → /scan → Request URL = your host + /slack/scan
  2. Copy the app's Signing Secret into SLACK_SIGNING_SECRET.
  3. Run the ChatOps endpoint (see run_chatops_server) behind that URL.

Slack posts application/x-www-form-urlencoded with `text`, `response_url`, etc.
Requests are verified with the signing secret (v0 HMAC scheme). The pure pieces
here — signature verification, command parsing, summary formatting — are unit
tested; the network parts (scan + async post to response_url) are thin wrappers.
"""

import hashlib
import hmac
import time

_MAX_SKEW = 60 * 5  # reject Slack requests older than 5 minutes (replay guard)


def verify_slack_signature(signing_secret: str, timestamp: str, body: str,
                           signature: str) -> bool:
    """Verify Slack's v0 request signature. Fail-closed on anything malformed."""
    if not (signing_secret and timestamp and signature):
        return False
    try:
        if abs(time.time() - int(timestamp)) > _MAX_SKEW:
            return False
    except (TypeError, ValueError):
        return False
    base = f"v0:{timestamp}:{body}".encode()
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_scan_command(text: str) -> dict | None:
    """Parse the `/scan <repo-url> [branch]` argument text.

    Returns {repo_url, branch} or None if no valid repo URL was given.
    """
    parts = (text or "").strip().split()
    if not parts:
        return None
    repo = parts[0].strip()
    if not repo.startswith(("http://", "https://", "git@")):
        return None
    branch = parts[1].strip() if len(parts) > 1 else "main"
    return {"repo_url": repo, "branch": branch}


def format_scan_result(repo_url: str, summary: dict, report_url: str = "") -> dict:
    """Format a completed scan as a Slack message payload (Block Kit-lite)."""
    s = summary or {}
    sev = s.get("by_severity", {}) or {}
    crit = sev.get("ERROR", s.get("critical", 0))
    warn = sev.get("WARNING", s.get("warnings", 0))
    total = s.get("total_findings", crit + warn)
    cves = s.get("dependency_vulns", 0)
    icon = ":red_circle:" if crit else (":large_yellow_circle:" if total else ":large_green_circle:")
    lines = [
        f"{icon} *SecureScope scan complete* — `{repo_url}`",
        f"*{total}* findings · *{crit}* critical · *{warn}* warnings · *{cves}* dependency CVEs",
    ]
    if report_url:
        lines.append(f"<{report_url}|Open full report>")
    return {"response_type": "in_channel", "text": "\n".join(lines)}


def ack_message(repo_url: str) -> dict:
    """Immediate ack Slack shows while the scan runs (must reply within 3s)."""
    return {"response_type": "ephemeral",
            "text": f":hourglass_flowing_sand: Scanning `{repo_url}` — I'll post the results here shortly."}
