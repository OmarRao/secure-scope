"""
Notification integrations — Slack and Microsoft Teams webhooks.
Posts scan completion summaries as incoming webhook messages.
"""

import json
import requests
from typing import Optional


def _severity_counts(result) -> dict:
    """Return {ERROR: N, WARNING: N, INFO: N} from an AnalysisResult."""
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _top_criticals(result, n: int = 3) -> list:
    """Return the top N ERROR-severity findings, falling back to WARNING."""
    errors = [f for f in result.findings if f.severity == "ERROR"]
    if not errors:
        errors = [f for f in result.findings if f.severity == "WARNING"]
    return errors[:n]


def send_slack_notification(result, webhook_url: str,
                            critical_only: bool = False,
                            report_url: Optional[str] = None) -> bool:
    """
    Post a scan-completion summary to a Slack incoming webhook.

    Args:
        result:       AnalysisResult from analyzer.analyze().
        webhook_url:  Slack incoming webhook URL.
        critical_only: If True, skip sending when there are no ERROR findings.
        report_url:   Optional link to the HTML report included in the message.

    Returns True on HTTP 200, False on any error (never raises).
    """
    try:
        counts = _severity_counts(result)
        errors = counts.get("ERROR", 0)
        warnings = counts.get("WARNING", 0)
        infos = counts.get("INFO", 0)

        if critical_only and errors == 0:
            return True  # nothing to send

        repo_name = result.repo_url.rstrip("/").split("/")[-1]
        color = "#d32f2f" if errors else ("#f57c00" if warnings else "#388e3c")

        # Build top-3 critical findings attachment text
        top_text = ""
        for i, f in enumerate(_top_criticals(result), 1):
            loc = f"{f.file}:{f.line_start}"
            top_text += f"{i}. `{f.rule_id}` — {f.message[:80]}\n   {loc}"
            if f.cwe:
                top_text += f" | {f.cwe}"
            top_text += "\n"

        fields = [
            {"title": "ERROR", "value": str(errors), "short": True},
            {"title": "WARNING", "value": str(warnings), "short": True},
            {"title": "INFO", "value": str(infos), "short": True},
            {"title": "Dep. CVEs", "value": str(len(result.dependency_vulns)), "short": True},
        ]
        if report_url:
            fields.append({"title": "Report", "value": f"<{report_url}|View full report>", "short": False})

        payload = {
            "text": f":mag: *SecureScope scan complete* — `{repo_name}`",
            "attachments": [
                {
                    "color": color,
                    "fields": fields,
                    "footer": "SecureScope v8.0.0",
                },
            ],
        }

        if top_text:
            payload["attachments"].append({
                "color": color,
                "title": "Top Critical Findings",
                "text": top_text,
                "mrkdwn_in": ["text"],
            })

        resp = requests.post(webhook_url, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def send_teams_notification(result, webhook_url: str,
                            critical_only: bool = False,
                            report_url: Optional[str] = None) -> bool:
    """
    Post a scan-completion summary to a Microsoft Teams incoming webhook (Adaptive Card).

    Args:
        result:       AnalysisResult from analyzer.analyze().
        webhook_url:  Teams incoming webhook URL.
        critical_only: If True, skip sending when there are no ERROR findings.
        report_url:   Optional link to the HTML report.

    Returns True on HTTP 200, False on any error (never raises).
    """
    try:
        counts = _severity_counts(result)
        errors = counts.get("ERROR", 0)
        warnings = counts.get("WARNING", 0)
        infos = counts.get("INFO", 0)

        if critical_only and errors == 0:
            return True

        repo_name = result.repo_url.rstrip("/").split("/")[-1]
        theme_color = "d32f2f" if errors else ("f57c00" if warnings else "388e3c")

        facts = [
            {"name": "ERROR", "value": str(errors)},
            {"name": "WARNING", "value": str(warnings)},
            {"name": "INFO", "value": str(infos)},
            {"name": "Dep. CVEs", "value": str(len(result.dependency_vulns))},
        ]

        sections = [
            {
                "activityTitle": f"SecureScope scan complete — **{repo_name}**",
                "activitySubtitle": result.repo_url,
                "facts": facts,
                "markdown": True,
            }
        ]

        top = _top_criticals(result)
        if top:
            lines = []
            for i, f in enumerate(top, 1):
                loc = f"{f.file}:{f.line_start}"
                line = f"{i}. **{f.rule_id}** — {f.message[:80]}  \n`{loc}`"
                if f.cwe:
                    line += f" | {f.cwe}"
                lines.append(line)
            sections.append({
                "title": "Top Critical Findings",
                "text": "\n\n".join(lines),
                "markdown": True,
            })

        actions = []
        if report_url:
            actions.append({
                "@type": "OpenUri",
                "name": "View Report",
                "targets": [{"os": "default", "uri": report_url}],
            })

        payload: dict = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"SecureScope: {repo_name} — {errors} errors",
            "sections": sections,
        }
        if actions:
            payload["potentialAction"] = actions

        resp = requests.post(webhook_url, json=payload, timeout=10)
        return resp.status_code in (200, 202)
    except Exception:
        return False
