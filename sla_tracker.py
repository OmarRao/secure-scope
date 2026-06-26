"""
SLA breach detection and alerting for SecureScope.
"""

import sqlite3
from datetime import datetime, timezone
from typing import Optional

import requests


_DEFAULT_SLA = {"CRITICAL": 7, "HIGH": 14, "MEDIUM": 30}


def update_sla_status(db_path: str) -> None:
    """Update days_open and breached flag for all open findings."""
    from db import _DEFAULT_SLA as _d
    now = datetime.now(timezone.utc)

    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute(
            """SELECT st.id, st.first_seen, f.severity
               FROM sla_tracking st
               JOIN findings f ON st.finding_id=f.id
               WHERE f.status='open'"""
        )
        rows = cur.fetchall()

        for row_id, first_seen_str, severity in rows:
            try:
                first_seen = datetime.fromisoformat(first_seen_str)
                # Make timezone-aware if naive
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=timezone.utc)
            except Exception:
                first_seen = now

            days_open = (now - first_seen).days
            threshold = _DEFAULT_SLA.get((severity or "").upper(), 9999)
            breached = 1 if days_open > threshold else 0

            cur.execute(
                """UPDATE sla_tracking
                   SET last_seen=?, days_open=?, breached=?
                   WHERE id=?""",
                (now.isoformat(), days_open, breached, row_id),
            )

        con.commit()
    finally:
        con.close()


def check_sla(
    db_path: str,
    slack_webhook: Optional[str] = None,
    sla_days: Optional[dict] = None,
) -> list[dict]:
    """
    Check for SLA breaches and optionally alert via Slack.

    Returns list of breached finding dicts.
    """
    from db import get_sla_breaches

    if sla_days is None:
        sla_days = _DEFAULT_SLA

    breaches = get_sla_breaches(db_path, sla_days=sla_days)

    if breaches and slack_webhook:
        _send_slack_alert(slack_webhook, breaches)

    return breaches


def _send_slack_alert(webhook_url: str, breaches: list[dict]) -> None:
    """Send a Slack message listing SLA-breached findings."""
    lines = [f"*:rotating_light: SecureScope SLA Breach Alert — {len(breaches)} findings overdue*\n"]
    for b in breaches[:20]:  # cap at 20 to avoid huge messages
        lines.append(
            f"• *{b.get('severity','')}* `{b.get('rule_id','')}` "
            f"in `{b.get('file','')}` — "
            f"{b.get('days_open',0)} days open "
            f"(repo: {b.get('repo_url','')})"
        )
    if len(breaches) > 20:
        lines.append(f"_...and {len(breaches)-20} more._")

    payload = {"text": "\n".join(lines)}
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as exc:
        print(f"[sla_tracker] Slack alert failed: {exc}")
