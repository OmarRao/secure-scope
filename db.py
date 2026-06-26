"""
SQLite persistence layer for SecureScope scan results.
Uses stdlib sqlite3 only — no external dependencies.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url    TEXT NOT NULL,
    scanned_at  TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    critical    INTEGER DEFAULT 0,
    high        INTEGER DEFAULT 0,
    medium      INTEGER DEFAULT 0,
    low         INTEGER DEFAULT 0,
    cve_count   INTEGER DEFAULT 0,
    secret_count INTEGER DEFAULT 0,
    iac_count   INTEGER DEFAULT 0,
    sarif_path  TEXT,
    sbom_path   TEXT,
    html_path   TEXT
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    rule_id     TEXT,
    severity    TEXT,
    file        TEXT,
    line_start  INTEGER,
    cwe         TEXT,
    message     TEXT,
    status      TEXT DEFAULT 'open'
);
"""

_CREATE_SLA = """
CREATE TABLE IF NOT EXISTS sla_tracking (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    days_open   INTEGER DEFAULT 0,
    breached    INTEGER DEFAULT 0
);
"""


def init_db(db_path: str) -> None:
    """Create database tables if they don't exist."""
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.executescript(_CREATE_SCANS + _CREATE_FINDINGS + _CREATE_SLA)
        con.commit()
    finally:
        con.close()


def record_scan(db_path: str, result, paths: Optional[dict] = None) -> int:
    """
    Insert a scan record and its findings into the database.

    Args:
        db_path: Path to the SQLite database file.
        result:  AnalysisResult object from analyzer.py.
        paths:   Optional dict with keys 'html', 'sarif', 'sbom'.

    Returns:
        The scan_id of the inserted scan record.
    """
    paths = paths or {}
    now = datetime.now(timezone.utc).isoformat()

    summary = result.summary() if hasattr(result, "summary") else {}
    by_sev = summary.get("by_severity", {})

    findings_list = result.findings if hasattr(result, "findings") else []

    critical = by_sev.get("CRITICAL", 0)
    high = by_sev.get("ERROR", by_sev.get("HIGH", 0))
    medium = by_sev.get("WARNING", by_sev.get("MEDIUM", 0))
    low = by_sev.get("INFO", by_sev.get("LOW", 0))
    cve_count = len(result.dependency_vulns) if hasattr(result, "dependency_vulns") else 0

    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute(
            """INSERT INTO scans
               (repo_url, scanned_at, total_findings, critical, high, medium, low,
                cve_count, sarif_path, sbom_path, html_path)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                getattr(result, "repo_url", ""),
                now,
                len(findings_list),
                critical, high, medium, low,
                cve_count,
                paths.get("sarif"),
                paths.get("sbom"),
                paths.get("html"),
            ),
        )
        scan_id = cur.lastrowid

        for f in findings_list:
            d = f.to_dict() if hasattr(f, "to_dict") else f
            cur.execute(
                """INSERT INTO findings
                   (scan_id, rule_id, severity, file, line_start, cwe, message, status)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    scan_id,
                    d.get("rule_id", ""),
                    d.get("severity", ""),
                    d.get("file", ""),
                    d.get("line_start", 0),
                    d.get("cwe", ""),
                    d.get("message", ""),
                    "open",
                ),
            )
            finding_id = cur.lastrowid
            cur.execute(
                """INSERT INTO sla_tracking (finding_id, first_seen, last_seen, days_open, breached)
                   VALUES (?,?,?,0,0)""",
                (finding_id, now, now),
            )

        con.commit()
        return scan_id
    finally:
        con.close()


def get_scan_history(db_path: str, repo_url: str, limit: int = 30) -> list[dict]:
    """Return recent scan records for trend chart."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        cur.execute(
            """SELECT * FROM scans WHERE repo_url=? ORDER BY scanned_at DESC LIMIT ?""",
            (repo_url, limit),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        con.close()


def get_open_findings(db_path: str, repo_url: str) -> list[dict]:
    """Return all open findings for a repo."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        cur.execute(
            """SELECT f.* FROM findings f
               JOIN scans s ON f.scan_id=s.id
               WHERE s.repo_url=? AND f.status='open'
               ORDER BY f.severity, f.id""",
            (repo_url,),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        con.close()


def get_sla_breaches(
    db_path: str,
    sla_days: Optional[dict] = None,
) -> list[dict]:
    """Return findings open longer than their SLA threshold."""
    if sla_days is None:
        sla_days = {"CRITICAL": 7, "HIGH": 14, "MEDIUM": 30}

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        cur.execute(
            """SELECT f.*, st.days_open, st.first_seen, s.repo_url
               FROM findings f
               JOIN sla_tracking st ON st.finding_id=f.id
               JOIN scans s ON f.scan_id=s.id
               WHERE f.status='open'"""
        )
        rows = [dict(row) for row in cur.fetchall()]
        breaches = []
        for row in rows:
            sev = (row.get("severity") or "").upper()
            threshold = sla_days.get(sev)
            if threshold and row.get("days_open", 0) > threshold:
                breaches.append(row)
        return breaches
    finally:
        con.close()
