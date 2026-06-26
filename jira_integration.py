"""
Create Jira Cloud tickets for SecureScope security findings.
Mirrors the pattern from github_issues.py.
"""

import requests
from typing import Optional

_SEVERITY_ORDER = {"CRITICAL": 0, "ERROR": 1, "HIGH": 1, "WARNING": 2, "MEDIUM": 2, "LOW": 3, "INFO": 3}
_THRESHOLD_MAP = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_PRIORITY_MAP = {
    "CRITICAL": "Highest",
    "ERROR": "High",
    "HIGH": "High",
    "WARNING": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Low",
}


def _jira_headers(email: str, token: str) -> dict:
    import base64
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _issue_exists(jira_url: str, headers: dict, project_key: str, rule_id: str) -> bool:
    """Check if a Jira issue with this rule_id already exists."""
    jql = f'project="{project_key}" AND labels="secscope" AND summary~"{rule_id}"'
    try:
        resp = requests.get(
            f"{jira_url}/rest/api/3/issue/picker",
            params={"query": rule_id, "currentJQL": jql},
            headers=headers,
            timeout=15,
        )
        # Fall back to search API
        resp2 = requests.post(
            f"{jira_url}/rest/api/3/issue/search",
            json={"jql": jql, "maxResults": 1, "fields": ["summary"]},
            headers=headers,
            timeout=15,
        )
        if resp2.status_code == 200:
            return resp2.json().get("total", 0) > 0
    except Exception:
        pass
    return False


def create_jira_issues(
    jira_url: str,
    jira_email: str,
    jira_token: str,
    project_key: str,
    findings: list,
    threshold: str = "HIGH",
) -> list[str]:
    """
    Create Jira Cloud Bug tickets for findings at or above threshold.

    Args:
        jira_url:     Base Jira URL, e.g. https://yourorg.atlassian.net
        jira_email:   Jira user email for Basic Auth.
        jira_token:   Jira API token.
        project_key:  Jira project key (e.g. SEC).
        findings:     List of finding dicts from SecureScope.
        threshold:    Minimum severity: CRITICAL, HIGH, MEDIUM, LOW.

    Returns:
        List of created issue keys (e.g. ['SEC-42', 'SEC-43']).
    """
    headers = _jira_headers(jira_email, jira_token)
    threshold_val = _THRESHOLD_MAP.get(threshold.upper(), 1)
    created_keys: list[str] = []

    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        sev_val = _SEVERITY_ORDER.get(sev, 99)
        if sev_val > threshold_val:
            continue

        rule_id = f.get("rule_id", "unknown")
        file_path = f.get("file", "")
        line_start = f.get("line_start", 0)
        cwe = f.get("cwe") or ""
        technique = f.get("attack_technique") or ""
        message = f.get("message", "")

        # Deduplication
        if _issue_exists(jira_url, headers, project_key, rule_id):
            print(f"[jira] Issue for {rule_id} already exists — skipping")
            continue

        labels = ["security", "secscope"]
        if cwe:
            labels.append(cwe)

        description_content = [
            {"type": "paragraph", "content": [{"type": "text", "text": f"Severity: {sev}"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": f"File: {file_path} (line {line_start})"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": f"Message: {message}"}]},
        ]
        if cwe:
            description_content.append(
                {"type": "paragraph", "content": [{"type": "text", "text": f"CWE: {cwe}"}]}
            )
        if technique:
            description_content.append(
                {"type": "paragraph", "content": [{"type": "text", "text": f"ATT&CK: {technique}"}]}
            )

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[SecureScope] {rule_id}: {message[:80]}",
                "issuetype": {"name": "Bug"},
                "priority": {"name": _PRIORITY_MAP.get(sev, "Medium")},
                "labels": labels,
                "description": {
                    "version": 1,
                    "type": "doc",
                    "content": description_content,
                },
            }
        }

        try:
            resp = requests.post(
                f"{jira_url}/rest/api/3/issue",
                json=payload,
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 201:
                key = resp.json().get("key", "")
                created_keys.append(key)
                print(f"[jira] Created issue {key} for {rule_id}")
            else:
                print(f"[jira] Failed to create issue for {rule_id}: HTTP {resp.status_code} — {resp.text[:200]}")
        except Exception as exc:
            print(f"[jira] Error creating issue for {rule_id}: {exc}")

    return created_keys
