"""
Secret scanner: detects hardcoded secrets using detect-secrets.
"""

import json
import subprocess
from typing import Optional


def scan_secrets(repo_path: str) -> list:
    """
    Run detect-secrets against repo_path and return a list of findings.

    Returns a list of dicts: {"file": str, "line": int, "type": str}
    Returns [] if detect-secrets is not installed or no secrets found.
    """
    try:
        proc = subprocess.run(
            ["python", "-m", "detect_secrets", "scan", repo_path, "--all-files"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode not in (0, 1):
            # Non-zero but not 1 typically means an error
            return []

        raw = proc.stdout.strip()
        if not raw:
            return []

        data = json.loads(raw)
        results = data.get("results", {})

        findings = []
        for filepath, secrets in results.items():
            for secret in secrets:
                findings.append({
                    "file": filepath,
                    "line": secret.get("line_number", 0),
                    "type": secret.get("type", "Unknown"),
                })
        return findings

    except FileNotFoundError:
        # detect-secrets not installed
        return []
    except json.JSONDecodeError:
        return []
    except Exception:
        return []


def secret_to_html(findings: Optional[list]) -> str:
    """Render secret findings as an HTML table section."""
    if not findings:
        return ""

    rows = ""
    for f in findings:
        rows += (
            f"<tr>"
            f"<td><code>{f.get('file', '')}</code></td>"
            f"<td>{f.get('line', '')}</td>"
            f"<td>{f.get('type', '')}</td>"
            f"</tr>"
        )

    return f"""
<h2>Hardcoded Secrets ({len(findings)} found)</h2>
<table>
  <thead>
    <tr><th>File</th><th>Line</th><th>Secret Type</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>"""
