"""
Dynamic Application Security Testing (DAST) module.
Supports Nuclei (preferred) and OWASP ZAP (via Docker).
"""

import json
import os
import shutil
import subprocess
import tempfile
from typing import Optional


def scan_with_nuclei(target_url: str, timeout: int = 120) -> list[dict]:
    """
    Run Nuclei against target_url and return parsed findings.

    Requires nuclei to be installed and on PATH.
    Falls back gracefully (returns empty list) if not available.

    Each finding dict:
        {
          "template_id": str,
          "name": str,
          "severity": str,      # critical / high / medium / low / info
          "url": str,
          "matched_at": str,
          "description": str,
        }
    """
    if not shutil.which("nuclei"):
        print("[dast] nuclei not found — skipping Nuclei scan")
        return []

    try:
        proc = subprocess.run(
            [
                "nuclei",
                "-u", target_url,
                "-json",
                "-severity", "critical,high,medium",
                "-silent",
            ],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print("[dast] Nuclei scan timed out")
        return []
    except Exception as exc:
        print(f"[dast] Nuclei error: {exc}")
        return []

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "template_id": entry.get("template-id", ""),
            "name": entry.get("info", {}).get("name", entry.get("template-id", "")),
            "severity": entry.get("info", {}).get("severity", "info"),
            "url": entry.get("host", target_url),
            "matched_at": entry.get("matched-at", ""),
            "description": entry.get("info", {}).get("description", ""),
        })

    return findings


def scan_with_zap(target_url: str, timeout: int = 180) -> list[dict]:
    """
    Run OWASP ZAP baseline scan via Docker and return parsed findings.

    Requires Docker to be installed and running.
    Falls back gracefully (returns empty list) if not available.

    Each finding dict matches the Nuclei format for easy merging.
    """
    if not shutil.which("docker"):
        print("[dast] docker not found — skipping ZAP scan")
        return []

    tmp_dir = tempfile.mkdtemp(prefix="secscope_zap_")
    report_path = os.path.join(tmp_dir, "zap_report.json")

    try:
        proc = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{tmp_dir}:/zap/wrk:rw",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
                "-t", target_url,
                "-J", "zap_report.json",
            ],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print("[dast] ZAP scan timed out")
        return []
    except Exception as exc:
        print(f"[dast] ZAP Docker error: {exc}")
        return []
    finally:
        pass  # clean up below

    findings = []
    if os.path.exists(report_path):
        try:
            with open(report_path) as fh:
                data = json.load(fh)
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    sev_map = {"3": "high", "2": "medium", "1": "low", "0": "info"}
                    risk = str(alert.get("riskcode", "0"))
                    findings.append({
                        "template_id": f"zap-{alert.get('pluginid', 'unknown')}",
                        "name": alert.get("alert", ""),
                        "severity": sev_map.get(risk, "info"),
                        "url": target_url,
                        "matched_at": alert.get("instances", [{}])[0].get("uri", ""),
                        "description": alert.get("desc", ""),
                    })
        except Exception as exc:
            print(f"[dast] ZAP report parse error: {exc}")

    import shutil as _sh
    _sh.rmtree(tmp_dir, ignore_errors=True)
    return findings


def dast_to_html(findings: list[dict]) -> str:
    """Render DAST findings as an HTML section."""
    if not findings:
        return ""

    sev_color = {
        "critical": "#b71c1c",
        "high": "#d32f2f",
        "medium": "#f57c00",
        "low": "#388e3c",
        "info": "#1976d2",
    }

    rows = ""
    for f in findings:
        sev = f.get("severity", "info")
        color = sev_color.get(sev, "#555")
        rows += (
            f"<tr>"
            f"<td><span style='color:{color};font-weight:bold'>{sev.upper()}</span></td>"
            f"<td><code style='font-size:11px'>{f.get('template_id','')}</code></td>"
            f"<td>{f.get('name','')}</td>"
            f"<td style='font-size:11px'>{f.get('matched_at','') or f.get('url','')}</td>"
            f"<td style='font-size:12px;max-width:300px'>{f.get('description','')[:120]}</td>"
            f"</tr>"
        )

    return f"""
<div class="sec" id="dast">
  <h2>DAST Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Template</th><th>Name</th><th>Matched At</th><th>Description</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
