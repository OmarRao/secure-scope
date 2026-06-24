"""
Report generator: produces a structured HTML and JSON security report.
"""

import json
from datetime import datetime
from pathlib import Path
from analyzer import AnalysisResult
from sandbox import RuntimeObservation


SEVERITY_COLOR = {
    "ERROR": "#d32f2f",
    "WARNING": "#f57c00",
    "INFO": "#1976d2",
}


def to_json(result: AnalysisResult, obs: Optional["RuntimeObservation"] = None,
            enriched: Optional[list] = None, path: str = "report.json") -> str:
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "repo": result.repo_url,
        "summary": result.summary(),
        "findings": enriched or [f.to_dict() for f in result.findings],
        "dependency_vulns": result.dependency_vulns,
        "runtime": {
            "suspicious_behaviors": obs.suspicious_behaviors if obs else [],
            "outbound_connections": obs.outbound_connections if obs else [],
            "exit_code": obs.exit_code if obs else None,
        } if obs else None,
    }
    Path(path).write_text(json.dumps(data, indent=2))
    print(f"[+] JSON report: {path}")
    return path


def to_html(result: AnalysisResult, obs: Optional["RuntimeObservation"] = None,
            enriched: Optional[list] = None, path: str = "report.html",
            compliance_html: str = "", container_vulns: Optional[list] = None,
            scorecard_data: Optional[dict] = None,
            dast_findings: Optional[list] = None,
            license_results: Optional[list] = None,
            supply_chain_findings: Optional[list] = None,
            trend_records: Optional[list] = None,
            suppressed_findings: Optional[list] = None) -> str:
    findings = enriched or [f.to_dict() for f in result.findings]
    summary = result.summary()

    rows = ""
    for f in findings:
        color = SEVERITY_COLOR.get(f.get("severity", "INFO"), "#555")
        advice_html = ""
        if f.get("fix_suggestion"):
            # Convert markdown to simple HTML
            advice_md = f["fix_suggestion"].replace("<", "&lt;").replace(">", "&gt;")
            advice_html = f'<details><summary>View Fix Advisory</summary><pre style="background:#f5f5f5;padding:12px;overflow:auto">{advice_md}</pre></details>'
        rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:bold">{f.get('severity','')}</span></td>
          <td><code>{f.get('rule_id','')}</code></td>
          <td>{f.get('file','')}:{f.get('line_start','')}</td>
          <td>{f.get('cwe') or '—'}</td>
          <td>{f.get('attack_technique') or '—'}</td>
          <td>{f.get('attack_tactic') or '—'}</td>
          <td style="max-width:300px">{f.get('message','')[:120]}</td>
          <td>{advice_html}</td>
        </tr>"""

    dep_rows = ""
    for v in result.dependency_vulns:
        dep_rows += f"""
        <tr>
          <td>{v.get('ecosystem','')}</td>
          <td><code>{v.get('package','')}</code></td>
          <td>{v.get('version','')}</td>
          <td>{v.get('vuln_id','')}</td>
          <td>{v.get('description','')[:120]}</td>
          <td>{', '.join(v.get('fix_versions', [])) or v.get('fix_available','')}</td>
        </tr>"""

    runtime_section = ""
    if obs and (obs.suspicious_behaviors or obs.outbound_connections):
        behaviors = "".join(f"<li>{b}</li>" for b in obs.suspicious_behaviors)
        conns = "".join(f"<li>{c['host']}:{c['port']}</li>" for c in obs.outbound_connections)
        runtime_section = f"""
        <h2>Runtime Analysis</h2>
        <h3>Suspicious Behaviors</h3><ul>{behaviors}</ul>
        <h3>Outbound Connections</h3><ul>{conns}</ul>"""

    # Container vulnerabilities (Trivy)
    container_section = ""
    if container_vulns:
        sev_color = {"CRITICAL": "#b71c1c", "HIGH": "#d32f2f", "MEDIUM": "#f57c00",
                     "LOW": "#388e3c", "UNKNOWN": "#757575"}
        cv_list = container_vulns if isinstance(container_vulns[0], dict) else [cv.to_dict() for cv in container_vulns]
        trivy_rows = ""
        for v in cv_list:
            sev = v.get("severity", "UNKNOWN")
            color = sev_color.get(sev, "#555")
            trivy_rows += (
                f"<tr><td><span style='color:{color};font-weight:bold'>{sev}</span></td>"
                f"<td>{v.get('target', '')}</td><td>{v.get('package', '')}</td>"
                f"<td>{v.get('version', '')}</td><td><code>{v.get('vuln_id', '')}</code></td>"
                f"<td>{v.get('title', '')[:80]}</td>"
                f"<td>{v.get('fixed_version', '') or '—'}</td></tr>"
            )
        container_section = f"""
        <h2>Container / Trivy Scan</h2>
        <table>
          <thead><tr><th>Severity</th><th>Target</th><th>Package</th><th>Version</th>
          <th>CVE/ID</th><th>Title</th><th>Fixed In</th></tr></thead>
          <tbody>{trivy_rows}</tbody>
        </table>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Review — {result.repo_url}</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; margin: 32px; color: #222; }}
    h1 {{ color: #b71c1c; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 32px; font-size: 13px; }}
    th {{ background: #333; color: #fff; padding: 8px 12px; text-align: left; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
    tr:hover {{ background: #fafafa; }}
    code {{ background: #f0f0f0; padding: 2px 4px; border-radius: 3px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; }}
    summary {{ cursor: pointer; color: #1565c0; }}
  </style>
</head>
<body>
  <h1>Security Review Report</h1>
  <p><strong>Repository:</strong> <a href="{result.repo_url}">{result.repo_url}</a></p>
  <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>

  <h2>Summary</h2>
  <ul>
    <li>Total findings: <strong>{summary['total_findings']}</strong></li>
    {''.join(f"<li>{k}: <strong>{v}</strong></li>" for k,v in summary['by_severity'].items())}
    <li>Dependency CVEs: <strong>{summary['dependency_vulns']}</strong></li>
  </ul>

  <h2>Static Analysis Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Rule</th><th>Location</th><th>CWE</th><th>ATT&CK</th><th>Tactic</th><th>Message</th><th>Fix</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>

  <h2>Dependency Vulnerabilities (CVE)</h2>
  <table>
    <thead>
      <tr><th>Ecosystem</th><th>Package</th><th>Version</th><th>CVE/ID</th><th>Description</th><th>Fix</th></tr>
    </thead>
    <tbody>{dep_rows}</tbody>
  </table>

  {runtime_section}
  {container_section}
  {compliance_html}
  {_scorecard_section(scorecard_data)}
  {_dast_section(dast_findings)}
  {_license_section(license_results)}
  {_supply_chain_section(supply_chain_findings)}
  {_trend_section(trend_records)}
  {_suppressed_section(suppressed_findings)}
</body>
</html>"""

    Path(path).write_text(html)
    print(f"[+] HTML report: {path}")
    return path


def _scorecard_section(scorecard_data: Optional[dict]) -> str:
    if not scorecard_data:
        return ""
    try:
        from scorecard import scorecard_to_html
        return scorecard_to_html(scorecard_data)
    except ImportError:
        return ""


def _dast_section(dast_findings: Optional[list]) -> str:
    if not dast_findings:
        return ""
    try:
        from dast import dast_to_html
        return dast_to_html(dast_findings)
    except ImportError:
        return ""


def _license_section(license_results: Optional[list]) -> str:
    if not license_results:
        return ""
    try:
        from license_scanner import license_to_html
        return license_to_html(license_results)
    except ImportError:
        return ""


def _supply_chain_section(supply_chain_findings: Optional[list]) -> str:
    if supply_chain_findings is None:
        return ""
    try:
        from supply_chain import supply_chain_to_html
        return supply_chain_to_html(supply_chain_findings)
    except ImportError:
        return ""


def _trend_section(trend_records: Optional[list]) -> str:
    if not trend_records:
        return ""
    try:
        from trend import trend_to_html
        return trend_to_html(trend_records)
    except ImportError:
        return ""


def _suppressed_section(suppressed_findings: Optional[list]) -> str:
    if not suppressed_findings:
        return ""
    rows = ""
    for f in suppressed_findings:
        sup = f.get("_suppression", {})
        rows += (
            f"<tr>"
            f"<td><code>{f.get('rule_id','')}</code></td>"
            f"<td>{f.get('file','')}:{f.get('line_start','')}</td>"
            f"<td>{sup.get('reason','')}</td>"
            f"<td>{sup.get('suppressed_by','')}</td>"
            f"<td>{sup.get('suppressed_at','')[:10]}</td>"
            f"</tr>"
        )
    return f"""
<h2>Suppressed Findings (False Positives)</h2>
<table>
  <thead><tr><th>Rule</th><th>Location</th><th>Reason</th><th>By</th><th>Date</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


try:
    from typing import Optional
except ImportError:
    pass
