"""
Multi-ecosystem dependency vulnerability scanner.
Supports: npm, cargo, go, bundler, maven.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional


def _run(cmd: list[str], cwd: str) -> Optional[str]:
    """Run a command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=120
        )
        return result.stdout
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _scan_npm(repo_path: str) -> list[dict]:
    out = _run(["npm", "audit", "--json"], repo_path)
    if out is None:
        return []
    try:
        data = json.loads(out)
        findings = []
        vulns = data.get("vulnerabilities", {})
        for pkg_name, vuln_data in vulns.items():
            severity = vuln_data.get("severity", "unknown").upper()
            via = vuln_data.get("via", [])
            for v in via:
                if isinstance(v, dict):
                    findings.append({
                        "ecosystem": "npm",
                        "package": pkg_name,
                        "version": vuln_data.get("range", "unknown"),
                        "vuln_id": v.get("url", "").split("/")[-1] or v.get("source", ""),
                        "severity": severity,
                        "description": v.get("title", v.get("name", "")),
                        "fix_version": vuln_data.get("fixAvailable", {}).get("version", "") if isinstance(vuln_data.get("fixAvailable"), dict) else "",
                    })
        return findings
    except (json.JSONDecodeError, Exception):
        return []


def _scan_cargo(repo_path: str) -> list[dict]:
    out = _run(["cargo", "audit", "--json"], repo_path)
    if out is None:
        return []
    try:
        data = json.loads(out)
        findings = []
        for vuln in data.get("vulnerabilities", {}).get("list", []):
            pkg = vuln.get("package", {})
            advisory = vuln.get("advisory", {})
            findings.append({
                "ecosystem": "cargo",
                "package": pkg.get("name", ""),
                "version": pkg.get("version", ""),
                "vuln_id": advisory.get("id", ""),
                "severity": advisory.get("cvss", {}).get("score", "UNKNOWN"),
                "description": advisory.get("title", ""),
                "fix_version": str(vuln.get("versions", {}).get("patched", [])),
            })
        return findings
    except (json.JSONDecodeError, Exception):
        return []


def _scan_go(repo_path: str) -> list[dict]:
    out = _run(["govulncheck", "-json", "./..."], repo_path)
    if out is None:
        return []
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            finding = obj.get("finding")
            if finding:
                osv = finding.get("osv", "")
                trace = finding.get("trace", [{}])
                frame = trace[0] if trace else {}
                findings.append({
                    "ecosystem": "go",
                    "package": frame.get("module", ""),
                    "version": frame.get("version", ""),
                    "vuln_id": osv,
                    "severity": "HIGH",
                    "description": finding.get("description", ""),
                    "fix_version": finding.get("fixed_version", ""),
                })
        except (json.JSONDecodeError, Exception):
            continue
    return findings


def _scan_bundler(repo_path: str) -> list[dict]:
    out = _run(["bundle", "audit", "check", "--format", "json"], repo_path)
    if out is None:
        return []
    try:
        data = json.loads(out)
        findings = []
        for vuln in data.get("results", []):
            gem = vuln.get("gem", {})
            advisory = vuln.get("advisory", {})
            findings.append({
                "ecosystem": "bundler",
                "package": gem.get("name", ""),
                "version": gem.get("version", ""),
                "vuln_id": advisory.get("id", ""),
                "severity": advisory.get("criticality", "UNKNOWN").upper(),
                "description": advisory.get("title", ""),
                "fix_version": advisory.get("patched_versions", [""])[0] if advisory.get("patched_versions") else "",
            })
        return findings
    except (json.JSONDecodeError, Exception):
        return []


def _scan_maven(repo_path: str) -> list[dict]:
    out = _run(
        ["mvn", "dependency-check:check", "-Dformat=JSON", "-q"],
        repo_path,
    )
    # Maven writes the report to target/dependency-check-report.json
    report_path = Path(repo_path) / "target" / "dependency-check-report.json"
    if not report_path.exists():
        return []
    try:
        data = json.loads(report_path.read_text())
        findings = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                findings.append({
                    "ecosystem": "maven",
                    "package": dep.get("fileName", ""),
                    "version": dep.get("version", ""),
                    "vuln_id": vuln.get("name", ""),
                    "severity": vuln.get("severity", "UNKNOWN").upper(),
                    "description": vuln.get("description", ""),
                    "fix_version": "",
                })
        return findings
    except (json.JSONDecodeError, Exception):
        return []


def scan_polyglot(repo_path: str) -> list[dict]:
    """
    Detect ecosystems in repo_path and run appropriate audit tools.
    Returns combined list of vulnerability dicts across all ecosystems.
    """
    p = Path(repo_path)
    all_findings: list[dict] = []

    if (p / "package.json").exists():
        findings = _scan_npm(repo_path)
        all_findings.extend(findings)

    if (p / "Cargo.toml").exists():
        findings = _scan_cargo(repo_path)
        all_findings.extend(findings)

    if (p / "go.mod").exists():
        findings = _scan_go(repo_path)
        all_findings.extend(findings)

    if (p / "Gemfile").exists():
        findings = _scan_bundler(repo_path)
        all_findings.extend(findings)

    if (p / "pom.xml").exists() or (p / "build.gradle").exists():
        findings = _scan_maven(repo_path)
        all_findings.extend(findings)

    return all_findings


_SEV_COLOR = {
    "CRITICAL": "#b71c1c",
    "HIGH": "#d32f2f",
    "MEDIUM": "#f57c00",
    "LOW": "#388e3c",
    "UNKNOWN": "#757575",
}


def polyglot_to_html(findings: list[dict]) -> str:
    """Render polyglot findings as an HTML table section."""
    if not findings:
        return ""
    rows = ""
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        color = _SEV_COLOR.get(sev, "#555")
        rows += (
            f"<tr>"
            f"<td>{f.get('ecosystem','')}</td>"
            f"<td><code>{f.get('package','')}</code></td>"
            f"<td>{f.get('version','')}</td>"
            f"<td><code>{f.get('vuln_id','')}</code></td>"
            f"<td><span style='color:{color};font-weight:bold'>{sev}</span></td>"
            f"<td>{f.get('description','')[:120]}</td>"
            f"<td>{f.get('fix_version','') or '—'}</td>"
            f"</tr>"
        )
    return f"""
<h2>Polyglot Dependency Scan</h2>
<table>
  <thead>
    <tr><th>Ecosystem</th><th>Package</th><th>Version</th><th>Vuln ID</th>
    <th>Severity</th><th>Description</th><th>Fix Version</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>"""
