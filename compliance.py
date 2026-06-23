"""
Compliance posture report: maps SecureScope findings to PCI DSS v4.0, NIST SP 800-53 Rev 5,
OWASP Top 10, and SANS/CWE Top 25 controls.
"""

from typing import Optional
from dataclasses import dataclass, field


# CWE -> compliance control mapping
CWE_COMPLIANCE: dict[str, dict] = {
    "CWE-89": {
        "pci": ["Req 6.2.4 (prevent SQL injection)"],
        "nist": ["SI-10 (Information Input Validation)"],
        "owasp": ["A03:2021 - Injection"],
        "sans_rank": 3,
    },
    "CWE-79": {
        "pci": ["Req 6.2.4 (prevent XSS)"],
        "nist": ["SI-10 (Information Input Validation)"],
        "owasp": ["A03:2021 - Injection"],
        "sans_rank": 2,
    },
    "CWE-78": {
        "pci": ["Req 6.2.4 (prevent OS command injection)"],
        "nist": ["SI-10 (Information Input Validation)", "SI-3 (Malicious Code Protection)"],
        "owasp": ["A03:2021 - Injection"],
        "sans_rank": 5,
    },
    "CWE-22": {
        "pci": ["Req 6.2.4 (prevent path traversal)"],
        "nist": ["AC-3 (Access Enforcement)", "SI-10 (Input Validation)"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "sans_rank": 8,
    },
    "CWE-798": {
        "pci": ["Req 8.6.1 (no hardcoded credentials)", "Req 8.6.3 (credentials protected)"],
        "nist": ["IA-5 (Authenticator Management)", "SA-15 (Development Process)"],
        "owasp": ["A07:2021 - Identification and Auth Failures"],
        "sans_rank": 18,
    },
    "CWE-330": {
        "pci": ["Req 8.3.6 (strong auth tokens required)"],
        "nist": ["IA-5 (Authenticator Management)", "SC-13 (Cryptographic Protection)"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "sans_rank": None,
    },
    "CWE-502": {
        "pci": ["Req 6.2.4 (prevent deserialization attacks)", "Req 6.3.2 (inventory of bespoke software)"],
        "nist": ["SI-3 (Malicious Code Protection)", "SI-10 (Input Validation)"],
        "owasp": ["A08:2021 - Software and Data Integrity Failures"],
        "sans_rank": None,
    },
    "CWE-611": {
        "pci": ["Req 6.2.4 (prevent XXE)"],
        "nist": ["SI-10 (Information Input Validation)"],
        "owasp": ["A05:2021 - Security Misconfiguration"],
        "sans_rank": 23,
    },
    "CWE-918": {
        "pci": ["Req 6.2.4 (prevent SSRF)", "Req 1.3 (network access controls)"],
        "nist": ["AC-4 (Information Flow Enforcement)", "SC-7 (Boundary Protection)"],
        "owasp": ["A10:2021 - Server-Side Request Forgery"],
        "sans_rank": 19,
    },
    "CWE-601": {
        "pci": ["Req 6.2.4 (prevent open redirect)"],
        "nist": ["SI-10 (Input Validation)"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "sans_rank": None,
    },
    "CWE-312": {
        "pci": ["Req 3.3.1 (SAD not retained)", "Req 3.4 (PAN rendered unreadable)"],
        "nist": ["SC-28 (Protection of Information at Rest)"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "sans_rank": None,
    },
    "CWE-327": {
        "pci": ["Req 4.2.1 (strong cryptography)", "Req 8.3.6 (strong hashing)"],
        "nist": ["SC-13 (Cryptographic Protection)", "IA-5(1) (Password Hashing)"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "sans_rank": None,
    },
    "CWE-352": {
        "pci": ["Req 6.2.4 (prevent CSRF)"],
        "nist": ["SC-8 (Transmission Confidentiality and Integrity)"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "sans_rank": 9,
    },
    "CWE-434": {
        "pci": ["Req 6.2.4 (prevent unrestricted file upload)"],
        "nist": ["SI-3 (Malicious Code Protection)", "AC-3 (Access Enforcement)"],
        "owasp": ["A04:2021 - Insecure Design"],
        "sans_rank": 16,
    },
    "CWE-285": {
        "pci": ["Req 7.2 (access control systems)", "Req 7.3 (access control enforcement)"],
        "nist": ["AC-3 (Access Enforcement)", "AC-6 (Least Privilege)"],
        "owasp": ["A01:2021 - Broken Access Control", "API1:2023 - Broken Object Level Auth"],
        "sans_rank": None,
    },
    "CWE-532": {
        "pci": ["Req 10.3.3 (log files protected)", "Req 3.3.1 (SAD not in logs)"],
        "nist": ["AU-3 (Content of Audit Records)", "AU-9 (Protection of Audit Information)"],
        "owasp": ["A09:2021 - Security Logging and Monitoring Failures"],
        "sans_rank": None,
    },
    "CWE-916": {
        "pci": ["Req 8.3.6 (strong password hashing)"],
        "nist": ["IA-5(1) (Password-Based Authentication)"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "sans_rank": None,
    },
}


@dataclass
class CompliancePosture:
    pci_dss: dict = field(default_factory=dict)    # requirement -> [findings]
    nist: dict = field(default_factory=dict)        # control -> [findings]
    owasp: dict = field(default_factory=dict)       # category -> [findings]
    sans_top25_hit: list = field(default_factory=list)   # (rank, cwe, count)
    coverage_pct: float = 0.0
    total_findings: int = 0
    mapped_findings: int = 0


def build_compliance_posture(findings: list) -> CompliancePosture:
    """
    Map a list of finding dicts (each with a 'cwe' key) to compliance controls.
    Returns a CompliancePosture with bucketed findings per control.
    """
    posture = CompliancePosture()
    posture.total_findings = len(findings)

    sans_counts: dict[str, dict] = {}  # cwe -> {rank, count, rule_ids}

    for f in findings:
        cwe = f.get("cwe")
        if not cwe:
            continue
        mapping = CWE_COMPLIANCE.get(cwe)
        if not mapping:
            continue

        posture.mapped_findings += 1
        rule_id = f.get("rule_id", "unknown")

        for req in mapping.get("pci", []):
            posture.pci_dss.setdefault(req, []).append(rule_id)

        for ctl in mapping.get("nist", []):
            posture.nist.setdefault(ctl, []).append(rule_id)

        for cat in mapping.get("owasp", []):
            posture.owasp.setdefault(cat, []).append(rule_id)

        rank = mapping.get("sans_rank")
        if rank:
            entry = sans_counts.setdefault(cwe, {"rank": rank, "count": 0, "rule_ids": []})
            entry["count"] += 1
            entry["rule_ids"].append(rule_id)

    posture.sans_top25_hit = sorted(
        [{"cwe": cwe, "rank": v["rank"], "count": v["count"]} for cwe, v in sans_counts.items()],
        key=lambda x: x["rank"],
    )

    if posture.total_findings > 0:
        posture.coverage_pct = round(posture.mapped_findings / posture.total_findings * 100, 1)

    return posture


def posture_to_html(posture: CompliancePosture) -> str:
    """Render the CompliancePosture as an HTML section for embedding in the full report."""

    def table_rows(mapping: dict) -> str:
        rows = ""
        for key, rule_ids in sorted(mapping.items()):
            count = len(rule_ids)
            badge_color = "#d32f2f" if count >= 5 else "#f57c00" if count >= 2 else "#388e3c"
            rows += (
                f"<tr><td>{key}</td>"
                f"<td><span style='background:{badge_color};color:#fff;padding:2px 8px;"
                f"border-radius:10px;font-size:12px'>{count} finding{'s' if count != 1 else ''}</span></td>"
                f"<td><code style='font-size:11px'>{', '.join(set(rule_ids[:5]))}"
                f"{'…' if len(rule_ids) > 5 else ''}</code></td></tr>"
            )
        return rows or "<tr><td colspan='3'>No findings mapped to this framework</td></tr>"

    sans_rows = ""
    for entry in posture.sans_top25_hit:
        sans_rows += (
            f"<tr><td>#{entry['rank']}</td><td>{entry['cwe']}</td>"
            f"<td>{entry['count']}</td></tr>"
        )
    if not sans_rows:
        sans_rows = "<tr><td colspan='3'>No SANS Top 25 CWEs detected</td></tr>"

    coverage_color = (
        "#d32f2f" if posture.coverage_pct >= 60 else
        "#f57c00" if posture.coverage_pct >= 30 else "#388e3c"
    )

    return f"""
<div class="sec" id="compliance">
  <h2>Compliance Posture</h2>
  <p>
    <strong>{posture.mapped_findings}</strong> of <strong>{posture.total_findings}</strong> findings
    mapped to compliance frameworks
    (<span style="color:{coverage_color};font-weight:bold">{posture.coverage_pct}%</span> coverage).
  </p>

  <h3>PCI DSS v4.0</h3>
  <table>
    <thead><tr><th>Requirement</th><th>Findings</th><th>Rule IDs</th></tr></thead>
    <tbody>{table_rows(posture.pci_dss)}</tbody>
  </table>

  <h3>NIST SP 800-53 Rev 5</h3>
  <table>
    <thead><tr><th>Control</th><th>Findings</th><th>Rule IDs</th></tr></thead>
    <tbody>{table_rows(posture.nist)}</tbody>
  </table>

  <h3>OWASP Top 10 / API Security</h3>
  <table>
    <thead><tr><th>Category</th><th>Findings</th><th>Rule IDs</th></tr></thead>
    <tbody>{table_rows(posture.owasp)}</tbody>
  </table>

  <h3>SANS / CWE Top 25 (2023) Hits</h3>
  <table>
    <thead><tr><th>Rank</th><th>CWE</th><th>Finding Count</th></tr></thead>
    <tbody>{sans_rows}</tbody>
  </table>
</div>"""
