# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Compliance evidence packs (SOC 2 / ISO 27001).

Turns SecureScope's OWASP-mapped findings into an auditor-facing control matrix
for SOC 2 (Trust Services Criteria) and ISO/IEC 27001:2022 (Annex A). Each
in-scope control is reported as either "No exceptions noted" (no related
findings surfaced) or "Exception(s) noted" with the evidence (which OWASP
categories and how many findings drove it).

This is a technical-evidence aid derived from automated scanning — it supports,
but does not replace, a formal audit. Pure functions, no I/O.
"""

from html import escape as _esc

# OWASP 2021 category code -> mapped controls in each framework.
_OWASP_TO_CONTROLS = {
    "A01": {"soc2": ["CC6.1", "CC6.3"], "iso": ["A.8.3", "A.8.2"]},   # Broken Access Control
    "A02": {"soc2": ["CC6.1", "CC6.7"], "iso": ["A.8.24"]},           # Cryptographic Failures
    "A03": {"soc2": ["CC6.8", "CC7.1"], "iso": ["A.8.28"]},           # Injection
    "A04": {"soc2": ["CC8.1"], "iso": ["A.8.25", "A.8.27"]},          # Insecure Design
    "A05": {"soc2": ["CC6.1", "CC6.6"], "iso": ["A.8.9"]},            # Security Misconfiguration
    "A06": {"soc2": ["CC7.1"], "iso": ["A.8.8"]},                     # Vulnerable Components
    "A07": {"soc2": ["CC6.1"], "iso": ["A.8.5", "A.5.17"]},           # Identification & Auth Failures
    "A08": {"soc2": ["CC6.8", "CC8.1"], "iso": ["A.8.28"]},           # Software & Data Integrity
    "A09": {"soc2": ["CC7.2"], "iso": ["A.8.15", "A.8.16"]},          # Logging & Monitoring Failures
    "A10": {"soc2": ["CC6.6"], "iso": ["A.8.23"]},                    # SSRF
    "API1": {"soc2": ["CC6.1", "CC6.3"], "iso": ["A.8.3"]},           # Broken Object Level Auth
}

_SOC2_CATALOG = {
    "CC6.1": "Logical access security controls restrict access to information assets.",
    "CC6.3": "Access is granted based on roles and least privilege.",
    "CC6.6": "Boundary protection controls guard the system perimeter.",
    "CC6.7": "Data in transit is protected via encryption.",
    "CC6.8": "Controls prevent or detect unauthorized or malicious software/changes.",
    "CC7.1": "Vulnerabilities are detected and evaluated on an ongoing basis.",
    "CC7.2": "Security events are monitored, logged, and analysed.",
    "CC8.1": "Changes are authorized, designed, tested, and approved (change management).",
}

_ISO_CATALOG = {
    "A.5.17": "Authentication information.",
    "A.8.2": "Privileged access rights.",
    "A.8.3": "Information access restriction.",
    "A.8.5": "Secure authentication.",
    "A.8.8": "Management of technical vulnerabilities.",
    "A.8.9": "Configuration management.",
    "A.8.15": "Logging.",
    "A.8.16": "Monitoring activities.",
    "A.8.23": "Web filtering.",
    "A.8.24": "Use of cryptography.",
    "A.8.25": "Secure development life cycle.",
    "A.8.27": "Secure system architecture and engineering principles.",
    "A.8.28": "Secure coding.",
}

_FRAMEWORKS = {
    "soc2": ("SOC 2 (Trust Services Criteria)", _SOC2_CATALOG, "soc2"),
    "iso27001": ("ISO/IEC 27001:2022 (Annex A)", _ISO_CATALOG, "iso"),
}


def _owasp_code(category: str) -> str:
    """'A03:2021 - Injection' -> 'A03'; 'API1:2023 - ...' -> 'API1'."""
    return (category or "").split(":")[0].strip().upper()


def build_evidence_pack(posture, repo: str = "", generated_at: str = "") -> dict:
    """Build a SOC 2 + ISO 27001 control matrix from a CompliancePosture.

    `posture` may be a CompliancePosture or any object/dict exposing an `owasp`
    mapping of {category: [rule_ids]}. Returns a JSON-safe dict.
    """
    owasp = getattr(posture, "owasp", None)
    if owasp is None and isinstance(posture, dict):
        owasp = posture.get("owasp", {})
    owasp = owasp or {}

    # control -> {"owasp": set(categories), "findings": int}
    ctrl_ev = {"soc2": {}, "iso": {}}
    for category, rule_ids in owasp.items():
        code = _owasp_code(category)
        mapping = _OWASP_TO_CONTROLS.get(code)
        if not mapping:
            continue
        n = len(rule_ids or [])
        for fw_key, ctrls in (("soc2", mapping["soc2"]), ("iso", mapping["iso"])):
            for c in ctrls:
                ev = ctrl_ev[fw_key].setdefault(c, {"owasp": set(), "findings": 0})
                ev["owasp"].add(category)
                ev["findings"] += n

    frameworks = []
    for fw_key, (title, catalog, ev_key) in _FRAMEWORKS.items():
        controls = []
        for ctrl, desc in catalog.items():
            ev = ctrl_ev[ev_key].get(ctrl)
            if ev and ev["findings"] > 0:
                status = "Exception(s) noted"
                controls.append({
                    "control": ctrl, "description": desc, "status": status,
                    "findings": ev["findings"],
                    "evidence": sorted(ev["owasp"]),
                })
            else:
                controls.append({
                    "control": ctrl, "description": desc,
                    "status": "No exceptions noted", "findings": 0, "evidence": [],
                })
        exceptions = sum(1 for c in controls if c["findings"] > 0)
        frameworks.append({
            "key": fw_key, "title": title,
            "controls": controls,
            "total_controls": len(controls),
            "exception_controls": exceptions,
        })

    return {
        "repo": repo,
        "generated_at": generated_at,
        "frameworks": frameworks,
    }


def evidence_pack_to_html(pack: dict) -> str:
    """Render an evidence pack as a standalone, printable HTML document."""
    parts = [_HTML_HEAD.replace("{{REPO}}", _esc(pack.get("repo", "") or "repository"))
             .replace("{{WHEN}}", _esc(pack.get("generated_at", "") or ""))]
    for fw in pack.get("frameworks", []):
        rows = ""
        for c in fw["controls"]:
            ok = c["findings"] == 0
            badge = ("no-exc" if ok else "exc")
            label = c["status"]
            ev = ", ".join(_esc(e) for e in c["evidence"]) or "&mdash;"
            rows += (
                f'<tr><td class="mono">{_esc(c["control"])}</td>'
                f'<td>{_esc(c["description"])}</td>'
                f'<td><span class="badge {badge}">{_esc(label)}</span></td>'
                f'<td class="num">{c["findings"] or ""}</td>'
                f'<td>{ev}</td></tr>'
            )
        parts.append(
            f'<h2>{_esc(fw["title"])}</h2>'
            f'<p class="sub">{fw["exception_controls"]} of {fw["total_controls"]} '
            f'in-scope controls with exceptions.</p>'
            '<table><thead><tr><th>Control</th><th>Description</th>'
            '<th>Status</th><th class="num">Findings</th><th>Evidence (OWASP)</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>'
        )
    parts.append(_HTML_FOOT)
    return "".join(parts)


_HTML_HEAD = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compliance Evidence Pack — {{REPO}}</title>
<style>
  :root{color-scheme:light}
  body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:0 auto;padding:32px 20px;color:#111827;background:#fff}
  h1{font-size:24px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 4px;border-bottom:2px solid #e5e7eb;padding-bottom:6px}
  .eye{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#6b7280;font-weight:700}
  .meta{color:#6b7280;font-size:13px;margin-bottom:6px}
  .sub{color:#6b7280;font-size:13px;margin:0 0 10px}
  table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:8px}
  th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #eef0f3;vertical-align:top}
  th{background:#f9fafb;font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:#6b7280}
  td.num,th.num{text-align:center;width:70px} .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600;white-space:nowrap}
  .badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:5px}
  .badge.no-exc{background:#dcfce7;color:#166534} .badge.exc{background:#fee2e2;color:#991b1b}
  .disc{margin-top:26px;font-size:11px;color:#9ca3af;line-height:1.5;border-top:1px solid #e5e7eb;padding-top:12px}
</style></head><body>
<div class="eye">Compliance Evidence Pack</div>
<h1>{{REPO}}</h1>
<div class="meta">Generated {{WHEN}} · SecureScope automated control mapping</div>
"""

_HTML_FOOT = """<p class="disc">This evidence pack is generated from automated static analysis and maps
OWASP-classified findings to SOC 2 Trust Services Criteria and ISO/IEC 27001:2022 Annex A controls.
"No exceptions noted" means no related findings were surfaced by this scan; it is technical evidence that
supports — but does not constitute — a formal audit opinion.</p>
</body></html>"""
