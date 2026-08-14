# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Attack-path / exploit-chain synthesis.

Individual findings are dots; attackers connect them. This module stitches the
signals SecureScope already collects — reachable dependency CVEs (with CISA KEV
+ EPSS), injection-class SAST findings, and exposed secrets — into a small set
of narrated, staged kill-chains (Entry -> Execution -> Impact).

It is deliberately heuristic and evidence-grounded: every stage cites a real
finding. Chains are ranked by severity and likelihood, and a combined
"full kill-chain" is emitted only when independent signals genuinely compose
(e.g. a reachable RCE dependency *and* a leaked credential).

Pure functions, no I/O — safe to unit test and reuse for both the HTML report
and the PDF.
"""

from typing import Optional

# CWE ids that represent an attacker-controllable execution/injection sink.
_INJECTION_CWES = {
    "89": "SQL injection", "79": "Cross-site scripting", "78": "OS command injection",
    "77": "Command injection", "94": "Code injection", "95": "Eval injection",
    "502": "Insecure deserialization", "918": "Server-side request forgery",
    "22": "Path traversal", "611": "XML external entity (XXE)", "917": "Expression-language injection",
    "98": "Remote file inclusion", "90": "LDAP injection", "643": "XPath injection",
}
_INJECTION_KEYWORDS = (
    "sql injection", "command injection", "code injection", "deserial",
    "ssrf", "path traversal", "xxe", "xss", "cross-site scripting",
    "remote code", "rce", "eval(", "template injection",
)

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_LIKELIHOOD_RANK = {"High": 3, "Medium": 2, "Low": 1}


def _cwe_num(cwe) -> str:
    if not cwe:
        return ""
    s = str(cwe).upper().replace("CWE-", "").strip()
    return s if s.isdigit() else ""


def _is_injection(f: dict) -> Optional[str]:
    """Return a human injection label if this SAST finding is an execution sink."""
    num = _cwe_num(f.get("cwe"))
    if num in _INJECTION_CWES:
        return _INJECTION_CWES[num]
    hay = f"{f.get('rule_id','')} {f.get('message','')}".lower()
    for kw in _INJECTION_KEYWORDS:
        if kw in hay:
            return "Injection / code execution"
    return None


def _epss_pct(v: dict) -> int:
    try:
        return round(float(v.get("epss") or 0.0) * 100)
    except (TypeError, ValueError):
        return 0


def _secret_list(secrets) -> list:
    if not secrets:
        return []
    if isinstance(secrets, list):
        return secrets
    if isinstance(secrets, dict):
        return secrets.get("findings") or secrets.get("secrets") or []
    return []


def build_attack_paths(deps=None, secrets=None, findings=None) -> list:
    """Return a ranked list of attack-chain dicts.

    Each chain:
        {id, title, severity, likelihood, summary,
         steps: [{stage, title, detail, evidence}]}
    """
    deps = deps or {}
    vulns = deps.get("vulnerabilities") or []
    secret_list = _secret_list(secrets)
    findings = findings or []
    chains: list[dict] = []

    # ── A. Reachable / known-exploited dependency CVE -> code execution ──────
    exec_dep = None  # remember the strongest for the combined chain
    for v in vulns:
        reachable = v.get("reachable")
        kev = bool(v.get("kev"))
        epss = _epss_pct(v)
        sev = str(v.get("severity", "")).upper()
        # Entry-worthy only if there's a real exploit signal.
        if not (kev or reachable is True or epss >= 50):
            continue
        if sev not in ("CRITICAL", "HIGH") and not kev:
            continue
        cve = v.get("primary_cve") or v.get("vuln_id") or "the CVE"
        pkg = v.get("package_name", "a dependency")
        rf = v.get("reachable_files") or 0
        likelihood = "High" if (kev or epss >= 70) else "Medium"
        reach_txt = (f"imported in {rf} first-party file{'s' if rf != 1 else ''}"
                     if reachable is True else "declared as a dependency")
        exploit_bits = []
        if kev:
            exploit_bits.append("listed in CISA KEV (exploited in the wild)")
        if epss:
            exploit_bits.append(f"EPSS {epss}% exploit probability")
        exploit_txt = "; ".join(exploit_bits) or f"{sev} severity"
        chain = {
            "id": f"dep-{pkg}-{cve}",
            "title": f"Exploitable dependency: {pkg} ({cve})",
            "severity": sev if sev in _SEV_RANK else ("HIGH" if kev else "MEDIUM"),
            "likelihood": likelihood,
            "summary": f"{cve} in {pkg} is {reach_txt} and {exploit_txt} — a directly exploitable entry point.",
            "steps": [
                {"stage": "Entry", "title": "Vulnerable package in the call path",
                 "detail": f"{pkg} carries {cve}; the vulnerable code is {reach_txt}.",
                 "evidence": f"{pkg} · {cve}"},
                {"stage": "Execution", "title": "Weaponise a known exploit",
                 "detail": f"An attacker triggers {cve} against the reachable code path ({exploit_txt}).",
                 "evidence": exploit_txt},
                {"stage": "Impact", "title": f"{sev or 'HIGH'} compromise",
                 "detail": "Depending on the flaw class this yields remote code execution, data disclosure, or denial of service on the host.",
                 "evidence": f"severity {sev or 'HIGH'}"},
            ],
        }
        chains.append(chain)
        if exec_dep is None:
            exec_dep = v

    # ── B. Untrusted input -> injection sink (SAST) ─────────────────────────
    inj_finding = None
    for f in findings:
        label = _is_injection(f)
        if not label:
            continue
        sev = str(f.get("severity", "")).upper()
        if sev not in ("CRITICAL", "HIGH", "ERROR"):
            continue
        sev_norm = "CRITICAL" if sev in ("CRITICAL", "ERROR") else "HIGH"
        loc = f.get("file", "source")
        line = f.get("line_start") or f.get("line") or 0
        where = f"{loc}:{line}" if line else loc
        chains.append({
            "id": f"inj-{where}",
            "title": f"{label} via untrusted input",
            "severity": sev_norm,
            "likelihood": "Medium",
            "summary": f"A {label.lower()} sink at {where} lets attacker-controlled input change program behaviour.",
            "steps": [
                {"stage": "Entry", "title": "Attacker-controlled input",
                 "detail": "A request parameter, header, or uploaded content reaches the vulnerable sink without sufficient validation.",
                 "evidence": where},
                {"stage": "Execution", "title": label,
                 "detail": f"The tainted value is used unsafely, enabling {label.lower()}.",
                 "evidence": f.get("rule_id", label)},
                {"stage": "Impact", "title": "Data or system compromise",
                 "detail": "Successful injection can read/modify data, move laterally, or execute code.",
                 "evidence": f.get("cwe") or label},
            ],
        })
        if inj_finding is None:
            inj_finding = f

    # ── C. Exposed secret -> credential compromise ──────────────────────────
    secret0 = None
    for s in secret_list:
        typ = s.get("type", "credential")
        file = s.get("file", "the codebase")
        line = s.get("line", 0)
        where = f"{file}:{line}" if line else file
        chains.append({
            "id": f"secret-{where}",
            "title": f"Leaked {typ} enables account takeover",
            "severity": "HIGH",
            "likelihood": "High",
            "summary": f"A {typ} committed at {where} can be replayed to authenticate as the application.",
            "steps": [
                {"stage": "Entry", "title": "Harvest the committed secret",
                 "detail": f"A {typ} is present in source at {where} (and in git history unless rotated).",
                 "evidence": where},
                {"stage": "Execution", "title": "Authenticate with the leaked credential",
                 "detail": f"The attacker uses the {typ} to access the associated service or cloud account.",
                 "evidence": typ},
                {"stage": "Impact", "title": "Privileged access / data exfiltration",
                 "detail": "Valid credentials often grant broad, logged-as-legitimate access to data and infrastructure.",
                 "evidence": "credential compromise"},
            ],
        })
        if secret0 is None:
            secret0 = s

    # ── D. Combined full kill-chain (only when signals genuinely compose) ────
    foothold = None
    if exec_dep is not None:
        foothold = ("a reachable CVE in "
                    f"{exec_dep.get('package_name','a dependency')} "
                    f"({exec_dep.get('primary_cve') or exec_dep.get('vuln_id') or 'CVE'})")
    elif inj_finding is not None:
        foothold = f"an injection sink at {inj_finding.get('file','source')}"
    if foothold and secret0 is not None:
        styp = secret0.get("type", "credential")
        chains.append({
            "id": "combined-kill-chain",
            "title": "Full kill-chain: foothold → credential → data breach",
            "severity": "CRITICAL",
            "likelihood": "High",
            "summary": f"An attacker chains {foothold} with a leaked {styp} to escalate from initial access to data exfiltration.",
            "steps": [
                {"stage": "Entry", "title": "Initial access",
                 "detail": f"Gain code execution or a foothold via {foothold}.",
                 "evidence": "reachable exploit"},
                {"stage": "Execution", "title": "Harvest in-repo credentials",
                 "detail": f"From the foothold, read the committed {styp} and authenticate to connected services.",
                 "evidence": styp},
                {"stage": "Impact", "title": "Data breach",
                 "detail": "Legitimate-looking credentials enable exfiltration of data and lateral movement across infrastructure.",
                 "evidence": "critical impact"},
            ],
        })

    # Rank: severity, then likelihood; combined chain floats near the top by both.
    chains.sort(key=lambda c: (
        _SEV_RANK.get(str(c.get("severity", "")).upper(), 0),
        _LIKELIHOOD_RANK.get(c.get("likelihood", "Low"), 1),
    ), reverse=True)
    return chains[:8]
