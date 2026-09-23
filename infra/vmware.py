# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
VMware vSphere / ESXi hardening assessor.

Pure, read-only posture checks over a normalized host *snapshot* dict (produced
by infra.connectors.vmware from the vSphere API, or supplied as a fixture).
Checks are inspired by the CIS VMware ESXi Benchmark and common ransomware-era
hardening guidance. No live calls happen here — this module never touches a host.

Snapshot shape (all keys optional; missing → UNKNOWN, never a crash):
    {
      "kind": "vmware_esxi",
      "host": "esxi01.example.com",
      "version": "7.0.3", "build": "20842708",
      "lockdown_mode": "disabled" | "normal" | "strict",
      "ssh_enabled": bool, "shell_enabled": bool, "mob_enabled": bool,
      "ntp_configured": bool, "syslog_configured": bool,
      "tls_min": "1.0" | "1.1" | "1.2" | "1.3",
      "outdated": bool,                 # optional: build behind latest patch
      "known_cves": [ {"id","kev","epss"} ],   # optional: CVEs for this build
    }
"""

from .base import Assessor, Finding, register

_CIS = "CIS-ESXi"


def _b(snap, key):
    """Tri-state read: True/False if present, None if unknown."""
    v = snap.get(key)
    return v if isinstance(v, bool) else None


def _finding(control, title, severity, status, host, detail, remediation, cis, nist=None):
    fw = {"CIS": cis}
    if nist:
        fw["NIST"] = nist
    return Finding(assessor="vmware.esxi", control=control, title=title,
                   severity=severity, status=status, resource=host,
                   detail=detail, remediation=remediation, frameworks=fw)


class VMwareEsxiAssessor(Assessor):
    id = "vmware.esxi"
    domain = "hypervisor"
    kinds = ("vmware_esxi", "vmware_vcenter")

    def assess(self, snapshot: dict) -> list:
        snap = snapshot or {}
        host = snap.get("host", "esxi-host")
        out = []

        # 1. Lockdown mode — restricts direct host access; a key ESXi control.
        lm = (snap.get("lockdown_mode") or "").lower() if snap.get("lockdown_mode") is not None else None
        if lm is None:
            out.append(_finding(f"{_CIS}-1", "Lockdown mode", "HIGH", "UNKNOWN", host,
                                "Lockdown mode state not reported.", "", "6.1"))
        elif lm in ("normal", "strict"):
            out.append(_finding(f"{_CIS}-1", "Lockdown mode enabled", "HIGH", "PASS", host,
                                f"Lockdown mode is '{lm}'.", "", "6.1", "AC-3"))
        else:
            out.append(_finding(f"{_CIS}-1", "Lockdown mode disabled", "HIGH", "FAIL", host,
                                "Lockdown mode is disabled — the host allows direct management access.",
                                "Enable Normal or Strict lockdown mode in Host → Security Profile.",
                                "6.1", "AC-3"))

        # 2. SSH service — should be stopped unless actively needed.
        ssh = _b(snap, "ssh_enabled")
        out.append(self._toggle(ssh, f"{_CIS}-2", "SSH service", host,
                                "SSH is enabled on the host — a common lateral-movement/ransomware vector.",
                                "Stop the SSH service and set its policy to 'Start manually'.",
                                "MEDIUM", "4.1", "CM-7"))

        # 3. ESXi Shell — should be disabled.
        shell = _b(snap, "shell_enabled")
        out.append(self._toggle(shell, f"{_CIS}-3", "ESXi Shell", host,
                                "The ESXi Shell is enabled — reduce the local attack surface.",
                                "Disable the ESXi Shell service.",
                                "MEDIUM", "4.2", "CM-7"))

        # 4. Managed Object Browser (MOB) — should be disabled.
        mob = _b(snap, "mob_enabled")
        out.append(self._toggle(mob, f"{_CIS}-4", "Managed Object Browser (MOB)", host,
                                "The MOB is enabled — it can be abused to enumerate the host.",
                                "Set Config.HostAgent.plugins.solo.enableMob = false.",
                                "MEDIUM", "3.1", "CM-7"))

        # 5. NTP — accurate time is required for trustworthy logs.
        ntp = _b(snap, "ntp_configured")
        out.append(self._required(ntp, f"{_CIS}-5", "Time synchronization (NTP)", host,
                                  "NTP is not configured — inaccurate time undermines log correlation.",
                                  "Configure NTP servers and start the NTP service.",
                                  "MEDIUM", "5.1", "AU-8"))

        # 6. Remote syslog — logs must survive host compromise.
        sl = _b(snap, "syslog_configured")
        out.append(self._required(sl, f"{_CIS}-6", "Remote syslog", host,
                                  "No remote syslog target — logs are lost if the host is compromised or wiped.",
                                  "Set Syslog.global.logHost to a central collector.",
                                  "MEDIUM", "5.2", "AU-9"))

        # 7. TLS minimum version — must be >= 1.2.
        tls = snap.get("tls_min")
        if tls is None:
            out.append(_finding(f"{_CIS}-7", "TLS minimum version", "HIGH", "UNKNOWN", host,
                                "TLS minimum version not reported.", "", "5.3"))
        else:
            try:
                ok = float(str(tls)) >= 1.2
            except ValueError:
                ok = False
            out.append(_finding(
                f"{_CIS}-7", f"TLS minimum version ({tls})", "HIGH",
                "PASS" if ok else "FAIL", host,
                f"Host accepts TLS {tls}." + ("" if ok else " Protocols below 1.2 are deprecated/insecure."),
                "" if ok else "Restrict management TLS to 1.2+ (UserVars.ESXiVPsDisabledProtocols).",
                "5.3", "SC-8"))

        # 8. Outdated build / known CVEs — cross-reference exploit intel (KEV/EPSS).
        cves = snap.get("known_cves") or []
        outdated = _b(snap, "outdated")
        if cves:
            kev = any(c.get("kev") for c in cves)
            ids = ", ".join(c.get("id", "?") for c in cves[:5])
            out.append(_finding(
                f"{_CIS}-8", "Outdated build with known CVEs", "CRITICAL" if kev else "HIGH",
                "FAIL", host,
                f"Host build {snap.get('build','?')} is affected by {len(cves)} known CVE(s): {ids}"
                + (" (includes CISA KEV — actively exploited)." if kev else "."),
                "Patch ESXi to the latest build; ESXi is a prime ransomware target.",
                "1.1", "SI-2"))
        elif outdated:
            out.append(_finding(f"{_CIS}-8", "Outdated build", "HIGH", "FAIL", host,
                                f"Host build {snap.get('build','?')} is behind the latest patch level.",
                                "Apply the latest ESXi patches.", "1.1", "SI-2"))
        elif outdated is False:
            out.append(_finding(f"{_CIS}-8", "Build up to date", "HIGH", "PASS", host,
                                f"Host build {snap.get('build','?')} is current.", "", "1.1", "SI-2"))

        return out

    # ── helpers for the two common check shapes ──────────────────────────────
    def _toggle(self, val, control, name, host, bad_detail, fix, sev, cis, nist):
        """A service that should be OFF: enabled → FAIL, disabled → PASS."""
        if val is None:
            return _finding(control, name, sev, "UNKNOWN", host, f"{name} state not reported.", "", cis)
        if val:
            return _finding(control, f"{name} enabled", sev, "FAIL", host, bad_detail, fix, cis, nist)
        return _finding(control, f"{name} disabled", sev, "PASS", host, f"{name} is disabled.", "", cis, nist)

    def _required(self, val, control, name, host, bad_detail, fix, sev, cis, nist):
        """Something that should be ON/configured: missing → FAIL, present → PASS."""
        if val is None:
            return _finding(control, name, sev, "UNKNOWN", host, f"{name} state not reported.", "", cis)
        if val:
            return _finding(control, f"{name} configured", sev, "PASS", host, f"{name} is configured.", "", cis, nist)
        return _finding(control, f"{name} missing", sev, "FAIL", host, bad_detail, fix, cis, nist)


register(VMwareEsxiAssessor())
