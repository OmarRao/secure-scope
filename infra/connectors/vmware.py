# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Read-only vSphere/ESXi connector — collects a normalized host snapshot.

DORMANT by default: requires `pyVmomi` and read-only vCenter/ESXi credentials
(a vCenter "Read-only" role is sufficient). With neither installed nor
configured, `available()` is False and `collect_snapshot` raises a clear,
non-sensitive error. It performs only read calls (content retrieval / config
reads) and never mutates the host.

The credentials are supplied by the in-network collector (see
docs/INFRASTRUCTURE-ASSESSMENT.md); they are never sent to the hosted app.
"""

from typing import Optional


def available() -> bool:
    """True if the pyVmomi SDK is importable."""
    try:
        import pyVim.connect  # noqa: F401
        return True
    except Exception:
        return False


def collect_snapshot(host: str, user: str, password: str,
                     port: int = 443, insecure: bool = False) -> dict:
    """Connect read-only and return a normalized ESXi host snapshot.

    Raises RuntimeError with a generic message if the SDK is missing or the
    connection fails — callers treat that as an UNKNOWN posture, never a crash.
    This is a thin adapter; the security logic lives in infra.vmware (pure).
    """
    if not available():
        raise RuntimeError("pyVmomi is not installed; cannot collect a vSphere snapshot")
    try:
        import ssl
        from pyVim.connect import SmartConnect, Disconnect

        ctx = None
        if insecure:
            ctx = ssl._create_unverified_context()
        si = SmartConnect(host=host, user=user, pwd=password, port=port, sslContext=ctx)
        try:
            content = si.RetrieveContent()
            hosts = _iter_hosts(content)
            snap: dict = {"kind": "vmware_esxi", "host": host}
            if hosts:
                snap.update(_host_to_snapshot(hosts[0]))
            return snap
        finally:
            Disconnect(si)
    except RuntimeError:
        raise
    except Exception:
        # Never leak connection internals/credentials in the message.
        raise RuntimeError("vSphere read-only collection failed (check host/credentials/network)")


def _iter_hosts(content) -> list:  # pragma: no cover - needs live vSphere
    from pyVmomi import vim
    view = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.HostSystem], True)
    try:
        return list(view.view)
    finally:
        view.Destroy()


def _host_to_snapshot(host) -> dict:  # pragma: no cover - needs live vSphere
    """Map a pyVmomi HostSystem to the normalized snapshot infra.vmware expects."""
    cfg = getattr(host, "config", None)
    summary = getattr(host, "summary", None)
    services = {}
    try:
        for svc in host.configManager.serviceSystem.serviceInfo.service:
            services[svc.key] = bool(svc.running)
    except Exception:
        pass

    def _adv(key):
        try:
            for opt in host.configManager.advancedOption.QueryOptions(key):
                return opt.value
        except Exception:
            return None
        return None

    lockdown = None
    try:
        lockdown = str(host.config.lockdownMode).replace("lockdown", "").lower() or "disabled"
    except Exception:
        pass

    return {
        "version": getattr(getattr(summary, "config", None), "product", None) and summary.config.product.version,
        "build": getattr(getattr(summary, "config", None), "product", None) and summary.config.product.build,
        "lockdown_mode": lockdown,
        "ssh_enabled": services.get("TSM-SSH"),
        "shell_enabled": services.get("TSM"),
        "mob_enabled": (_adv("Config.HostAgent.plugins.solo.enableMob") in (True, "true", 1, "1")),
        "ntp_configured": _ntp_configured(host),
        "syslog_configured": bool(_adv("Syslog.global.logHost")),
        "tls_min": _adv("UserVars.ESXiVPsDisabledProtocols") and "1.2" or None,
    }


def _ntp_configured(host) -> Optional[bool]:  # pragma: no cover - needs live vSphere
    try:
        return bool(host.configManager.dateTimeSystem.dateTimeInfo.ntpConfig.server)
    except Exception:
        return None
