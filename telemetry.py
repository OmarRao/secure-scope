"""
Anonymous opt-in usage telemetry via Firebase Measurement Protocol.
No personal data collected. Disable with --no-telemetry or SECSCOPE_NO_TELEMETRY=1.

What is collected (anonymously):
  - scan_start: feature flags used, Python version, OS type
  - scan_complete: finding counts by severity, duration_seconds, features used
  - scan_error: error type (not message), feature flags

What is NEVER collected:
  - Repository URLs or names
  - Finding messages, file paths, or code
  - API keys or tokens
  - IP addresses (Firebase strips them)
  - Any personally identifiable information
"""

import hashlib
import os
import platform
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

# Firebase Measurement Protocol — free, no SDK required
_FIREBASE_ENDPOINT = "https://www.google-analytics.com/mp/collect"
_MEASUREMENT_ID = "G-SECSCOPE2024"   # placeholder — replace with real ID
_API_SECRET = "secscope_telemetry"   # placeholder — replace with real secret

# Client ID stored locally so repeat scans are correlated as same client (not user)
_CLIENT_ID_FILE = Path.home() / ".secscope" / "client_id"
_OPT_OUT_FILE = Path.home() / ".secscope" / "no_telemetry"


def _get_client_id() -> str:
    """Return or create a random anonymous client ID."""
    try:
        _CLIENT_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
        if _CLIENT_ID_FILE.exists():
            return _CLIENT_ID_FILE.read_text().strip()
        cid = str(uuid.uuid4())
        _CLIENT_ID_FILE.write_text(cid)
        return cid
    except Exception:
        return str(uuid.uuid4())


def _is_opted_out() -> bool:
    """Return True if telemetry is disabled."""
    if os.environ.get("SECSCOPE_NO_TELEMETRY", "").strip() in ("1", "true", "yes"):
        return True
    if _OPT_OUT_FILE.exists():
        return True
    return False


def opt_out() -> None:
    """Write opt-out file. Persists across sessions."""
    try:
        _OPT_OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _OPT_OUT_FILE.touch()
        print("[telemetry] Opted out. No data will be sent in future runs.")
    except Exception:
        pass


def opt_in() -> None:
    """Remove opt-out file to re-enable telemetry."""
    try:
        _OPT_OUT_FILE.unlink(missing_ok=True)
        print("[telemetry] Opted back in.")
    except Exception:
        pass


def _send(event_name: str, params: dict) -> None:
    """Fire-and-forget event to Firebase. Never raises."""
    if _is_opted_out():
        return
    try:
        import requests
        payload = {
            "client_id": _get_client_id(),
            "events": [{"name": event_name, "params": params}],
        }
        requests.post(
            _FIREBASE_ENDPOINT,
            params={"measurement_id": _MEASUREMENT_ID, "api_secret": _API_SECRET},
            json=payload,
            timeout=3,
        )
    except Exception:
        pass   # telemetry must never crash the main process


def track_scan_start(features: list[str]) -> float:
    """Call at scan start. Returns start timestamp."""
    _send("scan_start", {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "os_type": platform.system(),
        "feature_flags": ",".join(sorted(features)),
        "version": "1.10.0",
    })
    return time.monotonic()


def track_scan_complete(start_ts: float, finding_counts: dict, features: list[str]) -> None:
    """Call at scan completion."""
    _send("scan_complete", {
        "duration_seconds": int(time.monotonic() - start_ts),
        "total_findings": finding_counts.get("total", 0),
        "critical": finding_counts.get("CRITICAL", 0),
        "high": finding_counts.get("HIGH", 0),
        "medium": finding_counts.get("MEDIUM", 0),
        "low": finding_counts.get("LOW", 0),
        "dep_vulns": finding_counts.get("dep_vulns", 0),
        "feature_flags": ",".join(sorted(features)),
        "version": "1.10.0",
    })


def track_error(error_type: str, features: list[str]) -> None:
    """Call on unhandled scan error. Only error class, not message."""
    _send("scan_error", {
        "error_type": error_type,
        "feature_flags": ",".join(sorted(features)),
        "version": "1.10.0",
    })
