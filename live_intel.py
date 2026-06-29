"""
Live threat intelligence — pulls real, current data from free public sources and
caches it so the dashboard's "Live Threat Feed" reflects what is happening now,
not just the curated in-repo database (threat_intel.py).

Sources (no API key required):
  - CISA KEV  — Known Exploited Vulnerabilities catalogue (official US CISA JSON)
  - ransomware.live — recently claimed ransomware victims

Results are cached in-memory for _TTL seconds so scans are never blocked and the
upstream services are not hammered. Every source is best-effort: if one is down,
the feed degrades gracefully to whatever else is available.
"""

import json
import time
import urllib.request
from datetime import datetime

_TTL = 1800  # 30 minutes
_CACHE = {"data": None, "ts": 0.0}

_CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_RW_URL = "https://api.ransomware.live/v2/recentvictims"


def _fetch_json(url: str, timeout: int = 12):
    req = urllib.request.Request(url, headers={
        "User-Agent": "SecureScope/1.0 (+https://github.com/OmarRao/secure-scope)",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _cisa_kev(limit: int = 8) -> list:
    d = _fetch_json(_CISA_URL)
    vulns = sorted(d.get("vulnerabilities", []), key=lambda v: v.get("dateAdded", ""), reverse=True)[:limit]
    out = []
    for v in vulns:
        rw = v.get("knownRansomwareCampaignUse") == "Known"
        out.append({
            "source": "CISA KEV",
            "type": "Exploited vulnerability",
            "title": f"{v.get('cveID','')} — {(v.get('vendorProject','') + ' ' + v.get('product','')).strip()}",
            "detail": v.get("vulnerabilityName") or v.get("shortDescription", ""),
            "date": v.get("dateAdded", ""),
            "severity": "CRITICAL" if rw else "HIGH",
            "ransomware": rw,
            "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID','')}",
        })
    return out


def _ransomware_live(limit: int = 8) -> list:
    d = _fetch_json(_RW_URL)
    items = d[:limit] if isinstance(d, list) else []
    out = []
    for x in items:
        country = x.get("country") or ""
        activity = x.get("activity") or ""
        extra = " · ".join([p for p in [country, activity] if p])
        out.append({
            "source": "ransomware.live",
            "type": "Ransomware victim",
            "title": f"{x.get('victim','Unknown target')} — {x.get('group','?')}",
            "detail": "Newly claimed ransomware victim" + (f" · {extra}" if extra else ""),
            "date": (x.get("discovered") or x.get("attackdate") or "")[:10],
            "severity": "CRITICAL",
            "group": x.get("group", ""),
            "url": x.get("claim_url") or x.get("url") or "",
        })
    return out


def get_live_feed(force: bool = False) -> dict:
    """Return merged, recency-sorted live intel; cached for _TTL seconds."""
    now = time.time()
    if not force and _CACHE["data"] and (now - _CACHE["ts"] < _TTL):
        return _CACHE["data"]

    items, sources = [], []
    for name, fn in (("CISA KEV", _cisa_kev), ("ransomware.live", _ransomware_live)):
        try:
            items.extend(fn())
            sources.append(name)
        except Exception:
            pass  # best-effort per source

    items.sort(key=lambda i: i.get("date", ""), reverse=True)
    data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        "sources": sources,
        "items": items[:16],
        "live": bool(sources),
    }
    _CACHE.update(data=data, ts=now)
    return data
