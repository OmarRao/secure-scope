# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Repo security badge — a shields-style SVG summarising the latest scan's risk.

Pure and self-contained: turns a scan summary into a (score, grade, colour) and
renders an embeddable SVG. The web server persists one small record per repo and
serves it from the /badge route; nothing here touches the network.
"""

import re

# Descending score thresholds → (grade, shields-style colour).
_GRADES = [
    (70, "CRITICAL", "#e05d44"),  # red
    (45, "HIGH", "#fe7d37"),      # orange
    (20, "MEDIUM", "#dfb317"),    # yellow
    (0,  "LOW", "#4c1"),          # green
]
_GRADE_COLOR = {g: c for _, g, c in _GRADES}
_UNKNOWN_COLOR = "#9f9f9f"


def compute_score(summary: dict) -> tuple[int, str, str]:
    """Return (score 0-100, grade, hex colour) from a scan summary.

    Mirrors the report's formula: errors*10 + warnings*3 + dep_vulns*8, capped
    at 100. Higher = worse.
    """
    sev = (summary or {}).get("by_severity", {}) or {}
    errors = int(sev.get("ERROR", 0) or 0)
    warnings = int(sev.get("WARNING", 0) or 0)
    dep_vulns = int((summary or {}).get("dependency_vulns", 0) or 0)
    score = min(errors * 10 + warnings * 3 + dep_vulns * 8, 100)
    for thr, grade, color in _GRADES:
        if score >= thr:
            return score, grade, color
    return score, "LOW", "#4c1"


def grade_color(grade: str) -> str:
    """Shields colour for a grade string (grey for anything unknown)."""
    return _GRADE_COLOR.get((grade or "").upper(), _UNKNOWN_COLOR)


def badge_slug(repo_url: str) -> str:
    """Stable, Firestore-safe document id derived from a repo URL.

    Both the writer (on scan) and the reader (/badge) derive the slug the same
    way, so a badge URL only needs the repo, e.g. ?repo=https://github.com/o/r.
    """
    s = (repo_url or "").strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.replace(".git", "")
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s[:200] or "unknown"


def _text_width(s: str) -> int:
    """Rough px width of an 11px Verdana string for badge layout."""
    return int(len(s) * 6.5) + 12


def render_svg(label: str, value: str, color: str) -> str:
    """Render a shields-style two-part badge as a self-contained SVG string."""
    label = str(label)
    value = str(value)
    lw = _text_width(label)
    vw = _text_width(value)
    w = lw + vw
    lx = lw / 2
    vx = lw + vw / 2
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        '<linearGradient id="s" x2="0" y2="100%">'
        '<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>'
        '<g clip-path="url(#r)">'
        f'<rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        f'<rect width="{w}" height="20" fill="url(#s)"/></g>'
        '<g fill="#fff" text-anchor="middle" '
        'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lx}" y="14">{label}</text>'
        f'<text x="{vx}" y="14">{value}</text></g></svg>'
    )


def badge_for(summary: dict, label: str = "security") -> str:
    """Convenience: SVG straight from a scan summary."""
    score, grade, color = compute_score(summary)
    return render_svg(label, f"{grade} {score}", color)
