# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Diff-aware finding classification for pull requests.

Given the findings from a base ref and a head ref, split them into:
  - new          : present in head, absent in base  (introduced by the PR)
  - fixed        : present in base, absent in head   (resolved by the PR)
  - pre_existing : present in both

Findings are matched by a line-independent fingerprint (rule + file + the
offending code), so a finding that merely shifted down a few lines is correctly
treated as pre-existing rather than "fixed + new". Pure functions, no I/O.
"""

import re

_WS = re.compile(r"\s+")


def _get(f, key: str, default=""):
    """Read a field from either a Finding dataclass or a plain dict."""
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def finding_fingerprint(f) -> str:
    """Stable, line-independent identity for a finding.

    Uses rule id + file + normalised code snippet. Line numbers are excluded so
    unchanged findings that shift position are not mis-reported as new/fixed.
    """
    rule = str(_get(f, "rule_id", "") or "")
    fpath = str(_get(f, "file", "") or "")
    snippet = str(_get(f, "code_snippet", "") or "")
    snippet = _WS.sub(" ", snippet).strip().lower()
    return f"{rule}|{fpath}|{snippet}"


def classify_findings(base, head) -> dict:
    """Classify head/base findings into new / fixed / pre_existing.

    Returns {"new": [...head...], "fixed": [...base...], "pre_existing": [...head...],
             "counts": {"new": n, "fixed": n, "pre_existing": n}}.
    """
    base = base or []
    head = head or []
    base_fps = {finding_fingerprint(b) for b in base}
    head_fps = {finding_fingerprint(h) for h in head}

    new = [h for h in head if finding_fingerprint(h) not in base_fps]
    fixed = [b for b in base if finding_fingerprint(b) not in head_fps]
    pre_existing = [h for h in head if finding_fingerprint(h) in base_fps]

    return {
        "new": new,
        "fixed": fixed,
        "pre_existing": pre_existing,
        "counts": {"new": len(new), "fixed": len(fixed), "pre_existing": len(pre_existing)},
    }


def classification_markdown(cls: dict, base_branch: str = "base") -> str:
    """Render a classification result as a PR-comment-friendly Markdown summary."""
    c = cls.get("counts", {})
    lines = [
        "### SecureScope PR diff",
        "",
        f"| vs `{base_branch}` | Count |",
        "|---|---|",
        f"| 🆕 New | **{c.get('new', 0)}** |",
        f"| ✅ Fixed | {c.get('fixed', 0)} |",
        f"| ➖ Pre-existing | {c.get('pre_existing', 0)} |",
        "",
    ]
    new = cls.get("new") or []
    if new:
        lines.append("**New findings introduced by this change:**")
        lines.append("")
        lines.append("| Severity | Rule | Location |")
        lines.append("|---|---|---|")
        for f in new[:25]:
            sev = _get(f, "severity", "INFO")
            rule = _get(f, "rule_id", "")
            loc = f"{_get(f, 'file', '')}:{_get(f, 'line_start', '')}"
            lines.append(f"| {sev} | `{rule}` | {loc} |")
        lines.append("")
    else:
        lines.append("_No new findings introduced by this change._ 🎉")
    return "\n".join(lines)
