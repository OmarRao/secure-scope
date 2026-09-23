# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Build the report-ready "Infrastructure Posture" object from assessments.

Pure aggregation over per-target summaries (infra.base.summarize) — used by the
HTML report section and the PDF. No I/O.
"""

from .base import Target, assess_snapshot, summarize, posture_grade, Finding


def assess_snapshots(snapshots: list) -> list:
    """Assess a list of normalized snapshots → list of per-target summaries.

    Each snapshot must carry at least "kind"; "host"/"id" are used to label it.
    """
    out = []
    for snap in snapshots or []:
        kind = snap.get("kind", "")
        target = Target(id=snap.get("id") or snap.get("host") or kind,
                        kind=kind, host=snap.get("host", ""))
        findings = assess_snapshot(kind, snap)
        out.append(summarize(target, findings))
    return out


def build_infra_posture(assessments: list) -> dict:
    """Aggregate per-target summaries into the report section object.

    Returns {targets, overall_score, overall_grade, totals:{targets, fail, warn,
    pass, critical, high}}. The overall score is the worst target's score
    (posture is only as strong as the weakest host).
    """
    assessments = assessments or []
    all_findings = []
    fail = warn = passed = crit = high = 0
    for a in assessments:
        for f in a.get("findings", []):
            all_findings.append(f)
            st = f.get("status")
            if st == "FAIL":
                fail += 1
            elif st == "WARN":
                warn += 1
            elif st == "PASS":
                passed += 1
            if st in ("FAIL", "WARN"):
                sev = f.get("severity")
                if sev == "CRITICAL":
                    crit += 1
                elif sev == "HIGH":
                    high += 1
    overall_score = max((a.get("score", 0) for a in assessments), default=0)
    overall_grade = ("CRITICAL" if overall_score >= 70 else "HIGH" if overall_score >= 45
                     else "MEDIUM" if overall_score >= 20 else "LOW")
    return {
        "targets": assessments,
        "overall_score": overall_score,
        "overall_grade": overall_grade,
        "totals": {"targets": len(assessments), "fail": fail, "warn": warn,
                   "pass": passed, "critical": crit, "high": high},
    }
