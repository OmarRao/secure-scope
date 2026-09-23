# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Core types + registry + runner for infrastructure assessors.

Design (see docs/INFRASTRUCTURE-ASSESSMENT.md):
  - A Target is *what* to assess and *how* to reach it (never inline secrets).
  - A Connector (elsewhere) turns a Target + resolved credentials into a
    normalized *snapshot* dict — strictly read-only.
  - An Assessor is pure logic over a snapshot → a list of Findings. Because the
    snapshot is a plain dict, assessors are unit-tested against fixtures with no
    live infrastructure.

Everything here is read-only and side-effect free apart from the in-process
registry. No network, no credentials.
"""

from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

# Severity + status vocabularies (align with the rest of SecureScope).
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_STATUSES = {"PASS", "FAIL", "WARN", "UNKNOWN"}


@dataclass
class Target:
    """What to assess and how to reach it. `cred_ref` is an indirection only —
    the collector resolves it locally; the hosted app never sees its value."""
    id: str
    kind: str                       # e.g. "vmware_esxi", "vmware_vcenter"
    host: str = ""
    cred_ref: str = ""
    tags: dict = field(default_factory=dict)


@dataclass
class Finding:
    """One normalized posture finding."""
    assessor: str
    control: str                    # e.g. "CIS-ESXi-1.2"
    title: str
    severity: str                   # CRITICAL..INFO
    status: str                     # PASS | FAIL | WARN | UNKNOWN
    resource: str = ""
    detail: str = ""
    remediation: str = ""
    frameworks: dict = field(default_factory=dict)   # {"CIS": "1.2", "NIST": "AC-3"}
    cve: Optional[str] = None
    kev: bool = False
    epss: float = 0.0

    def __post_init__(self):
        self.severity = (self.severity or "INFO").upper()
        if self.severity not in SEVERITY_RANK:
            self.severity = "INFO"
        self.status = (self.status or "UNKNOWN").upper()
        if self.status not in _STATUSES:
            self.status = "UNKNOWN"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Registry ──────────────────────────────────────────────────────────────────
# Assessors self-register by importing their module. Each declares the target
# kinds it applies to and a domain label.
_REGISTRY: list = []


class Assessor:
    """Base class for assessors. Subclasses set id/domain/kinds and implement
    assess(snapshot) -> list[Finding]. Kept a class (not just a Protocol) so
    registration and shared helpers are easy."""
    id: str = "base"
    domain: str = "generic"
    kinds: tuple = ()

    def assess(self, snapshot: dict) -> list:  # pragma: no cover - overridden
        raise NotImplementedError


def register(assessor: Assessor) -> Assessor:
    """Register an assessor instance. Idempotent by id."""
    if not any(a.id == assessor.id for a in _REGISTRY):
        _REGISTRY.append(assessor)
    return assessor


def get_assessors(domain: Optional[str] = None) -> list:
    """All registered assessors, optionally filtered by domain."""
    return [a for a in _REGISTRY if domain is None or a.domain == domain]


def assessors_for_kind(kind: str) -> list:
    """Assessors that apply to a given target kind."""
    return [a for a in _REGISTRY if kind in a.kinds]


# ── Runner + scoring ──────────────────────────────────────────────────────────

def assess_snapshot(kind: str, snapshot: dict) -> list:
    """Run every assessor that applies to `kind` over a snapshot → findings.

    Fail-safe: one assessor raising never aborts the rest; it yields a single
    UNKNOWN finding instead.
    """
    findings: list = []
    for a in assessors_for_kind(kind):
        try:
            findings.extend(a.assess(snapshot or {}) or [])
        except Exception as exc:  # pragma: no cover - defensive
            findings.append(Finding(
                assessor=a.id, control=f"{a.id}.error", title="Assessor error",
                severity="INFO", status="UNKNOWN",
                detail=f"{type(exc).__name__} while assessing", remediation=""))
    return findings


def posture_grade(findings: list) -> tuple:
    """Return (score 0-100, grade) from findings. Higher score = worse posture.

    Weighted by severity of FAIL/WARN findings (PASS/UNKNOWN don't add risk).
    """
    weight = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3, "INFO": 0}
    score = 0
    for f in findings:
        if f.status in ("FAIL", "WARN"):
            mult = 1.0 if f.status == "FAIL" else 0.5
            score += weight.get(f.severity, 0) * mult
    score = int(min(score, 100))
    grade = ("CRITICAL" if score >= 70 else "HIGH" if score >= 45
             else "MEDIUM" if score >= 20 else "LOW")
    return score, grade


def summarize(target: Target, findings: list) -> dict:
    """Roll findings into a report-ready posture object for one target."""
    by_status: dict = {}
    by_severity: dict = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        if f.status in ("FAIL", "WARN"):
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    score, grade = posture_grade(findings)
    # Sort findings worst-first: FAIL/WARN before PASS/UNKNOWN, then severity.
    order = {"FAIL": 0, "WARN": 1, "UNKNOWN": 2, "PASS": 3}
    ordered = sorted(
        findings,
        key=lambda f: (order.get(f.status, 4), -SEVERITY_RANK.get(f.severity, 0)))
    return {
        "target": asdict(target) if isinstance(target, Target) else dict(target or {}),
        "score": score,
        "grade": grade,
        "counts": {"total": len(findings), "by_status": by_status, "by_severity": by_severity},
        "findings": [f.to_dict() for f in ordered],
    }
