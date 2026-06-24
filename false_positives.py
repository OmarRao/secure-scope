"""
False positive / suppression workflow.
Stores accepted-risk suppressions in .secscope-suppressions.json at the repo root.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


FP_FILE = ".secscope-suppressions.json"

# Schema for each suppression record:
# {
#   "rule_id":       str,
#   "file":          str,
#   "reason":        str,
#   "suppressed_by": str,
#   "suppressed_at": str,  # ISO-8601
# }


def load_suppressions(repo_path: str) -> list[dict]:
    """
    Load suppressions from {repo_path}/.secscope-suppressions.json.
    Returns an empty list if the file doesn't exist or is malformed.
    """
    fp_path = Path(repo_path) / FP_FILE
    if not fp_path.exists():
        return []
    try:
        return json.loads(fp_path.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_suppression(
    repo_path: str,
    rule_id: str,
    file: str,
    reason: str,
    suppressed_by: str = "user",
) -> None:
    """
    Append a new suppression record to {repo_path}/.secscope-suppressions.json.
    Creates the file if it doesn't exist.
    """
    fp_path = Path(repo_path) / FP_FILE
    suppressions = load_suppressions(repo_path)

    # Avoid exact duplicates
    for s in suppressions:
        if s.get("rule_id") == rule_id and s.get("file") == file:
            return  # already suppressed

    suppressions.append({
        "rule_id": rule_id,
        "file": file,
        "reason": reason,
        "suppressed_by": suppressed_by,
        "suppressed_at": datetime.now(timezone.utc).isoformat(),
    })

    fp_path.write_text(json.dumps(suppressions, indent=2), encoding="utf-8")


def is_suppressed(finding: dict, suppressions: list[dict]) -> bool:
    """
    Return True if the finding matches any suppression record.

    Matching logic: rule_id AND file must both match a suppression entry.
    """
    rule_id = finding.get("rule_id", "")
    file = finding.get("file", "")
    for s in suppressions:
        if s.get("rule_id") == rule_id and s.get("file") == file:
            return True
    return False


def apply_suppressions(
    findings: list,
    suppressions: list[dict],
) -> tuple[list, list]:
    """
    Partition findings into (active_findings, suppressed_findings).

    Works with both Finding objects and plain dicts.

    Returns:
        active_findings:     findings NOT matched by any suppression.
        suppressed_findings: findings matched by a suppression (augmented with
                             the matching suppression record under key "_suppression").
    """
    active: list = []
    suppressed: list = []

    for f in findings:
        # Support both Finding dataclass (has .to_dict()) and plain dicts
        f_dict = f.to_dict() if hasattr(f, "to_dict") else f

        matched = None
        for s in suppressions:
            if s.get("rule_id") == f_dict.get("rule_id") and s.get("file") == f_dict.get("file"):
                matched = s
                break

        if matched:
            annotated = dict(f_dict)
            annotated["_suppression"] = matched
            suppressed.append(annotated)
        else:
            active.append(f)

    return active, suppressed
