"""
SARIF 2.1.0 export — produces output compatible with GitHub Advanced Security / Security tab.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "SecureScope"
TOOL_VERSION = "7.0.0"
TOOL_URI = "https://github.com/OmarRao/secure-scope"

SEVERITY_TO_LEVEL = {
    "ERROR": "error",
    "WARNING": "warning",
    "INFO": "note",
}


def _build_rules(findings: list) -> list:
    """Deduplicate rules from findings."""
    seen: dict[str, dict] = {}
    for f in findings:
        rid = f.get("rule_id", "unknown")
        if rid in seen:
            continue
        cwe = f.get("cwe") or ""
        technique = f.get("attack_technique") or ""
        tags = []
        if cwe:
            tags.append(cwe)
        if technique:
            tags.append(f"ATT&CK/{technique}")
        seen[rid] = {
            "id": rid,
            "name": rid.replace(".", "_").replace("-", "_"),
            "shortDescription": {"text": f.get("message", "")[:120]},
            "fullDescription": {"text": f.get("message", "")},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html" if cwe else TOOL_URI,
            "properties": {
                "tags": tags,
                "precision": "high",
                "problem.severity": SEVERITY_TO_LEVEL.get(f.get("severity", "INFO"), "note"),
            },
        }
    return list(seen.values())


def to_sarif(result, enriched: Optional[list] = None, path: str = "report.sarif") -> str:
    """
    Convert an AnalysisResult (plus optional enriched findings) to a SARIF 2.1.0 file.
    The output can be uploaded to GitHub via the Code Scanning API or committed as
    .github/code-scanning/results.sarif to appear in the Security tab.
    """
    findings_raw = enriched or [f.to_dict() for f in result.findings]

    rules = _build_rules(findings_raw)
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    sarif_results = []
    for f in findings_raw:
        rid = f.get("rule_id", "unknown")
        level = SEVERITY_TO_LEVEL.get(f.get("severity", "INFO"), "note")
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.get("file", "").replace("\\", "/"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": f.get("line_start", 1) or 1,
                    "endLine": f.get("line_end", 1) or 1,
                },
            }
        }
        if f.get("code_snippet"):
            location["physicalLocation"]["region"]["snippet"] = {
                "text": f["code_snippet"][:500]
            }

        entry: dict = {
            "ruleId": rid,
            "ruleIndex": rule_index.get(rid, 0),
            "level": level,
            "message": {"text": f.get("message", "")},
            "locations": [location],
        }

        # Add related info for ATT&CK technique
        if f.get("attack_technique"):
            entry["relatedLocations"] = []
            entry["properties"] = {
                "tags": [
                    t for t in [f.get("cwe"), f.get("attack_technique"), f.get("attack_tactic")]
                    if t
                ]
            }

        sarif_results.append(entry)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": result.repo_url + "/blob/HEAD/"}
                },
            }
        ],
    }

    Path(path).write_text(json.dumps(sarif_doc, indent=2))
    print(f"[+] SARIF report: {path}")
    return path
