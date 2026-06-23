"""
SBOM generation in CycloneDX 1.4 JSON format.
Produces a Software Bill of Materials from dependency scan results and repo metadata.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional


CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.4.schema.json"
CYCLONEDX_VERSION = "1.4"


def _severity_to_cvss_score(severity: str) -> float:
    return {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 1.0}.get(
        severity.upper(), 5.0
    )


def generate_sbom(result, path: str = "sbom.cyclonedx.json") -> str:
    """
    Generate a CycloneDX 1.4 JSON SBOM from dependency_vulns and repo metadata.
    Compatible with: grype, trivy, Dependency-Track, GitHub Dependency Submission API.
    """
    bom_ref_base = str(uuid.uuid4())
    components = []
    vulnerabilities = []

    # Build component map: package -> component
    seen_pkgs: dict[str, str] = {}  # pkg_key -> bom-ref
    for v in result.dependency_vulns:
        pkg_key = f"{v.get('ecosystem', 'unknown')}:{v.get('package', 'unknown')}@{v.get('version', 'unknown')}"
        if pkg_key not in seen_pkgs:
            bom_ref = f"pkg-{uuid.uuid4().hex[:8]}"
            seen_pkgs[pkg_key] = bom_ref
            ecosystem = v.get("ecosystem", "unknown")
            purl_type = {"python": "pypi", "npm": "npm", "go": "golang", "ruby": "gem"}.get(
                ecosystem, ecosystem
            )
            pkg_name = v.get("package", "unknown")
            pkg_version = v.get("version", "unknown") or "unknown"
            components.append({
                "type": "library",
                "bom-ref": bom_ref,
                "name": pkg_name,
                "version": pkg_version,
                "purl": f"pkg:{purl_type}/{pkg_name}@{pkg_version}",
                "scope": "required",
            })

        # Build vulnerability entry
        vuln_id = v.get("vuln_id") or "UNKNOWN"
        severity = v.get("severity", "UNKNOWN")
        fix_versions = v.get("fix_versions", [])
        if isinstance(fix_versions, bool):
            fix_versions = []

        vuln_entry: dict = {
            "id": vuln_id,
            "source": {"name": "OSV" if vuln_id.startswith("GHSA") else "NVD", "url": "https://osv.dev"},
            "ratings": [
                {
                    "source": {"name": "SecureScope"},
                    "score": _severity_to_cvss_score(severity),
                    "severity": severity.lower() if severity != "UNKNOWN" else "unknown",
                    "method": "CVSSv3",
                }
            ],
            "description": v.get("description", "")[:500],
            "affects": [
                {
                    "ref": seen_pkgs[pkg_key],
                    "versions": [{"version": v.get("version", "unknown"), "status": "affected"}],
                }
            ],
        }
        if fix_versions:
            vuln_entry["recommendation"] = f"Upgrade to {', '.join(str(fv) for fv in fix_versions)}"

        vulnerabilities.append(vuln_entry)

    repo_slug = result.repo_url.rstrip("/").split("/")[-1]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "$schema": CYCLONEDX_SCHEMA,
        "serialNumber": f"urn:uuid:{bom_ref_base}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "SecureScope",
                    "name": "SecureScope",
                    "version": "7.0.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"app-{bom_ref_base}",
                "name": repo_slug,
                "version": "HEAD",
                "purl": f"pkg:github/{result.repo_url.split('github.com/')[-1]}@HEAD",
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }

    Path(path).write_text(json.dumps(bom, indent=2))
    print(f"[+] SBOM (CycloneDX): {path}")
    return path
