"""
Trivy container image scanner integration.
Runs `trivy image` and returns parsed CVE findings for container images.
"""

import json
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ContainerVuln:
    target: str          # image layer / OS / library target
    package: str
    version: str
    vuln_id: str
    severity: str
    title: str
    description: str
    fixed_version: str
    cvss_score: float = 0.0
    published_date: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


def scan_container_image(image: str, timeout: int = 120) -> list[ContainerVuln]:
    """
    Run `trivy image --format json` against a container image reference.
    Requires Trivy to be installed: https://aquasecurity.github.io/trivy/

    Args:
        image: Docker image reference, e.g. "python:3.11-slim" or "ghcr.io/org/app:latest"
        timeout: seconds to wait for Trivy (default 120)

    Returns:
        List of ContainerVuln objects, sorted by severity.
    """
    print(f"[*] Running Trivy container scan: {image}")
    try:
        result = subprocess.run(
            [
                "trivy", "image",
                "--format", "json",
                "--quiet",
                "--no-progress",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        print("[!] Trivy not found. Install from https://aquasecurity.github.io/trivy/")
        return []
    except subprocess.TimeoutExpired:
        print(f"[!] Trivy timed out after {timeout}s")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        if result.returncode != 0:
            print(f"[!] Trivy error: {result.stderr[:200]}")
        return []

    vulns: list[ContainerVuln] = []
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    for scan_result in data.get("Results", []):
        target = scan_result.get("Target", "")
        for v in scan_result.get("Vulnerabilities") or []:
            cvss_score = 0.0
            cvss_data = v.get("CVSS", {})
            for source in ("nvd", "ghsa", "redhat"):
                if source in cvss_data and cvss_data[source].get("V3Score"):
                    cvss_score = float(cvss_data[source]["V3Score"])
                    break

            vulns.append(
                ContainerVuln(
                    target=target,
                    package=v.get("PkgName", ""),
                    version=v.get("InstalledVersion", ""),
                    vuln_id=v.get("VulnerabilityID", ""),
                    severity=v.get("Severity", "UNKNOWN"),
                    title=v.get("Title", ""),
                    description=(v.get("Description") or "")[:500],
                    fixed_version=v.get("FixedVersion", ""),
                    cvss_score=cvss_score,
                    published_date=v.get("PublishedDate", ""),
                )
            )

    vulns.sort(key=lambda v: (severity_order.get(v.severity, 99), -v.cvss_score))
    print(f"[+] Trivy found {len(vulns)} container CVEs in {image}")
    return vulns


def scan_dockerfile(repo_path: str, timeout: int = 120) -> list[ContainerVuln]:
    """
    Find Dockerfiles in repo_path and run Trivy filesystem scan for misconfigs.
    Returns findings as ContainerVuln objects with target="dockerfile".
    """
    from pathlib import Path

    dockerfiles = list(Path(repo_path).rglob("Dockerfile*"))
    if not dockerfiles:
        return []

    print(f"[*] Running Trivy filesystem scan on {len(dockerfiles)} Dockerfile(s)")
    try:
        result = subprocess.run(
            [
                "trivy", "fs",
                "--format", "json",
                "--quiet",
                "--no-progress",
                "--scanners", "misconfig,vuln",
                repo_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    vulns: list[ContainerVuln] = []
    for scan_result in data.get("Results", []):
        target = scan_result.get("Target", "")
        for m in scan_result.get("Misconfigurations") or []:
            vulns.append(
                ContainerVuln(
                    target=target,
                    package="dockerfile",
                    version="",
                    vuln_id=m.get("ID", ""),
                    severity=m.get("Severity", "UNKNOWN"),
                    title=m.get("Title", ""),
                    description=(m.get("Description") or "")[:500],
                    fixed_version="",
                )
            )
        for v in scan_result.get("Vulnerabilities") or []:
            vulns.append(
                ContainerVuln(
                    target=target,
                    package=v.get("PkgName", ""),
                    version=v.get("InstalledVersion", ""),
                    vuln_id=v.get("VulnerabilityID", ""),
                    severity=v.get("Severity", "UNKNOWN"),
                    title=v.get("Title", ""),
                    description=(v.get("Description") or "")[:500],
                    fixed_version=v.get("FixedVersion", ""),
                )
            )

    print(f"[+] Trivy filesystem scan found {len(vulns)} issues")
    return vulns
