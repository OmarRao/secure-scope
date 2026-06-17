"""
Dependency Vulnerability Scanner — SecureScope v4.0.0
Parses package manifests and queries OSV.dev for known CVEs.
Supports: PyPI, npm, Go, Maven, RubyGems, Cargo, Composer
"""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
import urllib.request
import urllib.error


# ── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class PackageDef:
    name: str
    version: str
    ecosystem: str
    file_path: str


@dataclass
class DepVuln:
    package_name: str
    package_version: str
    ecosystem: str
    file_path: str
    vuln_id: str
    aliases: list[str]        # CVE IDs
    severity: str             # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    cvss_score: float
    summary: str
    details: str
    fixed_versions: list[str]
    affected_versions: list[str]

    def primary_cve(self) -> str:
        cves = [a for a in self.aliases if a.startswith("CVE-")]
        return cves[0] if cves else self.vuln_id

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "package_version": self.package_version,
            "ecosystem": self.ecosystem,
            "file_path": self.file_path,
            "vuln_id": self.vuln_id,
            "aliases": self.aliases,
            "primary_cve": self.primary_cve(),
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "summary": self.summary,
            "details": self.details[:300] if self.details else "",
            "fixed_versions": self.fixed_versions,
            "affected_versions": self.affected_versions,
        }


@dataclass
class DepScanResult:
    total_packages: int = 0
    vulnerable_packages: int = 0
    vulnerabilities: list[DepVuln] = field(default_factory=list)
    ecosystems_scanned: list[str] = field(default_factory=list)
    manifest_files: list[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "LOW")

    def to_dict(self) -> dict:
        return {
            "total_packages": self.total_packages,
            "vulnerable_packages": self.vulnerable_packages,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "ecosystems_scanned": self.ecosystems_scanned,
            "manifest_files": self.manifest_files,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "error": self.error,
        }


# ── Manifest Parsers ───────────────────────────────────────────────────────────

def _parse_requirements_txt(path: Path) -> list[PackageDef]:
    packages = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip extras: requests[security]==2.31.0 -> requests, 2.31.0
            line = re.sub(r"\[.*?\]", "", line)
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=~><^!]+\s*([^\s;#,]+)", line)
            if m:
                packages.append(PackageDef(
                    name=m.group(1).lower(),
                    version=m.group(2).strip(),
                    ecosystem="PyPI",
                    file_path=str(path),
                ))
    except Exception:
        pass
    return packages


def _parse_package_json(path: Path) -> list[PackageDef]:
    packages = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, ver in data.get(section, {}).items():
                # Strip semver prefixes: ^1.0.0 -> 1.0.0
                ver = re.sub(r"^[~^>=<]+", "", ver).strip()
                if ver and not ver.startswith("*") and not ver.startswith("file:"):
                    packages.append(PackageDef(
                        name=name,
                        version=ver,
                        ecosystem="npm",
                        file_path=str(path),
                    ))
    except Exception:
        pass
    return packages


def _parse_package_lock_json(path: Path) -> list[PackageDef]:
    packages = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        pkgs = data.get("packages", data.get("dependencies", {}))
        for name, info in pkgs.items():
            if not isinstance(info, dict):
                continue
            ver = info.get("version", "")
            clean_name = name.lstrip("node_modules/") if name.startswith("node_modules/") else name
            if clean_name and ver:
                packages.append(PackageDef(
                    name=clean_name,
                    version=ver,
                    ecosystem="npm",
                    file_path=str(path),
                ))
    except Exception:
        pass
    return packages


def _parse_go_mod(path: Path) -> list[PackageDef]:
    packages = []
    try:
        in_require = False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require or line.startswith("require "):
                line = re.sub(r"^require\s+", "", line)
                parts = line.split()
                if len(parts) >= 2:
                    ver = parts[1].lstrip("v")
                    packages.append(PackageDef(
                        name=parts[0],
                        version=ver,
                        ecosystem="Go",
                        file_path=str(path),
                    ))
    except Exception:
        pass
    return packages


def _parse_pom_xml(path: Path) -> list[PackageDef]:
    packages = []
    try:
        tree = ET.parse(str(path))
        root = tree.getroot()
        ns = re.match(r"\{.*\}", root.tag)
        ns = ns.group(0) if ns else ""
        for dep in root.iter(f"{ns}dependency"):
            group = dep.findtext(f"{ns}groupId", "")
            artifact = dep.findtext(f"{ns}artifactId", "")
            version = dep.findtext(f"{ns}version", "")
            if group and artifact and version and not version.startswith("$"):
                packages.append(PackageDef(
                    name=f"{group}:{artifact}",
                    version=version,
                    ecosystem="Maven",
                    file_path=str(path),
                ))
    except Exception:
        pass
    return packages


def _parse_gemfile_lock(path: Path) -> list[PackageDef]:
    packages = []
    try:
        in_specs = False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs and line == "":
                in_specs = False
                continue
            if in_specs:
                m = re.match(r"^\s{4}([a-z][a-z0-9_\-]+)\s+\(([^\)]+)\)", line)
                if m:
                    packages.append(PackageDef(
                        name=m.group(1),
                        version=m.group(2),
                        ecosystem="RubyGems",
                        file_path=str(path),
                    ))
    except Exception:
        pass
    return packages


def _parse_cargo_lock(path: Path) -> list[PackageDef]:
    packages = []
    try:
        name = version = None
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line == "[[package]]":
                if name and version:
                    packages.append(PackageDef(name=name, version=version, ecosystem="crates.io", file_path=str(path)))
                name = version = None
            elif line.startswith("name = "):
                name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                version = line.split("=", 1)[1].strip().strip('"')
        if name and version:
            packages.append(PackageDef(name=name, version=version, ecosystem="crates.io", file_path=str(path)))
    except Exception:
        pass
    return packages


def _parse_composer_json(path: Path) -> list[PackageDef]:
    packages = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        for section in ("require", "require-dev"):
            for name, ver in data.get(section, {}).items():
                if name == "php" or name.startswith("ext-"):
                    continue
                ver = re.sub(r"^[~^>=<^]+", "", ver).strip().lstrip("v")
                if ver and not ver.startswith("*"):
                    packages.append(PackageDef(
                        name=name,
                        version=ver,
                        ecosystem="Packagist",
                        file_path=str(path),
                    ))
    except Exception:
        pass
    return packages


# ── Manifest Discovery ─────────────────────────────────────────────────────────

_MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "requirements-test.txt": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock_json,
    "go.mod": _parse_go_mod,
    "pom.xml": _parse_pom_xml,
    "Gemfile.lock": _parse_gemfile_lock,
    "Cargo.lock": _parse_cargo_lock,
    "composer.json": _parse_composer_json,
}

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "vendor", "dist", "build", ".tox", "target",
}


def _discover_manifests(repo_root: Path) -> list[tuple[Path, callable]]:
    found = []
    for root, dirs, files in repo_root.walk() if hasattr(repo_root, "walk") else _walk(repo_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if fname in _MANIFEST_PARSERS:
                found.append((Path(root) / fname, _MANIFEST_PARSERS[fname]))
    return found


def _walk(path: Path):
    """os.walk compatible for older Python."""
    import os
    for root, dirs, files in os.walk(str(path)):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        yield root, dirs, files


# ── OSV.dev API ────────────────────────────────────────────────────────────────

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_BATCH_SIZE = 100  # OSV allows up to 1000 but keep batches manageable


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _extract_severity(vuln: dict) -> tuple[str, float]:
    """Extract severity label and CVSS score from OSV vuln record."""
    best_score = 0.0
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> parse base score
        m = re.search(r"(\d+\.\d+)$", score_str)
        if m:
            score = float(m.group(1))
            if score > best_score:
                best_score = score
    # Fallback: check database_specific.severity
    db = vuln.get("database_specific", {})
    sev_label = db.get("severity", "").upper()
    if not best_score and sev_label in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        mapping = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}
        best_score = mapping.get(sev_label, 0.0)
    return _cvss_to_severity(best_score), best_score


def _extract_fixed_versions(vuln: dict, ecosystem: str, pkg_name: str) -> list[str]:
    fixed = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() != ecosystem.lower() and \
           pkg.get("name", "").lower() != pkg_name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return list(set(fixed))


def _query_osv_batch(packages: list[PackageDef]) -> list[list[dict]]:
    """Query OSV.dev in batches. Returns list of vuln lists, one per package."""
    all_results = []
    for i in range(0, len(packages), _BATCH_SIZE):
        batch = packages[i:i + _BATCH_SIZE]
        queries = [
            {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
            for p in batch
        ]
        payload = json.dumps({"queries": queries}).encode("utf-8")
        try:
            req = urllib.request.Request(
                _OSV_BATCH_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for r in data.get("results", []):
                    all_results.append(r.get("vulns", []))
        except Exception:
            # On network error, return empty results for this batch
            all_results.extend([[] for _ in batch])
    return all_results


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_repo(
    repo_path: str,
    progress_cb: Optional[Callable[[int, str], None]] = None,
) -> DepScanResult:
    """
    Scan a repository for dependency vulnerabilities via OSV.dev.
    progress_cb(percent, message) called during scan.
    """
    root = Path(repo_path)
    result = DepScanResult()

    if not root.exists():
        result.error = f"Path not found: {repo_path}"
        return result

    # Step 1 — discover manifests
    if progress_cb:
        progress_cb(5, "Discovering package manifests...")

    manifest_hits = _discover_manifests(root)
    if not manifest_hits:
        result.error = "No package manifests found (requirements.txt, package.json, go.mod, pom.xml, etc.)"
        return result

    result.manifest_files = [str(p.relative_to(root)) for p, _ in manifest_hits]

    # Step 2 — parse packages
    if progress_cb:
        progress_cb(15, f"Parsing {len(manifest_hits)} manifest file(s)...")

    all_packages: list[PackageDef] = []
    for path, parser in manifest_hits:
        pkgs = parser(path)
        all_packages.extend(pkgs)

    # Deduplicate by (name, version, ecosystem)
    seen = set()
    unique_packages = []
    for p in all_packages:
        key = (p.name.lower(), p.version, p.ecosystem)
        if key not in seen:
            seen.add(key)
            unique_packages.append(p)

    result.total_packages = len(unique_packages)
    result.ecosystems_scanned = sorted(set(p.ecosystem for p in unique_packages))

    if not unique_packages:
        result.error = "No versioned packages found in manifests"
        return result

    # Step 3 — query OSV.dev
    if progress_cb:
        progress_cb(30, f"Querying OSV.dev for {len(unique_packages)} packages...")

    osv_results = _query_osv_batch(unique_packages)

    # Step 4 — build findings
    if progress_cb:
        progress_cb(80, "Processing vulnerability data...")

    vulnerable_pkg_names = set()
    for pkg, vulns in zip(unique_packages, osv_results):
        for vuln in vulns:
            severity, cvss = _extract_severity(vuln)
            fixed = _extract_fixed_versions(vuln, pkg.ecosystem, pkg.name)
            aliases = vuln.get("aliases", [])
            # Relative file path
            try:
                rel_path = str(Path(pkg.file_path).relative_to(root))
            except ValueError:
                rel_path = pkg.file_path

            result.vulnerabilities.append(DepVuln(
                package_name=pkg.name,
                package_version=pkg.version,
                ecosystem=pkg.ecosystem,
                file_path=rel_path,
                vuln_id=vuln.get("id", ""),
                aliases=aliases,
                severity=severity,
                cvss_score=cvss,
                summary=vuln.get("summary", ""),
                details=vuln.get("details", ""),
                fixed_versions=fixed,
                affected_versions=[],
            ))
            vulnerable_pkg_names.add(pkg.name.lower())

    result.vulnerable_packages = len(vulnerable_pkg_names)

    # Sort by severity
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    result.vulnerabilities.sort(key=lambda v: _sev_order.get(v.severity, 4))

    if progress_cb:
        progress_cb(100, "Dependency scan complete.")

    return result
