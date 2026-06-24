"""
Supply-chain security: dependency confusion and typosquatting detection.
"""

import json
import re
from pathlib import Path
from typing import Optional
import requests


# Known typosquatting pairs: {suspicious_name: legitimate_name}
KNOWN_TYPOSQUATS: dict[str, str] = {
    "requets": "requests",
    "reqeusts": "requests",
    "requests2": "requests",
    "piyaml": "pyyaml",
    "piayml": "pyyaml",
    "colourama": "colorama",
    "coloramaa": "colorama",
    "boto": "boto3",
    "botto3": "boto3",
    "numpyy": "numpy",
    "panads": "pandas",
    "flaskk": "flask",
    "djang": "django",
    "djangoo": "django",
    "pillow2": "pillow",
    "cryptographi": "cryptography",
    "setuptoolss": "setuptools",
    "sqlalchmy": "sqlalchemy",
    "aiohttp2": "aiohttp",
    "httpx2": "httpx",
    "fastapii": "fastapi",
    "pydantik": "pydantic",
    "uvicornn": "uvicorn",
    "celeryy": "celery",
    "reddis": "redis",
    "mongoo": "pymongo",
    "psycopg": "psycopg2",
    "pytest2": "pytest",
    "mypi": "mypy",
    "blackk": "black",
    "isort2": "isort",
}

# Patterns suggesting internal/private package names
_INTERNAL_PATTERNS = [
    re.compile(r"^internal[-_]"),
    re.compile(r"^private[-_]"),
    re.compile(r"[-_]internal$"),
    re.compile(r"[-_]private$"),
    re.compile(r"^corp[-_]"),
    re.compile(r"^company[-_]"),
    re.compile(r"[-_]corp$"),
    re.compile(r"^lib[-_][a-z]{3,}[-_][a-z]{2,}$"),  # lib-acme-util style
]


def _looks_internal(name: str) -> bool:
    """Heuristic: does this package name look like it might be internal?"""
    n = name.lower()
    return any(p.search(n) for p in _INTERNAL_PATTERNS)


def _pypi_exists(package: str) -> Optional[str]:
    """Return the latest public PyPI version, or None if not found."""
    try:
        resp = requests.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=10, headers={"User-Agent": "SecureScope/8.0.0"}
        )
        if resp.status_code == 200:
            return resp.json()["info"]["version"]
    except Exception:
        pass
    return None


def _npm_exists(package: str) -> Optional[str]:
    """Return the latest public npm version, or None if not found."""
    try:
        resp = requests.get(
            f"https://registry.npmjs.org/{package}/latest",
            timeout=10, headers={"User-Agent": "SecureScope/8.0.0"}
        )
        if resp.status_code == 200:
            return resp.json().get("version")
    except Exception:
        pass
    return None


def _parse_requirements_txt(repo_path: str) -> list[tuple[str, str]]:
    """Return [(name, version), ...] from all requirements*.txt files."""
    pkgs = []
    for f in Path(repo_path).glob("requirements*.txt"):
        try:
            for line in f.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.-]+)\s*[>=<!]=?\s*([0-9.*]+)?", line)
                if m:
                    pkgs.append((m.group(1), m.group(2) or ""))
        except OSError:
            pass
    return pkgs


def _parse_package_json(repo_path: str) -> list[tuple[str, str]]:
    """Return [(name, version), ...] from package.json files."""
    pkgs = []
    for pkg_file in Path(repo_path).rglob("package.json"):
        if "node_modules" in str(pkg_file):
            continue
        try:
            data = json.loads(pkg_file.read_text(errors="ignore"))
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for name, ver in data.get(section, {}).items():
                    pkgs.append((name, ver.lstrip("^~")))
        except Exception:
            pass
    return pkgs


def check_dependency_confusion(repo_path: str) -> list[dict]:
    """
    Check for potential dependency confusion attacks.

    For packages that look internal, checks if a public package with the same
    name exists on PyPI / npm.  If the public version is higher than what's
    pinned, flags it as a potential confusion attack.

    Each finding:
        {
          "package": str,
          "ecosystem": "python"|"npm",
          "type": "confusion",
          "public_version": str,
          "required_version": str,
          "risk": "high"|"medium",
        }
    """
    findings: list[dict] = []

    py_pkgs = _parse_requirements_txt(repo_path)
    for name, req_ver in py_pkgs:
        if not _looks_internal(name):
            continue
        pub_ver = _pypi_exists(name)
        if pub_ver:
            findings.append({
                "package": name,
                "ecosystem": "python",
                "type": "confusion",
                "public_version": pub_ver,
                "required_version": req_ver,
                "risk": "high",
            })

    node_pkgs = _parse_package_json(repo_path)
    for name, req_ver in node_pkgs:
        if not _looks_internal(name):
            continue
        pub_ver = _npm_exists(name)
        if pub_ver:
            findings.append({
                "package": name,
                "ecosystem": "npm",
                "type": "confusion",
                "public_version": pub_ver,
                "required_version": req_ver,
                "risk": "high",
            })

    return findings


def check_typosquatting(repo_path: str) -> list[dict]:
    """
    Check for known typosquats of popular packages.

    Reads requirements.txt and package.json and compares each package name
    against the KNOWN_TYPOSQUATS dictionary.

    Each finding:
        {
          "package": str,           # suspicious package name found in repo
          "ecosystem": str,
          "type": "typosquat",
          "legitimate": str,        # the real package it might be mimicking
          "risk": "high",
        }
    """
    findings: list[dict] = []

    py_pkgs = _parse_requirements_txt(repo_path)
    for name, _ in py_pkgs:
        legit = KNOWN_TYPOSQUATS.get(name.lower())
        if legit:
            findings.append({
                "package": name,
                "ecosystem": "python",
                "type": "typosquat",
                "legitimate": legit,
                "risk": "high",
            })

    node_pkgs = _parse_package_json(repo_path)
    for name, _ in node_pkgs:
        legit = KNOWN_TYPOSQUATS.get(name.lower())
        if legit:
            findings.append({
                "package": name,
                "ecosystem": "npm",
                "type": "typosquat",
                "legitimate": legit,
                "risk": "high",
            })

    return findings


def supply_chain_to_html(findings: list[dict]) -> str:
    """Render supply-chain findings as an HTML section."""
    if not findings:
        return (
            '<div class="sec" id="supply-chain"><h2>Supply Chain</h2>'
            '<p style="color:#388e3c">No dependency confusion or typosquatting issues detected.</p></div>'
        )

    rows = ""
    for f in findings:
        type_label = "Dependency Confusion" if f["type"] == "confusion" else "Typosquatting"
        detail = f.get("public_version", "") or f.get("legitimate", "")
        rows += (
            f"<tr>"
            f"<td><code>{f['package']}</code></td>"
            f"<td>{f['ecosystem']}</td>"
            f"<td><span style='color:#d32f2f;font-weight:bold'>{type_label}</span></td>"
            f"<td>{detail}</td>"
            f"<td><span style='color:#d32f2f;font-weight:bold'>HIGH</span></td>"
            f"</tr>"
        )

    return f"""
<div class="sec" id="supply-chain">
  <h2>Supply Chain Risks</h2>
  <p><strong style="color:#d32f2f">{len(findings)} supply-chain issues detected.</strong></p>
  <table>
    <thead><tr><th>Package</th><th>Ecosystem</th><th>Type</th><th>Detail</th><th>Risk</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
