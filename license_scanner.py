"""
License compliance scanner.
Uses pip-licenses (Python) and license-checker (Node) when available;
falls back to manually parsing requirements.txt / pyproject.toml.
"""

import json
import re
import subprocess
import shutil
from pathlib import Path


# Risk classification by SPDX identifier (or substring)
_HIGH_RISK = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1"}
_MEDIUM_RISK = {"MPL-2.0", "EPL-2.0", "CDDL"}
_LOW_RISK = {"LGPL-3.0"}
_OK_PREFIXES = {"MIT", "Apache-2.0", "BSD", "ISC", "Unlicense", "CC0", "PSF", "Python"}


def _classify_risk(license_id: str) -> str:
    """Classify a license SPDX identifier into high / medium / low / ok."""
    if not license_id:
        return "ok"
    norm = license_id.strip()
    if norm in _HIGH_RISK:
        return "high"
    if norm in _MEDIUM_RISK:
        return "medium"
    if norm in _LOW_RISK:
        return "low"
    for prefix in _OK_PREFIXES:
        if norm.startswith(prefix):
            return "ok"
    # Unknown license — treat as low risk rather than blocking
    return "low"


def _scan_python_pip_licenses(repo_path: str) -> list[dict]:
    """Run pip-licenses --format=json and parse output."""
    try:
        proc = subprocess.run(
            ["pip-licenses", "--format=json", "--with-license-file", "--no-license-path"],
            capture_output=True, text=True, timeout=60, cwd=repo_path,
        )
        pkgs = json.loads(proc.stdout)
        results = []
        for p in pkgs:
            lic = p.get("License", "UNKNOWN")
            results.append({
                "package": p.get("Name", ""),
                "version": p.get("Version", ""),
                "license": lic,
                "risk": _classify_risk(lic),
            })
        return results
    except Exception:
        return []


def _scan_node_license_checker(repo_path: str) -> list[dict]:
    """Run license-checker --json and parse output."""
    pkg_json = Path(repo_path) / "package.json"
    if not pkg_json.exists():
        return []
    try:
        proc = subprocess.run(
            ["license-checker", "--json"],
            capture_output=True, text=True, timeout=60, cwd=repo_path,
        )
        data = json.loads(proc.stdout)
        results = []
        for pkg_at_ver, info in data.items():
            lic = info.get("licenses", "UNKNOWN")
            # license-checker sometimes returns a list
            if isinstance(lic, list):
                lic = ", ".join(lic)
            parts = pkg_at_ver.rsplit("@", 1)
            name = parts[0]
            version = parts[1] if len(parts) == 2 else ""
            results.append({
                "package": name,
                "version": version,
                "license": lic,
                "risk": _classify_risk(lic),
            })
        return results
    except Exception:
        return []


# Very rough heuristic: package name -> guessed license (for fallback)
_KNOWN_LICENSES: dict[str, str] = {
    "requests": "Apache-2.0",
    "flask": "BSD-3-Clause",
    "django": "BSD-3-Clause",
    "numpy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause",
    "scipy": "BSD-3-Clause",
    "matplotlib": "PSF",
    "sqlalchemy": "MIT",
    "boto3": "Apache-2.0",
    "click": "BSD-3-Clause",
    "pyyaml": "MIT",
    "cryptography": "Apache-2.0",
    "pillow": "MIT",
    "setuptools": "MIT",
    "pip": "MIT",
    "certifi": "MPL-2.0",
}


def _fallback_python(repo_path: str) -> list[dict]:
    """Parse requirements.txt / pyproject.toml for package names, guess license."""
    results = []
    seen = set()

    for req_file in (
        list(Path(repo_path).glob("requirements*.txt")) +
        list(Path(repo_path).glob("pyproject.toml"))
    ):
        try:
            text = req_file.read_text(errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            # Strip version specifiers
            pkg = re.split(r"[>=<!;\s]", line)[0].strip().lower().replace("_", "-")
            if not pkg or pkg in seen:
                continue
            seen.add(pkg)
            lic = _KNOWN_LICENSES.get(pkg, "UNKNOWN")
            results.append({
                "package": pkg,
                "version": "",
                "license": lic,
                "risk": _classify_risk(lic),
            })

    return results


def scan_licenses(repo_path: str) -> list[dict]:
    """
    Scan a repository for license compliance.

    Tries pip-licenses for Python dependencies and license-checker for Node.
    Falls back to manual parsing of requirements.txt / pyproject.toml.

    Returns a list of:
        {"package": str, "version": str, "license": str, "risk": "high"|"medium"|"low"|"ok"}
    """
    results: list[dict] = []

    # Python
    if shutil.which("pip-licenses"):
        results += _scan_python_pip_licenses(repo_path)
    else:
        results += _fallback_python(repo_path)

    # Node
    if shutil.which("license-checker"):
        results += _scan_node_license_checker(repo_path)

    # Deduplicate by package name
    seen: set[str] = set()
    unique = []
    for r in results:
        key = r["package"].lower()
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique


def license_to_html(results: list[dict]) -> str:
    """Render license scan results as an HTML section."""
    if not results:
        return ""

    risk_color = {
        "high":   "#d32f2f",
        "medium": "#f57c00",
        "low":    "#1976d2",
        "ok":     "#388e3c",
    }

    rows = ""
    for r in sorted(results, key=lambda x: {"high": 0, "medium": 1, "low": 2, "ok": 3}.get(x["risk"], 4)):
        color = risk_color.get(r["risk"], "#555")
        rows += (
            f"<tr>"
            f"<td><code>{r['package']}</code></td>"
            f"<td>{r['version']}</td>"
            f"<td>{r['license']}</td>"
            f"<td><span style='color:{color};font-weight:bold'>{r['risk'].upper()}</span></td>"
            f"</tr>"
        )

    high_count = sum(1 for r in results if r["risk"] == "high")
    summary_color = "#d32f2f" if high_count else "#388e3c"

    return f"""
<div class="sec" id="licenses">
  <h2>License Compliance</h2>
  <p>
    {len(results)} packages scanned.
    <span style="color:{summary_color};font-weight:bold">{high_count} high-risk (copyleft)</span>.
  </p>
  <table>
    <thead><tr><th>Package</th><th>Version</th><th>License</th><th>Risk</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
