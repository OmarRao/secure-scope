"""
Static analysis engine: clones repo, runs Semgrep, maps findings to MITRE CWE/ATT&CK.
"""

import json
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import requests

# CWE -> ATT&CK technique mapping (subset of common web/app weaknesses)
CWE_TO_ATTACK: dict[str, dict] = {
    "CWE-89":  {"technique": "T1190", "name": "SQL Injection", "tactic": "Initial Access"},
    "CWE-79":  {"technique": "T1059.007", "name": "XSS", "tactic": "Execution"},
    "CWE-78":  {"technique": "T1059", "name": "OS Command Injection", "tactic": "Execution"},
    "CWE-22":  {"technique": "T1083", "name": "Path Traversal", "tactic": "Discovery"},
    "CWE-798": {"technique": "T1552.001", "name": "Hardcoded Credentials", "tactic": "Credential Access"},
    "CWE-330": {"technique": "T1552", "name": "Weak Randomness", "tactic": "Credential Access"},
    "CWE-502": {"technique": "T1059", "name": "Deserialization", "tactic": "Execution"},
    "CWE-611": {"technique": "T1190", "name": "XXE Injection", "tactic": "Initial Access"},
    "CWE-918": {"technique": "T1090", "name": "SSRF", "tactic": "Defense Evasion"},
    "CWE-601": {"technique": "T1566", "name": "Open Redirect", "tactic": "Initial Access"},
    "CWE-312": {"technique": "T1552", "name": "Cleartext Storage of Sensitive Info", "tactic": "Credential Access"},
    "CWE-327": {"technique": "T1600", "name": "Weak Cryptography", "tactic": "Defense Evasion"},
    "CWE-352": {"technique": "T1562", "name": "CSRF", "tactic": "Defense Evasion"},
    "CWE-434": {"technique": "T1190", "name": "Unrestricted File Upload", "tactic": "Initial Access"},
    "CWE-285": {"technique": "T1548", "name": "Improper Authorization", "tactic": "Privilege Escalation"},
}

SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}


@dataclass
class Finding:
    rule_id: str
    message: str
    severity: str
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    cwe: Optional[str] = None
    attack_technique: Optional[str] = None
    attack_tactic: Optional[str] = None
    attack_name: Optional[str] = None
    fix_suggestion: Optional[str] = None  # populated by advisor

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class AnalysisResult:
    repo_url: str
    repo_path: str
    findings: list[Finding] = field(default_factory=list)
    dependency_vulns: list[dict] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)
    pr_diff_mode: bool = False
    changed_files: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        by_severity = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "dependency_vulns": len(self.dependency_vulns),
            "errors": self.scan_errors,
        }


def clone_repo(repo_url: str, dest: Optional[str] = None) -> str:
    """Clone a GitHub repo and return the local path."""
    if dest is None:
        dest = tempfile.mkdtemp(prefix="secreview_")
    print(f"[*] Cloning {repo_url} -> {dest}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, dest],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr}")
    return dest


def run_semgrep(repo_path: str, fast: bool = True) -> list[Finding]:
    """Run Semgrep with security rulesets and return parsed findings.

    fast=True (default) runs the core security packs with parallelism and
    excludes; fast=False (Deep scan) also adds the heavier supply-chain pack.
    """
    print("[*] Running Semgrep security scan...")
    # Core packs cover OWASP/CWE/secrets. supply-chain overlaps the OSV
    # dependency scanner and is the slowest pack, so it's Deep-scan only.
    rulesets = ["p/owasp-top-ten", "p/cwe-top-25", "p/secrets"]
    if not fast:
        rulesets.append("p/supply-chain")

    # Performance flags: parallel jobs, no telemetry round-trip, per-rule
    # timeout, skip huge files, and exclude vendored/build directories.
    cmd = [
        "semgrep", "scan", "--json", "--quiet",
        "--metrics=off",
        "--jobs", str(os.cpu_count() or 2),
        "--timeout", "30",
        "--timeout-threshold", "3",
        "--max-target-bytes", "2000000",
    ]
    for ex in ("node_modules", "vendor", "dist", "build", ".git", ".venv", "venv"):
        cmd += ["--exclude", ex]
    for rs in rulesets:
        cmd += ["--config", rs]
    cmd.append(repo_path)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    except subprocess.TimeoutExpired:
        print("[!] Semgrep timed out; returning no findings")
        return []

    findings: list[Finding] = []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Try stderr if stdout was empty
        try:
            data = json.loads(result.stderr)
        except json.JSONDecodeError:
            return findings

    for r in data.get("results", []):
        meta = r.get("extra", {})
        metadata = meta.get("metadata", {})

        # Extract CWE(s)
        cwes = metadata.get("cwe", [])
        if isinstance(cwes, str):
            cwes = [cwes]
        primary_cwe = cwes[0] if cwes else None

        # Normalise CWE id (e.g. "CWE-89: SQL Injection" -> "CWE-89")
        if primary_cwe:
            primary_cwe = primary_cwe.split(":")[0].strip()

        attack_info = CWE_TO_ATTACK.get(primary_cwe, {}) if primary_cwe else {}

        rel_file = r.get("path", "")
        try:
            rel_file = str(Path(rel_file).relative_to(repo_path))
        except ValueError:
            pass

        findings.append(Finding(
            rule_id=r.get("check_id", "unknown"),
            message=meta.get("message", ""),
            severity=meta.get("severity", "INFO").upper(),
            file=rel_file,
            line_start=r.get("start", {}).get("line", 0),
            line_end=r.get("end", {}).get("line", 0),
            code_snippet=meta.get("lines", ""),
            cwe=primary_cwe,
            attack_technique=attack_info.get("technique"),
            attack_tactic=attack_info.get("tactic"),
            attack_name=attack_info.get("name"),
        ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


def check_dependency_vulns(repo_path: str) -> list[dict]:
    """Check for known CVEs in dependencies using pip-audit / npm audit."""
    vulns: list[dict] = []

    # Python
    req_files = list(Path(repo_path).rglob("requirements*.txt")) + \
                list(Path(repo_path).rglob("pyproject.toml"))
    import shutil as _sh2
    if req_files and _sh2.which("pip-audit"):
        print("[*] Running pip-audit for Python dependencies...")
        result = subprocess.run(
            ["pip-audit", "--format", "json", "-r", str(req_files[0])],
            capture_output=True, text=True, cwd=repo_path
        )
        try:
            data = json.loads(result.stdout)
            for dep in data.get("dependencies", []):
                for vuln in dep.get("vulns", []):
                    vulns.append({
                        "ecosystem": "python",
                        "package": dep.get("name"),
                        "version": dep.get("version"),
                        "vuln_id": vuln.get("id"),
                        "description": vuln.get("description", ""),
                        "fix_versions": vuln.get("fix_versions", []),
                    })
        except (json.JSONDecodeError, KeyError):
            pass

    # Node — skip silently if npm is not on PATH
    import shutil as _sh
    pkg_files = list(Path(repo_path).rglob("package.json"))
    pkg_files = [p for p in pkg_files if "node_modules" not in str(p)]
    if pkg_files and _sh.which("npm"):
        print("[*] Running npm audit for Node dependencies...")
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, cwd=str(pkg_files[0].parent)
        )
        try:
            data = json.loads(result.stdout)
            for name, vuln in data.get("vulnerabilities", {}).items():
                vulns.append({
                    "ecosystem": "npm",
                    "package": name,
                    "severity": vuln.get("severity"),
                    "vuln_id": vuln.get("via", [{}])[0].get("source") if vuln.get("via") else None,
                    "description": vuln.get("via", [{}])[0].get("title", "") if vuln.get("via") else "",
                    "fix_available": vuln.get("fixAvailable", False),
                })
        except (json.JSONDecodeError, KeyError):
            pass
    elif pkg_files:
        print("[*] npm not found — skipping Node dependency audit")

    return vulns


def get_pr_changed_files(repo_path: str, base_branch: str = "main") -> list[str]:
    """Run git diff --name-only origin/{base_branch}...HEAD and return changed file paths."""
    result = subprocess.run(
        ["git", "diff", "--name-only", f"origin/{base_branch}...HEAD"],
        capture_output=True, text=True, cwd=repo_path,
    )
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return files


def run_semgrep_diff(repo_path: str, changed_files: list[str]) -> list[Finding]:
    """Run semgrep only on the provided changed_files list."""
    if not changed_files:
        return []

    # Resolve to absolute paths that exist
    abs_files = []
    for f in changed_files:
        abs_path = str(Path(repo_path) / f)
        if Path(abs_path).exists():
            abs_files.append(abs_path)

    if not abs_files:
        return []

    rulesets = ["p/owasp-top-ten", "p/cwe-top-25", "p/secrets", "p/supply-chain"]
    cmd = ["semgrep", "scan", "--json", "--quiet"]
    for rs in rulesets:
        cmd += ["--config", rs]
    cmd += abs_files

    result = subprocess.run(cmd, capture_output=True, text=True)

    findings: list[Finding] = []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        try:
            data = json.loads(result.stderr)
        except json.JSONDecodeError:
            return findings

    # Reuse the same parsing logic as run_semgrep
    for r in data.get("results", []):
        meta = r.get("extra", {})
        metadata = meta.get("metadata", {})
        cwes = metadata.get("cwe", [])
        if isinstance(cwes, str):
            cwes = [cwes]
        primary_cwe = cwes[0] if cwes else None
        if primary_cwe:
            primary_cwe = primary_cwe.split(":")[0].strip()
        attack_info = CWE_TO_ATTACK.get(primary_cwe, {}) if primary_cwe else {}
        rel_file = r.get("path", "")
        try:
            rel_file = str(Path(rel_file).relative_to(repo_path))
        except ValueError:
            pass
        findings.append(Finding(
            rule_id=r.get("check_id", "unknown"),
            message=meta.get("message", ""),
            severity=meta.get("severity", "INFO").upper(),
            file=rel_file,
            line_start=r.get("start", {}).get("line", 0),
            line_end=r.get("end", {}).get("line", 0),
            code_snippet=meta.get("lines", ""),
            cwe=primary_cwe,
            attack_technique=attack_info.get("technique"),
            attack_tactic=attack_info.get("tactic"),
            attack_name=attack_info.get("name"),
        ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


def analyze_pr(repo_url: str, base_branch: str = "main",
               workdir: Optional[str] = None) -> AnalysisResult:
    """Like analyze() but clones the repo and only scans files changed vs base_branch."""
    repo_path = clone_repo(repo_url, workdir)
    result = AnalysisResult(repo_url=repo_url, repo_path=repo_path,
                            pr_diff_mode=True)

    try:
        # Fetch the base branch so git diff has something to compare against
        subprocess.run(
            ["git", "fetch", "origin", base_branch],
            capture_output=True, cwd=repo_path,
        )
        result.changed_files = get_pr_changed_files(repo_path, base_branch)
        print(f"[*] PR diff mode: {len(result.changed_files)} changed files")
        result.findings = run_semgrep_diff(repo_path, result.changed_files)
        result.dependency_vulns = check_dependency_vulns(repo_path)
    except Exception as e:
        result.scan_errors.append(str(e))

    return result


def analyze(repo_url: str, workdir: Optional[str] = None) -> AnalysisResult:
    """Full static analysis pipeline for a GitHub repo."""
    repo_path = clone_repo(repo_url, workdir)
    result = AnalysisResult(repo_url=repo_url, repo_path=repo_path)

    try:
        result.findings = run_semgrep(repo_path)
        result.dependency_vulns = check_dependency_vulns(repo_path)
    except Exception as e:
        result.scan_errors.append(str(e))

    return result
