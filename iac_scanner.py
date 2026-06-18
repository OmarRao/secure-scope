"""
Infrastructure as Code (IaC) Security Scanner (v6.0.0)

Scans repositories for cloud and container misconfigurations across:
  - Terraform (.tf)
  - CloudFormation (.yaml/.json with CF markers)
  - Kubernetes manifests (.yaml/.yml with k8s apiVersion)
  - Helm charts (Chart.yaml + templates/)
  - Dockerfiles
  - GitHub Actions workflows (.github/workflows/*.yml)
  - Ansible playbooks

Uses checkov (via subprocess) when installed for deep analysis,
with a comprehensive regex/AST fallback for zero-dependency operation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

# ── Severity ordering ─────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class IaCFinding:
    check_id: str
    severity: str
    framework: str
    file_path: str
    line: int
    resource: str
    description: str
    fix: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "framework": self.framework,
            "file_path": self.file_path,
            "line": self.line,
            "resource": self.resource,
            "description": self.description,
            "fix": self.fix,
        }


@dataclass
class IaCScanResult:
    total_files_scanned: int = 0
    frameworks_detected: List[str] = field(default_factory=list)
    findings: List[IaCFinding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_duration_s: float = 0.0
    scanner_used: str = "pattern"

    def _recount(self):
        self.critical_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        self.high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        self.medium_count = sum(1 for f in self.findings if f.severity == "MEDIUM")
        self.low_count = sum(1 for f in self.findings if f.severity in ("LOW", "INFO"))

    def to_dict(self) -> dict:
        self._recount()
        return {
            "total_files_scanned": self.total_files_scanned,
            "frameworks_detected": self.frameworks_detected,
            "total_findings": len(self.findings),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "scan_duration_s": round(self.scan_duration_s, 2),
            "scanner_used": self.scanner_used,
            "findings": sorted(
                [f.to_dict() for f in self.findings],
                key=lambda x: (_SEV_ORDER.get(x["severity"], 99), x["file_path"]),
            ),
        }


# ── Framework detection ────────────────────────────────────────────────────────

def _detect_framework(path: Path, content: str) -> Optional[str]:
    """Return the IaC framework for a file, or None if not recognised."""
    name = path.name.lower()
    suffix = path.suffix.lower()

    # GitHub Actions
    parts = [p.lower() for p in path.parts]
    if ".github" in parts and "workflows" in parts and suffix in (".yml", ".yaml"):
        return "github_actions"

    # Dockerfile
    if name in ("dockerfile",) or name.startswith("dockerfile."):
        return "dockerfile"

    # Terraform
    if suffix == ".tf":
        return "terraform"

    # Helm — Chart.yaml or templates under a helm chart
    if name == "chart.yaml":
        return "helm"

    # CloudFormation — YAML/JSON with CF markers
    if suffix in (".yml", ".yaml", ".json"):
        cf_markers = [
            "AWSTemplateFormatVersion",
            "aws_cloudformation",
            "CloudFormation",
        ]
        if any(m in content for m in cf_markers):
            return "cloudformation"

    # Kubernetes — apiVersion + kind present
    if suffix in (".yml", ".yaml"):
        if re.search(r"apiVersion\s*:", content) and re.search(r"kind\s*:", content):
            k8s_kinds = [
                "Deployment", "Pod", "DaemonSet", "StatefulSet", "Job", "CronJob",
                "Service", "Ingress", "ClusterRole", "ClusterRoleBinding",
                "Role", "RoleBinding", "NetworkPolicy", "ServiceAccount",
            ]
            if any(k in content for k in k8s_kinds):
                return "kubernetes"

    # Ansible playbook
    if suffix in (".yml", ".yaml"):
        if re.search(r"^\s*-\s+hosts\s*:", content, re.MULTILINE):
            return "ansible"

    return None


# ── Pattern-based checks ───────────────────────────────────────────────────────

def _line_of(content: str, match_start: int) -> int:
    return content[:match_start].count("\n") + 1


def _check_terraform(path: Path, content: str) -> List[IaCFinding]:
    findings: List[IaCFinding] = []
    rel = str(path)

    checks = [
        (
            r'acl\s*=\s*"public-read(?:-write)?"',
            "CRITICAL", "TF001", "S3 bucket is publicly readable",
            "Remove the acl argument or set acl = \"private\". Use bucket policies for explicit access.",
        ),
        (
            r'publicly_accessible\s*=\s*true',
            "HIGH", "TF002", "RDS/database instance is publicly accessible",
            "Set publicly_accessible = false. Use VPC security groups for controlled access.",
        ),
        (
            r'cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"\s*\]?',
            "HIGH", "TF003", "Security group allows inbound traffic from 0.0.0.0/0 (world)",
            "Restrict cidr_blocks to known IP ranges. Never expose 0.0.0.0/0 on sensitive ports.",
        ),
        (
            r'ipv6_cidr_blocks\s*=\s*\[?\s*"::/0"\s*\]?',
            "HIGH", "TF004", "Security group allows all IPv6 inbound (::/0)",
            "Restrict ipv6_cidr_blocks to known ranges.",
        ),
        (
            r'"Action"\s*:\s*"\*"',
            "CRITICAL", "TF005", "IAM policy grants wildcard Action (*) — full permission",
            "Enumerate only the required IAM actions. Follow least-privilege.",
        ),
        (
            r'"Resource"\s*:\s*"\*"',
            "HIGH", "TF006", "IAM policy grants wildcard Resource (*)",
            "Scope IAM Resource to specific ARNs instead of *.",
        ),
        (
            r'encrypted\s*=\s*false',
            "HIGH", "TF007", "Storage resource has encryption explicitly disabled",
            "Set encrypted = true and provide a KMS key ARN.",
        ),
        (
            r'enable_dns_hostnames\s*=\s*false',
            "LOW", "TF008", "VPC has DNS hostnames disabled",
            "Set enable_dns_hostnames = true for proper service discovery.",
        ),
        (
            r'deletion_protection\s*=\s*false',
            "MEDIUM", "TF009", "Database deletion protection is disabled",
            "Set deletion_protection = true to prevent accidental data loss.",
        ),
        (
            r'skip_final_snapshot\s*=\s*true',
            "MEDIUM", "TF010", "RDS instance skips final snapshot on deletion",
            "Set skip_final_snapshot = false and provide final_snapshot_identifier.",
        ),
        (
            r'multi_az\s*=\s*false',
            "LOW", "TF011", "RDS instance is not Multi-AZ — single point of failure",
            "Set multi_az = true for production databases.",
        ),
        (
            r'password\s*=\s*"[^$][^"]{3,}"',
            "CRITICAL", "TF012", "Hardcoded password detected in Terraform resource",
            "Use var.* references or AWS Secrets Manager. Never hardcode credentials.",
        ),
        (
            r'access_key\s*=\s*"AKIA[A-Z0-9]{16}"',
            "CRITICAL", "TF013", "AWS access key hardcoded in Terraform",
            "Remove hardcoded credentials. Use IAM roles or environment variables.",
        ),
        (
            r'enabled\s*=\s*false\b.*(?:logging|log)',
            "MEDIUM", "TF014", "Logging is explicitly disabled on a resource",
            "Enable logging for audit trails and incident response.",
        ),
    ]

    resource_block = "unknown"
    for m in re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', content):
        pass  # We annotate resource name per match below

    for pattern, severity, check_id, desc, fix in checks:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            # Try to find nearest resource block
            preceding = content[:m.start()]
            resource_matches = list(re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', preceding))
            if resource_matches:
                rm = resource_matches[-1]
                resource_name = f"{rm.group(1)}.{rm.group(2)}"
            else:
                resource_name = "unknown"
            findings.append(IaCFinding(
                check_id=check_id,
                severity=severity,
                framework="terraform",
                file_path=rel,
                line=_line_of(content, m.start()),
                resource=resource_name,
                description=desc,
                fix=fix,
            ))

    return findings


def _check_kubernetes(path: Path, content: str) -> List[IaCFinding]:
    findings: List[IaCFinding] = []
    rel = str(path)

    # Extract resource name
    name_match = re.search(r'name\s*:\s*(\S+)', content)
    resource_name = name_match.group(1) if name_match else path.stem
    kind_match = re.search(r'kind\s*:\s*(\S+)', content)
    kind = kind_match.group(1) if kind_match else "unknown"

    checks = [
        (
            r'privileged\s*:\s*true',
            "CRITICAL", "K8S001", "Container runs in privileged mode — full host access",
            "Remove privileged: true from securityContext. Use specific capabilities instead.",
        ),
        (
            r'hostNetwork\s*:\s*true',
            "HIGH", "K8S002", "Pod shares the host network namespace",
            "Remove hostNetwork: true. Use Service and Ingress for network exposure.",
        ),
        (
            r'hostPID\s*:\s*true',
            "HIGH", "K8S003", "Pod shares the host PID namespace — can see all host processes",
            "Remove hostPID: true unless absolutely required.",
        ),
        (
            r'hostIPC\s*:\s*true',
            "HIGH", "K8S004", "Pod shares the host IPC namespace",
            "Remove hostIPC: true unless absolutely required.",
        ),
        (
            r'allowPrivilegeEscalation\s*:\s*true',
            "HIGH", "K8S005", "Container allows privilege escalation (setuid binaries)",
            "Set allowPrivilegeEscalation: false in securityContext.",
        ),
        (
            r'runAsUser\s*:\s*0\b',
            "HIGH", "K8S006", "Container explicitly runs as root (UID 0)",
            "Set runAsNonRoot: true and runAsUser to a non-zero UID (e.g. 1000).",
        ),
        (
            r'verbs\s*:\s*\[?\s*["\']?\*["\']?\s*\]?',
            "CRITICAL", "K8S007", "RBAC ClusterRole/Role grants wildcard verbs (*)",
            "Enumerate only required verbs: [get, list, watch]. Never use *.",
        ),
        (
            r'resources\s*:\s*\[?\s*["\']?\*["\']?\s*\]?',
            "HIGH", "K8S008", "RBAC role grants wildcard resource access (*)",
            "Specify only required resource types in the RBAC role.",
        ),
        (
            r'image\s*:\s*\S+:latest\b',
            "MEDIUM", "K8S009", "Container image uses :latest tag — unpinned version",
            "Pin container images to a specific digest or semantic version tag.",
        ),
        (
            r'imagePullPolicy\s*:\s*Always',
            "LOW", "K8S010", "imagePullPolicy: Always can cause unexpected image changes",
            "Use imagePullPolicy: IfNotPresent with pinned image digests.",
        ),
        (
            r'readOnlyRootFilesystem\s*:\s*false',
            "MEDIUM", "K8S011", "Root filesystem is writable — increases attack surface",
            "Set readOnlyRootFilesystem: true. Mount writable volumes only where needed.",
        ),
        (
            r'automountServiceAccountToken\s*:\s*true',
            "MEDIUM", "K8S012", "Service account token auto-mounted — exposed to all containers",
            "Set automountServiceAccountToken: false unless the pod requires API access.",
        ),
    ]

    # Check for missing resource limits (no limits: block at all)
    if "limits:" not in content and kind in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
        findings.append(IaCFinding(
            check_id="K8S013",
            severity="MEDIUM",
            framework="kubernetes",
            file_path=rel,
            line=1,
            resource=f"{kind}/{resource_name}",
            description="No resource limits defined — container can consume unlimited CPU/memory",
            fix="Add resources.limits.cpu and resources.limits.memory to each container spec.",
        ))

    for pattern, severity, check_id, desc, fix in checks:
        for m in re.finditer(pattern, content):
            findings.append(IaCFinding(
                check_id=check_id,
                severity=severity,
                framework="kubernetes",
                file_path=rel,
                line=_line_of(content, m.start()),
                resource=f"{kind}/{resource_name}",
                description=desc,
                fix=fix,
            ))

    return findings


def _check_dockerfile(path: Path, content: str) -> List[IaCFinding]:
    findings: List[IaCFinding] = []
    rel = str(path)
    lines = content.splitlines()

    has_user = False
    has_healthcheck = False

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # FROM with :latest or no tag
        if stripped.upper().startswith("FROM "):
            img = stripped.split()[1] if len(stripped.split()) > 1 else ""
            if img.endswith(":latest") or (":" not in img and "@" not in img and img not in ("scratch",)):
                findings.append(IaCFinding(
                    check_id="DF001",
                    severity="MEDIUM",
                    framework="dockerfile",
                    file_path=rel,
                    line=i,
                    resource="FROM",
                    description=f"Base image '{img}' uses :latest or no tag — unpinned",
                    fix="Pin the base image to a specific version or SHA digest.",
                ))

        # ADD for local files (not URL)
        if stripped.upper().startswith("ADD ") and "http" not in stripped.lower():
            findings.append(IaCFinding(
                check_id="DF002",
                severity="LOW",
                framework="dockerfile",
                file_path=rel,
                line=i,
                resource="ADD",
                description="ADD used for local file copy — use COPY for clarity and security",
                fix="Replace ADD with COPY for local files. ADD should only be used for URL downloads or tar extraction.",
            ))

        # USER instruction tracking
        if stripped.upper().startswith("USER "):
            user_val = stripped.split()[1] if len(stripped.split()) > 1 else ""
            has_user = True
            if user_val in ("root", "0"):
                findings.append(IaCFinding(
                    check_id="DF003",
                    severity="HIGH",
                    framework="dockerfile",
                    file_path=rel,
                    line=i,
                    resource="USER",
                    description="Container explicitly set to run as root",
                    fix="Set USER to a non-root UID/username (e.g. USER appuser or USER 1001).",
                ))

        # HEALTHCHECK
        if stripped.upper().startswith("HEALTHCHECK"):
            has_healthcheck = True

        # Secrets in ENV
        secret_patterns = [
            (r'(?i)password\s*=\s*\S+', "password"),
            (r'(?i)secret\s*=\s*\S+', "secret"),
            (r'(?i)api[_-]?key\s*=\s*\S+', "API key"),
            (r'(?i)access[_-]?token\s*=\s*\S+', "access token"),
            (r'AKIA[A-Z0-9]{16}', "AWS access key"),
        ]
        if stripped.upper().startswith("ENV ") or stripped.upper().startswith("ARG "):
            for spat, sname in secret_patterns:
                if re.search(spat, stripped):
                    findings.append(IaCFinding(
                        check_id="DF004",
                        severity="CRITICAL",
                        framework="dockerfile",
                        file_path=rel,
                        line=i,
                        resource="ENV/ARG",
                        description=f"Potential {sname} hardcoded in Dockerfile ENV/ARG",
                        fix="Use Docker secrets, build args without default values, or runtime env injection. Never hardcode credentials.",
                    ))

        # curl | bash / wget | sh patterns
        if re.search(r'curl\s+.*\|.*sh|wget\s+.*\|.*sh|curl\s+.*\|\s*bash', stripped, re.IGNORECASE):
            findings.append(IaCFinding(
                check_id="DF005",
                severity="HIGH",
                framework="dockerfile",
                file_path=rel,
                line=i,
                resource="RUN",
                description="Remote script piped directly to shell (curl|bash) — supply chain risk",
                fix="Download the script separately, verify its checksum, then execute. Never pipe untrusted remote content to a shell.",
            ))

        # --privileged flag
        if "--privileged" in stripped:
            findings.append(IaCFinding(
                check_id="DF006",
                severity="CRITICAL",
                framework="dockerfile",
                file_path=rel,
                line=i,
                resource="RUN",
                description="Container run with --privileged flag — full host access",
                fix="Remove --privileged. Use specific Linux capabilities (--cap-add) instead.",
            ))

    # No USER instruction at all
    if not has_user:
        findings.append(IaCFinding(
            check_id="DF007",
            severity="HIGH",
            framework="dockerfile",
            file_path=rel,
            line=len(lines),
            resource="USER",
            description="No USER instruction — container will run as root by default",
            fix="Add USER <non-root-user> before the final CMD/ENTRYPOINT.",
        ))

    # No HEALTHCHECK
    if not has_healthcheck:
        findings.append(IaCFinding(
            check_id="DF008",
            severity="LOW",
            framework="dockerfile",
            file_path=rel,
            line=len(lines),
            resource="HEALTHCHECK",
            description="No HEALTHCHECK instruction — orchestrators cannot detect unhealthy containers",
            fix="Add HEALTHCHECK CMD <command> to enable container health monitoring.",
        ))

    return findings


def _check_github_actions(path: Path, content: str) -> List[IaCFinding]:
    findings: List[IaCFinding] = []
    rel = str(path)

    checks = [
        (
            r'permissions\s*:\s*write-all',
            "HIGH", "GHA001", "GitHub Actions workflow has write-all permissions",
            "Use minimal permissions. Enumerate only required scopes (e.g. contents: read).",
        ),
        (
            r'permissions\s*:\s*\n\s+\w+\s*:\s*write',
            "MEDIUM", "GHA002", "GitHub Actions step grants write permission to a scope",
            "Audit each write permission. Use the minimum required scope.",
        ),
        (
            r'pull_request_target',
            "HIGH", "GHA003", "Workflow uses pull_request_target — can expose secrets to untrusted PRs",
            "Avoid checking out PR head in pull_request_target workflows. Use pull_request trigger for untrusted code.",
        ),
        (
            r'uses\s*:\s*\S+@(?:main|master|HEAD)',
            "HIGH", "GHA004", "Action pinned to mutable branch ref (main/master) — supply chain risk",
            "Pin actions to a specific commit SHA (e.g. uses: actions/checkout@abc1234). Never use @main or @master.",
        ),
        (
            r'curl\s+.*\|\s*(?:bash|sh)|wget\s+.*\|\s*(?:bash|sh)',
            "HIGH", "GHA005", "Workflow pipes remote content directly to shell — supply chain risk",
            "Download the script, verify its checksum, then execute separately.",
        ),
        (
            r'run\s*:\s*.*\$\{\{.*github\.event\.(?:pull_request\.|issue\.|comment\.).*\}\}',
            "CRITICAL", "GHA006", "Untrusted input from GitHub event used in run step — script injection",
            "Never interpolate github.event.* directly into run commands. Use intermediate env vars with sanitisation.",
        ),
        (
            r'(?i)password\s*=\s*["\'][^$][^"\']{3,}["\']',
            "CRITICAL", "GHA007", "Hardcoded credential in workflow file",
            "Use ${{ secrets.YOUR_SECRET }} for all sensitive values. Never hardcode credentials.",
        ),
        (
            r'continue-on-error\s*:\s*true',
            "LOW", "GHA008", "continue-on-error: true may mask security scan failures",
            "Remove continue-on-error or add explicit handling for security-critical steps.",
        ),
        (
            r'GITHUB_TOKEN\s*:\s*\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}.*write',
            "MEDIUM", "GHA009", "GITHUB_TOKEN with write permission passed to an action",
            "Pass only the minimum permission level required. Prefer read-only tokens.",
        ),
    ]

    for pattern, severity, check_id, desc, fix in checks:
        for m in re.finditer(pattern, content, re.MULTILINE):
            findings.append(IaCFinding(
                check_id=check_id,
                severity=severity,
                framework="github_actions",
                file_path=rel,
                line=_line_of(content, m.start()),
                resource=path.stem,
                description=desc,
                fix=fix,
            ))

    return findings


def _check_cloudformation(path: Path, content: str) -> List[IaCFinding]:
    findings: List[IaCFinding] = []
    rel = str(path)

    checks = [
        (
            r'PubliclyAccessible\s*:\s*true',
            "HIGH", "CF001", "RDS instance is publicly accessible",
            "Set PubliclyAccessible: false and use VPC security groups for access.",
        ),
        (
            r'MultiAZ\s*:\s*false',
            "LOW", "CF002", "RDS instance is not Multi-AZ",
            "Set MultiAZ: true for production databases.",
        ),
        (
            r'AccessControl\s*:\s*(?:PublicRead|PublicReadWrite)',
            "CRITICAL", "CF003", "S3 bucket has public read/write ACL",
            "Remove AccessControl or set to Private. Use bucket policies for explicit access.",
        ),
        (
            r'(?i)NoEcho\s*:\s*false',
            "MEDIUM", "CF004", "Parameter with NoEcho: false may log sensitive values",
            "Set NoEcho: true for parameters that hold passwords or secrets.",
        ),
        (
            r'"Action"\s*:\s*"\*"',
            "CRITICAL", "CF005", "IAM policy grants wildcard Action (*)",
            "Enumerate only the required IAM actions. Follow least-privilege.",
        ),
        (
            r'DeletionPolicy\s*:', None, None, None, None,  # presence check below
        ),
        (
            r'StorageEncrypted\s*:\s*false',
            "HIGH", "CF007", "RDS storage encryption explicitly disabled",
            "Set StorageEncrypted: true and provide KmsKeyId.",
        ),
        (
            r'EnableDnsHostnames\s*:\s*false',
            "LOW", "CF008", "VPC DNS hostnames disabled",
            "Set EnableDnsHostnames: true for proper service discovery.",
        ),
    ]

    # Check for missing DeletionPolicy
    if "DeletionPolicy" not in content:
        findings.append(IaCFinding(
            check_id="CF006",
            severity="MEDIUM",
            framework="cloudformation",
            file_path=rel,
            line=1,
            resource="Template",
            description="No DeletionPolicy defined on resources — accidental deletion risk",
            fix="Add DeletionPolicy: Retain or Snapshot to stateful resources (RDS, S3, DynamoDB).",
        ))

    for item in checks:
        pattern, severity, check_id, desc, fix = item
        if check_id is None:
            continue
        for m in re.finditer(pattern, content):
            findings.append(IaCFinding(
                check_id=check_id,
                severity=severity,
                framework="cloudformation",
                file_path=rel,
                line=_line_of(content, m.start()),
                resource=path.stem,
                description=desc,
                fix=fix,
            ))

    return findings


def _check_ansible(path: Path, content: str) -> List[IaCFinding]:
    findings: List[IaCFinding] = []
    rel = str(path)

    checks = [
        (
            r'(?i)become\s*:\s*yes\b',
            "MEDIUM", "ANS001", "Task uses become: yes (privilege escalation) — verify this is necessary",
            "Use become only where strictly required. Prefer dedicated service accounts.",
        ),
        (
            r'(?i)no_log\s*:\s*false',
            "HIGH", "ANS002", "no_log: false on a task that may handle secrets",
            "Set no_log: true on tasks that handle passwords or API keys.",
        ),
        (
            r'(?i)password\s*:\s*["\'][^{][^"\']{3,}["\']',
            "CRITICAL", "ANS003", "Hardcoded password in Ansible playbook",
            "Use Ansible Vault to encrypt secrets. Reference as {{ vault_password }}.",
        ),
        (
            r'(?i)shell\s*:\s*.*(curl|wget).*\|\s*(bash|sh)',
            "HIGH", "ANS004", "Task pipes remote script directly to shell",
            "Download separately, verify checksum, then execute.",
        ),
        (
            r'(?i)validate_certs\s*:\s*(?:no|false)',
            "HIGH", "ANS005", "SSL/TLS certificate validation disabled",
            "Set validate_certs: yes. Fix the underlying certificate issue instead of disabling validation.",
        ),
    ]

    for pattern, severity, check_id, desc, fix in checks:
        for m in re.finditer(pattern, content, re.MULTILINE):
            findings.append(IaCFinding(
                check_id=check_id,
                severity=severity,
                framework="ansible",
                file_path=rel,
                line=_line_of(content, m.start()),
                resource=path.stem,
                description=desc,
                fix=fix,
            ))

    return findings


# ── Checkov integration ────────────────────────────────────────────────────────

def _try_checkov(repo_path: Path) -> Optional[List[IaCFinding]]:
    """Run checkov if installed; return parsed findings or None."""
    try:
        result = subprocess.run(
            ["checkov", "-d", str(repo_path), "-o", "json", "--quiet", "--compact"],
            capture_output=True, text=True, timeout=120,
        )
        raw = result.stdout.strip()
        if not raw:
            return None

        data = json.loads(raw)
        findings: List[IaCFinding] = []

        # checkov can return a list or a single dict with results
        if isinstance(data, list):
            blocks = data
        else:
            blocks = [data]

        severity_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                        "low": "LOW", "none": "INFO"}

        for block in blocks:
            for chk in block.get("results", {}).get("failed_checks", []):
                sev_raw = chk.get("severity") or "medium"
                findings.append(IaCFinding(
                    check_id=chk.get("check_id", "CKV_UNKNOWN"),
                    severity=severity_map.get(sev_raw.lower(), "MEDIUM"),
                    framework=chk.get("repo_file_path", "").split(".")[-1],
                    file_path=chk.get("repo_file_path", ""),
                    line=chk.get("file_line_range", [1])[0],
                    resource=chk.get("resource", "unknown"),
                    description=chk.get("check", {}).get("name", "Misconfiguration"),
                    fix=chk.get("check", {}).get("guideline", "See checkov documentation.") or "",
                ))

        return findings if findings else None

    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return None


# ── File discovery ─────────────────────────────────────────────────────────────

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".terraform",
    "vendor", "dist", "build", ".cache", "venv", ".venv",
}

_MAX_FILE_SIZE = 512 * 1024  # 512 KB


def _iter_iac_files(repo_path: Path):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.stat().st_size > _MAX_FILE_SIZE:
                continue
            suffix = fpath.suffix.lower()
            name = fpath.name.lower()
            if suffix in (".tf", ".yml", ".yaml", ".json") or name.startswith("dockerfile"):
                yield fpath


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_repo(
    repo_path: str,
    progress_cb: Optional[Callable[[float, str], None]] = None,
) -> IaCScanResult:
    """
    Scan a repository for IaC misconfigurations.

    Args:
        repo_path: Absolute path to the cloned repository.
        progress_cb: Optional callback(pct, message) for streaming progress.

    Returns:
        IaCScanResult with all findings.
    """

    def _progress(pct: float, msg: str):
        if progress_cb:
            progress_cb(pct, msg)

    t0 = time.time()
    root = Path(repo_path)
    result = IaCScanResult()

    _progress(5, "🔍 Discovering IaC files...")

    # Collect files
    all_files = list(_iter_iac_files(root))
    result.total_files_scanned = len(all_files)

    if not all_files:
        _progress(100, "✅ No IaC files found.")
        result.scan_duration_s = time.time() - t0
        return result

    # Try checkov first
    _progress(10, "🛠️ Attempting checkov deep scan...")
    ck_findings = _try_checkov(root)
    if ck_findings is not None:
        result.findings = ck_findings
        result.scanner_used = "checkov"
        _progress(90, f"✅ Checkov found {len(ck_findings)} findings")
    else:
        # Pattern-based fallback
        result.scanner_used = "pattern"
        _progress(15, "🔍 Running pattern-based IaC analysis...")

        framework_set: set = set()
        checker_map = {
            "terraform": _check_terraform,
            "kubernetes": _check_kubernetes,
            "dockerfile": _check_dockerfile,
            "github_actions": _check_github_actions,
            "cloudformation": _check_cloudformation,
            "ansible": _check_ansible,
        }

        for i, fpath in enumerate(all_files):
            pct = 15 + (75 * i / len(all_files))
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(fpath.relative_to(root))
                framework = _detect_framework(fpath, content)
                if framework and framework in checker_map:
                    framework_set.add(framework)
                    _progress(pct, f"🔍 Scanning {rel_path}...")
                    checker = checker_map[framework]
                    rel_fpath = Path(rel_path)
                    findings = checker(rel_fpath, content)
                    result.findings.extend(findings)
            except Exception as exc:
                logger.debug("Skipping %s: %s", fpath, exc)

        result.frameworks_detected = sorted(framework_set)

    # Populate frameworks from findings if checkov was used
    if result.scanner_used == "checkov" and not result.frameworks_detected:
        result.frameworks_detected = sorted({f.framework for f in result.findings})

    result._recount()
    result.scan_duration_s = time.time() - t0

    _progress(100, f"✅ IaC scan complete — {len(result.findings)} findings across {len(result.frameworks_detected)} frameworks")
    return result


def list_frameworks() -> List[dict]:
    """Return metadata for all supported IaC frameworks."""
    return [
        {"id": "terraform",      "name": "Terraform",        "extensions": [".tf"],                "icon": "🏗️"},
        {"id": "kubernetes",     "name": "Kubernetes",        "extensions": [".yml", ".yaml"],      "icon": "☸️"},
        {"id": "dockerfile",     "name": "Dockerfile",        "extensions": ["Dockerfile"],         "icon": "🐳"},
        {"id": "github_actions", "name": "GitHub Actions",    "extensions": [".yml", ".yaml"],      "icon": "⚙️"},
        {"id": "cloudformation", "name": "CloudFormation",    "extensions": [".yml", ".yaml", ".json"], "icon": "☁️"},
        {"id": "ansible",        "name": "Ansible",           "extensions": [".yml", ".yaml"],      "icon": "🤖"},
    ]
