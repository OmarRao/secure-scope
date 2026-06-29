"""
Secrets scanner (v3.0.0) — self-contained, zero external dependencies.

Detects hardcoded secrets and credentials across the working tree and, when
requested, the full git commit history. Every match is classified into a
category, assigned a severity, and annotated with a plain-English blast-radius
description so security teams can prioritise rotation by real impact.

Public API (consumed by ui/server.py):
    scan_repo(repo_path, include_history=True, entropy_check=True, progress_cb=None)
        -> SecretScanResult
    list_pattern_categories() -> list[dict]

SecretScanResult.to_dict() shape (consumed by ui/templates/report.html):
    {
      "total_findings": int,
      "critical_count": int, "high_count": int,
      "medium_count": int,   "low_count": int,
      "files_scanned": int,  "commits_scanned": int,
      "findings": [ {severity, category, pattern_name, description,
                     blast_radius, file, line, commit}, ... ],
      "error": str | None,
    }
"""

from __future__ import annotations

import math
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

# ── Pattern library ──────────────────────────────────────────────────────────
# Each pattern: (name, category, severity, blast_radius, compiled regex)


@dataclass
class _Pattern:
    name: str
    category: str
    severity: str
    blast_radius: str
    regex: "re.Pattern"


def _p(name, category, severity, blast_radius, pattern, flags=0):
    return _Pattern(name, category, severity, blast_radius, re.compile(pattern, flags))


_PATTERNS: list[_Pattern] = [
    # ── Cloud ────────────────────────────────────────────────────────────────
    _p("AWS Access Key ID", "Cloud", "CRITICAL",
       "Full AWS account access — IAM, S3, EC2, Lambda, RDS depending on the key's policy.",
       r"\bAKIA[0-9A-Z]{16}\b"),
    _p("AWS Secret Access Key", "Cloud", "CRITICAL",
       "Paired with an access key ID, grants programmatic AWS API access.",
       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    _p("Azure Storage Connection String", "Cloud", "CRITICAL",
       "Read/write access to Azure Blob/Table/Queue storage accounts.",
       r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;\"']+"),
    _p("Google Cloud API Key", "Cloud", "HIGH",
       "Access to enabled GCP APIs billed to the project (Maps, Translate, etc.).",
       r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _p("DigitalOcean Token", "Cloud", "HIGH",
       "Full control of DigitalOcean droplets, networking and billing.",
       r"\bdop_v1_[0-9a-f]{64}\b"),

    # ── AI / ML ──────────────────────────────────────────────────────────────
    _p("Anthropic API Key", "AI / ML", "HIGH",
       "Billed Claude API usage on the owner's account.",
       r"\bsk-ant-[0-9A-Za-z\-_]{20,}"),
    _p("OpenAI API Key", "AI / ML", "HIGH",
       "Billed OpenAI API usage (GPT-4o, embeddings, etc.) on the owner's account.",
       r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}"),
    _p("Groq API Key", "AI / ML", "HIGH",
       "Billed Groq inference usage on the owner's account.",
       r"\bgsk_[0-9A-Za-z]{52}\b"),
    _p("HuggingFace Token", "AI / ML", "MEDIUM",
       "Access to private models and datasets on HuggingFace Hub.",
       r"\bhf_[0-9A-Za-z]{34}\b"),

    # ── Version Control ──────────────────────────────────────────────────────
    _p("GitHub Personal Access Token", "Version Control", "CRITICAL",
       "Repository read/write, and with repo scope, code and secrets access.",
       r"\bghp_[0-9A-Za-z]{36}\b"),
    _p("GitHub Fine-Grained Token", "Version Control", "CRITICAL",
       "Scoped repository access per the token's configured permissions.",
       r"\bgithub_pat_[0-9A-Za-z_]{82}\b"),
    _p("GitHub OAuth Token", "Version Control", "HIGH",
       "OAuth-delegated access to the authorising user's repositories.",
       r"\bgho_[0-9A-Za-z]{36}\b"),
    _p("GitLab Personal Token", "Version Control", "HIGH",
       "Repository and API access scoped to the token.",
       r"\bglpat-[0-9A-Za-z_\-]{20}\b"),
    _p("npm Token", "Version Control", "HIGH",
       "Publish/unpublish packages to the npm registry as the owner.",
       r"\bnpm_[0-9A-Za-z]{36}\b"),

    # ── Payment ──────────────────────────────────────────────────────────────
    _p("Stripe Secret Key", "Payment", "CRITICAL",
       "Full access to the Stripe account — charges, refunds, customer data.",
       r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    _p("Stripe Restricted Key", "Payment", "HIGH",
       "Scoped Stripe API access per the restricted key's permissions.",
       r"\brk_live_[0-9A-Za-z]{24,}\b"),

    # ── Communications ───────────────────────────────────────────────────────
    _p("Slack Token", "Communications", "HIGH",
       "Read/post messages and access workspace data per the token's scopes.",
       r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"),
    _p("Slack Webhook", "Communications", "MEDIUM",
       "Post arbitrary messages into the configured Slack channel.",
       r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"),
    _p("Twilio API Key", "Communications", "HIGH",
       "Send SMS/voice and access Twilio account resources (billed).",
       r"\bSK[0-9a-fA-F]{32}\b"),
    _p("SendGrid API Key", "Communications", "HIGH",
       "Send email as the owner's verified domains via SendGrid.",
       r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
    _p("Mailgun API Key", "Communications", "MEDIUM",
       "Send email and access Mailgun account resources.",
       r"\bkey-[0-9a-zA-Z]{32}\b"),

    # ── Cryptographic Keys ───────────────────────────────────────────────────
    _p("Private Key", "Cryptographic Keys", "CRITICAL",
       "Private key material — impersonation, decryption, or signing as the owner.",
       r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    _p("JSON Web Token", "Cryptographic Keys", "MEDIUM",
       "May contain a valid session/identity token usable until it expires.",
       r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),

    # ── Database ─────────────────────────────────────────────────────────────
    _p("MongoDB Connection String", "Database", "CRITICAL",
       "Direct read/write access to the MongoDB database.",
       r"mongodb(?:\+srv)?://[^\s:'\"]+:[^\s@'\"]+@"),
    _p("PostgreSQL Connection String", "Database", "CRITICAL",
       "Direct read/write access to the PostgreSQL database.",
       r"postgres(?:ql)?://[^\s:'\"]+:[^\s@'\"]+@"),
    _p("MySQL Connection String", "Database", "CRITICAL",
       "Direct read/write access to the MySQL database.",
       r"mysql://[^\s:'\"]+:[^\s@'\"]+@"),
    _p("Redis Connection String", "Database", "HIGH",
       "Direct access to the Redis instance and any cached data.",
       r"redis://[^\s:'\"]*:[^\s@'\"]+@"),

    # ── Generic Credentials ──────────────────────────────────────────────────
    _p("Hardcoded Password", "Generic Credentials", "MEDIUM",
       "A hardcoded password — usable wherever the associated account is valid.",
       r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
    _p("Generic API Key / Secret", "Generic Credentials", "MEDIUM",
       "A hardcoded API key or secret token.",
       r"(?i)(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][0-9a-zA-Z/+_\-]{16,}['\"]"),
    _p("Basic Auth Credentials in URL", "Generic Credentials", "HIGH",
       "Username and password embedded in a URL — leaks via logs and history.",
       r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^:/\s'\"]+:[^@/\s'\"]+@[^\s'\"]+"),
]

# Common false-positive placeholder values to ignore for generic patterns.
_PLACEHOLDERS = re.compile(
    r"(?i)(example|changeme|placeholder|your[_-]?|xxx+|<[^>]+>|\$\{|process\.env|os\.environ|"
    r"dummy|sample|test[_-]?key|redacted|\*{3,}|null|none|true|false)"
)

_SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "env", "__pycache__",
              "dist", "build", ".next", ".cache", "site-packages", ".mypy_cache",
              ".pytest_cache", "coverage", "htmlcov"}
_SKIP_EXT = {".min.js", ".map", ".lock", ".png", ".jpg", ".jpeg", ".gif", ".svg",
             ".ico", ".pdf", ".zip", ".gz", ".tar", ".woff", ".woff2", ".ttf",
             ".eot", ".mp4", ".mp3", ".webp", ".bin", ".so", ".dll", ".class"}
_MAX_FILE_BYTES = 1_500_000
_MAX_FINDINGS = 500

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Token pattern used by the entropy heuristic.
_ENTROPY_TOKEN = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]")


@dataclass
class SecretFinding:
    severity: str
    category: str
    pattern_name: str
    description: str
    blast_radius: str
    file: str
    line: int
    commit: Optional[str] = None


@dataclass
class SecretScanResult:
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    commits_scanned: int = 0
    error: Optional[str] = None

    def _count(self, sev: str) -> int:
        return sum(1 for f in self.findings if f.severity == sev)

    def to_dict(self) -> dict:
        return {
            "total_findings": len(self.findings),
            "critical_count": self._count("CRITICAL"),
            "high_count": self._count("HIGH"),
            "medium_count": self._count("MEDIUM"),
            "low_count": self._count("LOW"),
            "files_scanned": self.files_scanned,
            "commits_scanned": self.commits_scanned,
            "findings": [asdict(f) for f in self.findings],
            "error": self.error,
        }


def list_pattern_categories() -> list:
    """Return the catalogue of detection categories and the patterns in each."""
    cats: dict[str, list] = {}
    for p in _PATTERNS:
        cats.setdefault(p.category, []).append(p.name)
    cats.setdefault("High-Entropy Strings", []).append("Shannon entropy >= 4.6")
    return [{"category": c, "patterns": sorted(set(names)), "count": len(set(names))}
            for c, names in sorted(cats.items())]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _scan_text(text: str, file_label: str, entropy_check: bool,
               commit: Optional[str] = None) -> list:
    """Scan a blob of text and return SecretFinding objects."""
    out: list = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if len(line) > 4000:  # skip absurdly long minified lines
            continue
        for p in _PATTERNS:
            if not p.regex.search(line):
                continue
            # For generic/low-confidence patterns, drop obvious placeholders.
            if p.severity == "MEDIUM" and _PLACEHOLDERS.search(line):
                continue
            out.append(SecretFinding(
                severity=p.severity, category=p.category, pattern_name=p.name,
                description=p.name, blast_radius=p.blast_radius,
                file=file_label, line=idx, commit=commit,
            ))
        if entropy_check:
            for m in _ENTROPY_TOKEN.finditer(line):
                tok = m.group(1)
                if _PLACEHOLDERS.search(tok):
                    continue
                if _shannon_entropy(tok) >= 4.6 and len(set(tok)) >= 12:
                    out.append(SecretFinding(
                        severity="MEDIUM", category="High-Entropy Strings",
                        pattern_name="High-Entropy String",
                        description="High-entropy string — likely a key, token or password",
                        blast_radius="Unknown — high-entropy value with no recognised "
                                     "provider pattern; verify and rotate if sensitive.",
                        file=file_label, line=idx, commit=commit,
                    ))
    return out


def _scan_working_tree(root: Path, entropy_check: bool, progress_cb) -> tuple:
    findings: list = []
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if any(path.name.endswith(ext) for ext in _SKIP_EXT):
            continue
        files.append(path)

    total = len(files) or 1
    scanned = 0
    for i, path in enumerate(files):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if "\x00" in text[:1024]:  # binary guard
            continue
        rel = str(path.relative_to(root))
        findings.extend(_scan_text(text, rel, entropy_check))
        scanned += 1
        if progress_cb and i % 50 == 0:
            progress_cb(10 + 60 * i / total, f"Scanning files… ({i}/{total})")
    return findings, scanned


def _scan_history(root: Path, entropy_check: bool, progress_cb) -> tuple:
    """Scan added lines across recent commit history via `git log -p`."""
    findings: list = []
    commits: set = set()
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", "-p", "-U0", "--no-color",
             "-n", "300", "--all"],
            capture_output=True, text=True, timeout=120, errors="ignore",
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return findings, 0

    if proc.returncode != 0:
        return findings, 0

    cur_commit = None
    cur_file = "(history)"
    added_buf: list = []

    def flush():
        if added_buf and cur_commit:
            findings.extend(
                _scan_text("\n".join(added_buf), cur_file, entropy_check, cur_commit)
            )
        added_buf.clear()

    for raw in proc.stdout.splitlines():
        if raw.startswith("commit "):
            flush()
            cur_commit = raw.split()[1] if len(raw.split()) > 1 else None
            if cur_commit:
                commits.add(cur_commit)
        elif raw.startswith("+++ b/"):
            flush()
            cur_file = raw[6:]
        elif raw.startswith("+") and not raw.startswith("+++"):
            added_buf.append(raw[1:])
            if len(added_buf) > 5000:  # bound memory per file/commit
                flush()
    flush()
    if progress_cb:
        progress_cb(75, f"Scanned {len(commits)} commits of history…")
    return findings, len(commits)


def _dedup(findings: list) -> list:
    seen = set()
    out = []
    for f in findings:
        key = (f.file, f.line, f.pattern_name, f.commit)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda f: (_SEV_RANK.get(f.severity, 9), f.file, f.line))
    return out[:_MAX_FINDINGS]


def scan_repo(repo_path: str,
              include_history: bool = True,
              entropy_check: bool = True,
              progress_cb: Optional[Callable[[float, str], None]] = None
              ) -> SecretScanResult:
    """Scan a repository working tree (and optionally git history) for secrets."""
    root = Path(repo_path)
    result = SecretScanResult()

    if not root.exists():
        result.error = f"Path does not exist: {repo_path}"
        return result

    try:
        if progress_cb:
            progress_cb(5, "Enumerating files…")
        wt_findings, scanned = _scan_working_tree(root, entropy_check, progress_cb)
        result.files_scanned = scanned

        hist_findings: list = []
        if include_history and (root / ".git").exists():
            if progress_cb:
                progress_cb(70, "Scanning git history…")
            hist_findings, commits = _scan_history(root, entropy_check, progress_cb)
            result.commits_scanned = commits

        result.findings = _dedup(wt_findings + hist_findings)
        if progress_cb:
            progress_cb(100, f"Found {len(result.findings)} potential secrets.")
    except Exception as exc:  # never let the scanner crash the pipeline
        result.error = str(exc)
    return result
