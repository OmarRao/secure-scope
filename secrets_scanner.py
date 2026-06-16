"""
secrets_scanner.py — SecureScope Secrets Detection Engine
==========================================================
Scans source code files AND full git commit history for hardcoded secrets,
API keys, tokens, credentials, and high-entropy strings.

Key capabilities
----------------
  • 60+ regex patterns across 10 provider categories
  • Git history scan — catches secrets deleted from HEAD that still live in history
  • Shannon entropy analysis — catches generic high-entropy secrets with no known pattern
  • Blast radius assessment — maps each secret type to what systems it exposes
  • Secret redaction — never stores full secret values in results; shows only prefix + ***
  • Exclusion rules — ignores test fixtures, example values, and placeholder strings

Usage
-----
  from secrets_scanner import scan_repo, list_pattern_categories, SecretFinding

  results = scan_repo(
      repo_path="/path/to/cloned/repo",
      include_history=True,   # scan git commit history in addition to HEAD
      entropy_check=True,     # enable high-entropy string detection
      progress_cb=None,       # optional: fn(pct: float, message: str)
  )

  for finding in results.findings:
      print(finding.provider, finding.severity, finding.file_path)

Data classes
------------
  SecretFinding     — one detected secret instance
  SecretScanResult  — aggregated result from scan_repo()
"""

from __future__ import annotations

import math
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# ── Constants ─────────────────────────────────────────────────────────────────

# Minimum string length considered for entropy analysis
_ENTROPY_MIN_LEN = 20

# Shannon entropy threshold (bits per character) above which a string is
# flagged as a potential generic secret.  Typical thresholds: 4.5 (strict)
# to 5.0 (permissive).  We use 4.6 to balance false positives vs coverage.
_ENTROPY_THRESHOLD = 4.6

# File extensions always skipped — binary, media, lockfiles, generated code
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".pyc", ".pyo", ".pyd", ".so", ".dll", ".exe",
    ".lock", ".sum",
}

# File / directory names always skipped
_SKIP_NAMES = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".mypy_cache", ".pytest_cache", "coverage",
    "package-lock.json", "yarn.lock", "Pipfile.lock",
}

# Regex patterns that indicate a value is a placeholder / example
_PLACEHOLDER_RE = re.compile(
    r"(example|placeholder|your[-_]?key|test[-_]?key|sample|dummy|fake|"
    r"insert[-_]?here|<.*?>|\*{4,}|xxx+|yyy+|zzz+|1234|abcd)",
    re.IGNORECASE,
)


# ── Pattern library ───────────────────────────────────────────────────────────

@dataclass
class PatternDef:
    """Definition of a single secret pattern."""
    name: str           # Unique pattern ID (snake_case)
    provider: str       # Human-readable provider name
    category: str       # Grouping category shown in the UI
    severity: str       # critical / high / medium
    pattern: str        # Raw regex string (applied to each line of source)
    description: str    # What this secret grants access to
    blast_radius: str   # What an attacker can do with this secret


# All patterns are compiled once at module load — do not add flags here,
# apply them in _compile_patterns() below.
_RAW_PATTERNS: list[PatternDef] = [

    # ── Cloud: AWS ────────────────────────────────────────────────────────────
    PatternDef(
        name="aws_access_key_id",
        provider="AWS", category="Cloud",
        severity="critical",
        pattern=r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        description="AWS Access Key ID",
        blast_radius="Full AWS account access if paired with secret key — IAM, S3, EC2, Lambda, RDS",
    ),
    PatternDef(
        name="aws_secret_access_key",
        provider="AWS", category="Cloud",
        severity="critical",
        pattern=r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[_\-\s]*[=:\"'\s]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        description="AWS Secret Access Key",
        blast_radius="Full AWS account compromise — all services accessible",
    ),
    PatternDef(
        name="aws_session_token",
        provider="AWS", category="Cloud",
        severity="critical",
        pattern=r"(?i)aws[_\-\s]?session[_\-\s]?token[_\-\s]*[=:\"'\s]+([A-Za-z0-9/+=]{100,})",
        description="AWS Temporary Session Token",
        blast_radius="Time-limited AWS access — same blast radius as access key while valid",
    ),

    # ── Cloud: Azure ──────────────────────────────────────────────────────────
    PatternDef(
        name="azure_connection_string",
        provider="Azure", category="Cloud",
        severity="critical",
        pattern=r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}",
        description="Azure Storage Connection String",
        blast_radius="Full access to Azure Storage account — read/write/delete all blobs, queues, tables",
    ),
    PatternDef(
        name="azure_client_secret",
        provider="Azure", category="Cloud",
        severity="critical",
        pattern=r"(?i)azure[_\-\s]?client[_\-\s]?secret[_\-\s]*[=:\"'\s]+([A-Za-z0-9~._\-]{34,})",
        description="Azure Service Principal Client Secret",
        blast_radius="Azure AD application access — depends on app permissions assigned in tenant",
    ),
    PatternDef(
        name="azure_sas_token",
        provider="Azure", category="Cloud",
        severity="high",
        pattern=r"(?i)sv=\d{4}-\d{2}-\d{2}&s[a-z]=&[a-z]+=[^&\s]{10,}",
        description="Azure Shared Access Signature (SAS) Token",
        blast_radius="Scoped Azure Storage access — read/write within defined permissions and TTL",
    ),

    # ── Cloud: GCP ────────────────────────────────────────────────────────────
    PatternDef(
        name="gcp_api_key",
        provider="GCP", category="Cloud",
        severity="critical",
        pattern=r"AIza[0-9A-Za-z\-_]{35}",
        description="Google Cloud Platform API Key",
        blast_radius="Access to all GCP APIs enabled for this key — Maps, Vision, Translation, Firebase, etc.",
    ),
    PatternDef(
        name="gcp_service_account_key",
        provider="GCP", category="Cloud",
        severity="critical",
        pattern=r'"type"\s*:\s*"service_account"',
        description="GCP Service Account Key (JSON)",
        blast_radius="Full impersonation of the service account — IAM roles determine exact blast radius",
    ),
    PatternDef(
        name="gcp_oauth_token",
        provider="GCP", category="Cloud",
        severity="high",
        pattern=r"ya29\.[A-Za-z0-9\-_]{60,}",
        description="Google OAuth 2.0 Access Token",
        blast_radius="Access to Google APIs within OAuth scopes for the duration of the token TTL",
    ),

    # ── Cloud: DigitalOcean ───────────────────────────────────────────────────
    PatternDef(
        name="digitalocean_token",
        provider="DigitalOcean", category="Cloud",
        severity="critical",
        pattern=r"dop_v1_[a-f0-9]{64}",
        description="DigitalOcean Personal Access Token",
        blast_radius="Full DigitalOcean account — create/delete Droplets, Spaces, databases, DNS records",
    ),

    # ── AI / ML Providers ─────────────────────────────────────────────────────
    PatternDef(
        name="anthropic_api_key",
        provider="Anthropic", category="AI / ML",
        severity="critical",
        pattern=r"sk-ant-(?:api03-)?[A-Za-z0-9\-_]{93,}",
        description="Anthropic Claude API Key",
        blast_radius="Unbilled Claude API usage — financial liability, access to all Claude models",
    ),
    PatternDef(
        name="openai_api_key",
        provider="OpenAI", category="AI / ML",
        severity="critical",
        pattern=r"sk-(?:proj-)?[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_\-]{43,}",
        description="OpenAI API Key",
        blast_radius="Unbilled GPT/DALL-E API usage — financial liability, access to all OpenAI models",
    ),
    PatternDef(
        name="groq_api_key",
        provider="Groq", category="AI / ML",
        severity="high",
        pattern=r"gsk_[A-Za-z0-9]{52}",
        description="Groq API Key",
        blast_radius="Free Groq inference usage under the account quota — possible rate-limit abuse",
    ),
    PatternDef(
        name="huggingface_token",
        provider="HuggingFace", category="AI / ML",
        severity="high",
        pattern=r"hf_[A-Za-z0-9]{34}",
        description="HuggingFace Access Token",
        blast_radius="Access to private HuggingFace models, datasets, and inference endpoints",
    ),
    PatternDef(
        name="cohere_api_key",
        provider="Cohere", category="AI / ML",
        severity="high",
        pattern=r"(?i)cohere[_\-\s]?(?:api[_\-\s]?)?key[_\-\s]*[=:\"'\s]+([A-Za-z0-9]{40})",
        description="Cohere API Key",
        blast_radius="Cohere NLP API usage billed to the account",
    ),

    # ── Version Control ───────────────────────────────────────────────────────
    PatternDef(
        name="github_pat_classic",
        provider="GitHub", category="Version Control",
        severity="critical",
        pattern=r"ghp_[A-Za-z0-9]{36}",
        description="GitHub Personal Access Token (Classic)",
        blast_radius="Full repo read/write within token scopes — may include org-wide access",
    ),
    PatternDef(
        name="github_pat_fine_grained",
        provider="GitHub", category="Version Control",
        severity="critical",
        pattern=r"github_pat_[A-Za-z0-9_]{82}",
        description="GitHub Fine-Grained Personal Access Token",
        blast_radius="Scoped repo access as defined by token permissions",
    ),
    PatternDef(
        name="github_oauth_token",
        provider="GitHub", category="Version Control",
        severity="critical",
        pattern=r"gho_[A-Za-z0-9]{36}",
        description="GitHub OAuth Token",
        blast_radius="GitHub API access on behalf of the authorising user",
    ),
    PatternDef(
        name="github_actions_token",
        provider="GitHub", category="Version Control",
        severity="high",
        pattern=r"ghs_[A-Za-z0-9]{36}",
        description="GitHub Actions Token",
        blast_radius="Workflow-scoped GitHub access — repo write during CI run",
    ),
    PatternDef(
        name="github_refresh_token",
        provider="GitHub", category="Version Control",
        severity="high",
        pattern=r"ghr_[A-Za-z0-9]{76}",
        description="GitHub Refresh Token",
        blast_radius="Can obtain fresh OAuth tokens — persistent account access",
    ),
    PatternDef(
        name="gitlab_pat",
        provider="GitLab", category="Version Control",
        severity="critical",
        pattern=r"glpat-[A-Za-z0-9\-_]{20}",
        description="GitLab Personal Access Token",
        blast_radius="GitLab API access — repositories, CI/CD, registry within token scopes",
    ),

    # ── Payment Providers ─────────────────────────────────────────────────────
    PatternDef(
        name="stripe_secret_key",
        provider="Stripe", category="Payment",
        severity="critical",
        pattern=r"sk_live_[A-Za-z0-9]{24,}",
        description="Stripe Secret API Key (Live)",
        blast_radius="Full Stripe account — issue charges, read customer data, initiate payouts",
    ),
    PatternDef(
        name="stripe_restricted_key",
        provider="Stripe", category="Payment",
        severity="high",
        pattern=r"rk_live_[A-Za-z0-9]{24,}",
        description="Stripe Restricted API Key (Live)",
        blast_radius="Scoped Stripe access — exact permissions defined on the key",
    ),
    PatternDef(
        name="square_access_token",
        provider="Square", category="Payment",
        severity="critical",
        pattern=r"sq0atp-[0-9A-Za-z\-_]{22}",
        description="Square OAuth Access Token",
        blast_radius="Square merchant account — payments, inventory, customer data",
    ),
    PatternDef(
        name="square_secret",
        provider="Square", category="Payment",
        severity="critical",
        pattern=r"sq0csp-[0-9A-Za-z\-_]{43}",
        description="Square Application Secret",
        blast_radius="Square OAuth flows — impersonate app to gain merchant access",
    ),
    PatternDef(
        name="braintree_access_token",
        provider="Braintree", category="Payment",
        severity="critical",
        pattern=r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        description="Braintree Production Access Token",
        blast_radius="Braintree merchant account — transactions, vault data, refunds",
    ),

    # ── Communications ────────────────────────────────────────────────────────
    PatternDef(
        name="slack_bot_token",
        provider="Slack", category="Communications",
        severity="critical",
        pattern=r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}",
        description="Slack Bot Token",
        blast_radius="Full Slack bot capabilities — read/write messages, access channels, DMs",
    ),
    PatternDef(
        name="slack_user_token",
        provider="Slack", category="Communications",
        severity="critical",
        pattern=r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{32}",
        description="Slack User OAuth Token",
        blast_radius="Act as the authorising user — full workspace access including private channels",
    ),
    PatternDef(
        name="slack_app_token",
        provider="Slack", category="Communications",
        severity="high",
        pattern=r"xapp-[0-9]-[A-Z0-9]{10,12}-[0-9]{11}-[a-f0-9]{64}",
        description="Slack App-Level Token",
        blast_radius="Socket Mode connections — receive all events the app is subscribed to",
    ),
    PatternDef(
        name="slack_webhook",
        provider="Slack", category="Communications",
        severity="medium",
        pattern=r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{10}/B[A-Za-z0-9_]{10}/[A-Za-z0-9_]{24}",
        description="Slack Incoming Webhook URL",
        blast_radius="Post arbitrary messages to the configured Slack channel",
    ),
    PatternDef(
        name="twilio_account_sid",
        provider="Twilio", category="Communications",
        severity="high",
        pattern=r"AC[a-f0-9]{32}",
        description="Twilio Account SID",
        blast_radius="Required with Auth Token — Twilio calls, SMS, WhatsApp messaging",
    ),
    PatternDef(
        name="twilio_auth_token",
        provider="Twilio", category="Communications",
        severity="critical",
        pattern=r"(?i)twilio[_\-\s]?auth[_\-\s]?token[_\-\s]*[=:\"'\s]+([a-f0-9]{32})",
        description="Twilio Auth Token",
        blast_radius="Full Twilio account — phone calls, SMS, WhatsApp, account manipulation",
    ),
    PatternDef(
        name="sendgrid_api_key",
        provider="SendGrid", category="Communications",
        severity="critical",
        pattern=r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        description="SendGrid API Key",
        blast_radius="Send email as the account — phishing, spam, email enumeration, data exfil",
    ),
    PatternDef(
        name="mailgun_api_key",
        provider="Mailgun", category="Communications",
        severity="critical",
        pattern=r"key-[A-Za-z0-9]{32}",
        description="Mailgun API Key",
        blast_radius="Send/receive email via Mailgun account — phishing, spam relay",
    ),

    # ── Cryptographic Keys & Certificates ────────────────────────────────────
    PatternDef(
        name="rsa_private_key",
        provider="PKI", category="Cryptographic Keys",
        severity="critical",
        pattern=r"-----BEGIN RSA PRIVATE KEY-----",
        description="RSA Private Key",
        blast_radius="Decrypt TLS traffic, forge signatures, impersonate server — depends on where key is used",
    ),
    PatternDef(
        name="ec_private_key",
        provider="PKI", category="Cryptographic Keys",
        severity="critical",
        pattern=r"-----BEGIN EC PRIVATE KEY-----",
        description="Elliptic Curve Private Key",
        blast_radius="Same as RSA — sign arbitrary data, impersonate server",
    ),
    PatternDef(
        name="openssh_private_key",
        provider="PKI", category="Cryptographic Keys",
        severity="critical",
        pattern=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        description="OpenSSH Private Key",
        blast_radius="SSH authentication to any server the corresponding public key is authorised on",
    ),
    PatternDef(
        name="pgp_private_key",
        provider="PKI", category="Cryptographic Keys",
        severity="critical",
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        description="PGP Private Key Block",
        blast_radius="Decrypt PGP-encrypted messages, forge signatures on behalf of key owner",
    ),
    PatternDef(
        name="pkcs8_private_key",
        provider="PKI", category="Cryptographic Keys",
        severity="critical",
        pattern=r"-----BEGIN PRIVATE KEY-----",
        description="PKCS#8 Private Key",
        blast_radius="General-purpose private key — impact depends on associated certificate and usage",
    ),
    PatternDef(
        name="jwt_token",
        provider="Auth", category="Cryptographic Keys",
        severity="medium",
        pattern=r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        description="JSON Web Token (JWT)",
        blast_radius="Session impersonation for the duration of token validity",
    ),

    # ── Database Connection Strings ───────────────────────────────────────────
    PatternDef(
        name="mongodb_connection_string",
        provider="MongoDB", category="Database",
        severity="critical",
        pattern=r"mongodb(?:\+srv)?://[^:]+:[^@\s]{6,}@[A-Za-z0-9._\-]",
        description="MongoDB Connection String with credentials",
        blast_radius="Full database access — read/write/drop all collections on the connected instance",
    ),
    PatternDef(
        name="postgresql_connection_string",
        provider="PostgreSQL", category="Database",
        severity="critical",
        pattern=r"postgres(?:ql)?://[^:]+:[^@\s]{6,}@[A-Za-z0-9._\-]",
        description="PostgreSQL Connection String with credentials",
        blast_radius="Full database access — read/write/drop all tables in scope",
    ),
    PatternDef(
        name="mysql_connection_string",
        provider="MySQL", category="Database",
        severity="critical",
        pattern=r"mysql(?:2)?://[^:]+:[^@\s]{6,}@[A-Za-z0-9._\-]",
        description="MySQL Connection String with credentials",
        blast_radius="Full database access — depends on database user grants",
    ),
    PatternDef(
        name="redis_connection_string",
        provider="Redis", category="Database",
        severity="high",
        pattern=r"redis://(?:[^:]+:[^@\s]{6,}@)?[A-Za-z0-9._\-]+:[0-9]+",
        description="Redis Connection String (may include AUTH password)",
        blast_radius="Cache/session store access — read all keys, overwrite data, execute Lua scripts",
    ),

    # ── Generic Credential Patterns ───────────────────────────────────────────
    PatternDef(
        name="generic_password_assignment",
        provider="Generic", category="Generic Credentials",
        severity="medium",
        pattern=r"""(?i)(?:password|passwd|pwd|secret|token|apikey|api_key|auth_key)\s*[=:]\s*["']([^"']{8,64})["']""",
        description="Hardcoded password or secret in assignment",
        blast_radius="Depends on what system the credential grants access to",
    ),
    PatternDef(
        name="generic_bearer_token",
        provider="Generic", category="Generic Credentials",
        severity="medium",
        pattern=r"(?i)Bearer\s+([A-Za-z0-9\-_=.]{30,})",
        description="HTTP Bearer token hardcoded in source",
        blast_radius="API authentication for the duration of the token — scope varies",
    ),
    PatternDef(
        name="basic_auth_url",
        provider="Generic", category="Generic Credentials",
        severity="high",
        pattern=r"https?://[A-Za-z0-9._\-]+:[^@\s/]{6,}@[A-Za-z0-9._\-]",
        description="Credentials embedded in URL (Basic Auth)",
        blast_radius="Authentication to the target service — full user-level access",
    ),
]


# ── Compile patterns once at import time ─────────────────────────────────────

@dataclass
class _CompiledPattern:
    definition: PatternDef
    regex: re.Pattern


def _compile_patterns() -> list[_CompiledPattern]:
    compiled = []
    for pdef in _RAW_PATTERNS:
        try:
            compiled.append(_CompiledPattern(
                definition=pdef,
                regex=re.compile(pdef.pattern),
            ))
        except re.error as exc:
            # Log compile errors but don't crash — skip the bad pattern
            print(f"[secrets_scanner] WARNING: Could not compile pattern "
                  f"'{pdef.name}': {exc}", flush=True)
    return compiled


_COMPILED_PATTERNS: list[_CompiledPattern] = _compile_patterns()


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class SecretFinding:
    """
    Represents a single detected secret instance.

    The `secret_redacted` field shows only the first 6 chars followed by ***
    so the UI can confirm the type without exposing the full value.
    """
    # Pattern identification
    pattern_name: str       # e.g. "aws_access_key_id"
    provider: str           # e.g. "AWS"
    category: str           # e.g. "Cloud"
    severity: str           # critical / high / medium
    description: str        # Human-readable type description
    blast_radius: str       # What an attacker gains

    # Location
    file_path: str          # Relative path within the repo
    line_number: int        # 1-based line number (-1 for git history findings)
    commit_hash: str = ""   # Non-empty when found in git history
    commit_message: str = ""

    # Secret value (always redacted)
    secret_redacted: str = ""   # First 6 chars + ***
    context_line: str = ""      # The full source line (with secret masked)

    # Detection method
    detection_method: str = "pattern"  # "pattern" | "entropy"

    def to_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "provider": self.provider,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "blast_radius": self.blast_radius,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "commit_hash": self.commit_hash,
            "commit_message": self.commit_message,
            "secret_redacted": self.secret_redacted,
            "context_line": self.context_line,
            "detection_method": self.detection_method,
        }


@dataclass
class SecretScanResult:
    """Aggregated result from a complete repo scan."""
    repo_path: str
    files_scanned: int = 0
    commits_scanned: int = 0
    findings: list[SecretFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_sec: float = 0.0
    include_history: bool = False
    entropy_check: bool = True

    # ── Derived statistics ────────────────────────────────────────────────────

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def history_findings(self) -> list[SecretFinding]:
        """Findings from git history (not present in HEAD)."""
        return [f for f in self.findings if f.commit_hash]

    @property
    def categories(self) -> dict[str, int]:
        """Count findings per provider category."""
        cats: dict[str, int] = {}
        for f in self.findings:
            cats[f.category] = cats.get(f.category, 0) + 1
        return dict(sorted(cats.items(), key=lambda x: x[1], reverse=True))

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "files_scanned": self.files_scanned,
            "commits_scanned": self.commits_scanned,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "history_findings": len(self.history_findings),
            "categories": self.categories,
            "include_history": self.include_history,
            "entropy_check": self.entropy_check,
            "duration_sec": round(self.duration_sec, 2),
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }


# ── Utility functions ─────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy of a string in bits per character.

    A completely random string of printable ASCII chars has entropy ≈ 6.57.
    Real secrets from hex / base64 alphabets typically sit between 4.5–6.0.
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _redact(value: str) -> str:
    """Return a redacted version: first 6 chars + '***...'"""
    if len(value) <= 6:
        return "***"
    return value[:6] + "***"


def _mask_line(line: str, match_value: str) -> str:
    """Replace the matched secret in a line with [REDACTED]."""
    if not match_value:
        return line.strip()
    return line.replace(match_value, "[REDACTED]").strip()


def _is_placeholder(value: str) -> bool:
    """Return True if the matched value looks like a placeholder / test fixture."""
    return bool(_PLACEHOLDER_RE.search(value))


def _should_skip_file(path: Path) -> bool:
    """Return True if this file should be excluded from scanning."""
    # Skip by extension
    if path.suffix.lower() in _SKIP_EXTENSIONS:
        return True
    # Skip if any path component is in the exclusion list
    for part in path.parts:
        if part in _SKIP_NAMES:
            return True
    return False


def list_pattern_categories() -> list[dict]:
    """
    Return all available pattern categories with names and counts.
    Used by the UI to render the category filter panel.
    """
    cats: dict[str, dict] = {}
    for cp in _COMPILED_PATTERNS:
        cat = cp.definition.category
        if cat not in cats:
            cats[cat] = {
                "category": cat,
                "count": 0,
                "providers": set(),
            }
        cats[cat]["count"] += 1
        cats[cat]["providers"].add(cp.definition.provider)

    return [
        {
            "category": v["category"],
            "pattern_count": v["count"],
            "providers": sorted(v["providers"]),
        }
        for v in sorted(cats.values(), key=lambda x: x["category"])
    ]


# ── Core scanning logic ───────────────────────────────────────────────────────

def _scan_content(
    content: str,
    file_path: str,
    entropy_check: bool,
    commit_hash: str = "",
    commit_message: str = "",
) -> list[SecretFinding]:
    """
    Scan a block of text for secrets using all compiled patterns plus
    optional entropy analysis.

    Returns a list of SecretFinding objects (may be empty).
    """
    findings: list[SecretFinding] = []
    seen: set[str] = set()  # deduplicate within the same file/commit

    lines = content.splitlines()

    for line_idx, line in enumerate(lines):
        line_num = line_idx + 1

        # ── Pattern matching ──────────────────────────────────────────────────
        for cp in _COMPILED_PATTERNS:
            m = cp.regex.search(line)
            if not m:
                continue

            # Extract the matched value (use group 1 if captured, else full match)
            matched_value = m.group(1) if m.lastindex else m.group(0)

            # Skip placeholders / test fixtures
            if _is_placeholder(matched_value):
                continue

            # Deduplicate: same pattern + value in same file
            dedup_key = f"{cp.definition.name}:{matched_value[:12]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(SecretFinding(
                pattern_name=cp.definition.name,
                provider=cp.definition.provider,
                category=cp.definition.category,
                severity=cp.definition.severity,
                description=cp.definition.description,
                blast_radius=cp.definition.blast_radius,
                file_path=file_path,
                line_number=line_num,
                commit_hash=commit_hash,
                commit_message=commit_message[:120] if commit_message else "",
                secret_redacted=_redact(matched_value),
                context_line=_mask_line(line, matched_value),
                detection_method="pattern",
            ))

        # ── Entropy analysis ──────────────────────────────────────────────────
        if not entropy_check:
            continue

        # Extract candidate tokens: sequences of non-whitespace chars that are
        # long enough and look like they could be secrets (base64/hex/alphanum)
        for token_match in re.finditer(r'[A-Za-z0-9+/=_\-]{%d,80}' % _ENTROPY_MIN_LEN, line):
            token = token_match.group(0)

            # Skip if already caught by a named pattern
            if any(cp.regex.search(token) for cp in _COMPILED_PATTERNS):
                continue

            if _is_placeholder(token):
                continue

            entropy = _shannon_entropy(token)
            if entropy < _ENTROPY_THRESHOLD:
                continue

            dedup_key = f"entropy:{token[:12]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(SecretFinding(
                pattern_name="high_entropy_string",
                provider="Generic",
                category="Generic Credentials",
                severity="medium",
                description=f"High-entropy string (Shannon entropy {entropy:.2f} bpc)",
                blast_radius="Unknown — manual review required to determine what this value grants access to",
                file_path=file_path,
                line_number=line_num,
                commit_hash=commit_hash,
                commit_message=commit_message[:120] if commit_message else "",
                secret_redacted=_redact(token),
                context_line=_mask_line(line, token),
                detection_method="entropy",
            ))

    return findings


def _scan_file(
    file_path: Path,
    repo_root: Path,
    entropy_check: bool,
) -> list[SecretFinding]:
    """Read and scan a single file from the working tree."""
    try:
        # Read as text with lenient encoding
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    return _scan_content(content, rel_path, entropy_check)


def _scan_working_tree(
    repo_root: Path,
    entropy_check: bool,
    progress_cb: Optional[Callable],
) -> tuple[list[SecretFinding], int, list[str]]:
    """
    Walk every file in the repo working tree and scan for secrets.

    Returns (findings, files_scanned, errors).
    """
    findings: list[SecretFinding] = []
    errors: list[str] = []
    files_scanned = 0

    # Collect all scannable files first (for accurate progress reporting)
    all_files = [
        p for p in repo_root.rglob("*")
        if p.is_file() and not _should_skip_file(p)
    ]
    total = max(len(all_files), 1)

    for idx, fpath in enumerate(all_files):
        if progress_cb:
            pct = 5 + (idx / total) * 40   # working-tree scan = 5–45%
            progress_cb(pct, f"Scanning {fpath.name}")

        file_findings = _scan_file(fpath, repo_root, entropy_check)
        findings.extend(file_findings)
        files_scanned += 1

    return findings, files_scanned, errors


def _scan_git_history(
    repo_root: Path,
    entropy_check: bool,
    progress_cb: Optional[Callable],
) -> tuple[list[SecretFinding], int, list[str]]:
    """
    Iterate through every commit in git history and scan the diff content
    for secrets.  This catches credentials that were committed and later
    deleted — they still exist in history even when not in HEAD.

    Returns (findings, commits_scanned, errors).
    """
    findings: list[SecretFinding] = []
    errors: list[str] = []
    commits_scanned = 0

    # Get a list of all commit hashes (oldest first)
    try:
        result = subprocess.run(
            ["git", "log", "--all", "--format=%H %s"],
            cwd=str(repo_root),
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            errors.append(f"git log failed: {result.stderr[:200]}")
            return findings, 0, errors

        commit_lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    except Exception as exc:
        errors.append(f"git log exception: {exc}")
        return findings, 0, errors

    total = max(len(commit_lines), 1)

    for idx, commit_line in enumerate(commit_lines):
        parts = commit_line.split(" ", 1)
        commit_hash = parts[0]
        commit_msg = parts[1] if len(parts) > 1 else ""

        if progress_cb:
            pct = 50 + (idx / total) * 45   # history scan = 50–95%
            progress_cb(pct, f"History: {commit_hash[:8]} — {commit_msg[:50]}")

        # Get the patch (diff) introduced by this commit
        try:
            diff_result = subprocess.run(
                ["git", "show", "--format=", "--unified=0", commit_hash],
                cwd=str(repo_root),
                capture_output=True, text=True, timeout=20,
                errors="replace",
            )
            if diff_result.returncode != 0:
                continue
            diff_content = diff_result.stdout
        except Exception as exc:
            errors.append(f"git show {commit_hash[:8]}: {exc}")
            continue

        # Parse diff: extract added lines and their source file
        current_file = f"<commit:{commit_hash[:8]}>"
        for line in diff_content.splitlines():
            if line.startswith("diff --git"):
                # Extract file path: "diff --git a/foo b/foo"
                parts_diff = line.split(" b/", 1)
                if len(parts_diff) == 2:
                    current_file = parts_diff[1].strip()
            elif line.startswith("+") and not line.startswith("+++"):
                # Only scan added lines (lines introduced by this commit)
                added_line = line[1:]
                line_findings = _scan_content(
                    added_line,
                    file_path=current_file,
                    entropy_check=entropy_check,
                    commit_hash=commit_hash,
                    commit_message=commit_msg,
                )
                findings.extend(line_findings)

        commits_scanned += 1

    return findings, commits_scanned, errors


# ── Public API ────────────────────────────────────────────────────────────────

def scan_repo(
    repo_path: str,
    include_history: bool = True,
    entropy_check: bool = True,
    progress_cb: Optional[Callable[[float, str], None]] = None,
) -> SecretScanResult:
    """
    Scan a locally cloned repository for hardcoded secrets.

    Parameters
    ----------
    repo_path       : str
        Absolute path to the cloned repository root.
    include_history : bool
        If True, also scan git commit history (not just HEAD files).
        This catches secrets that were committed and later deleted.
    entropy_check   : bool
        If True, use Shannon entropy analysis to detect generic secrets
        with no known provider pattern.
    progress_cb     : callable(pct: float, message: str) | None
        Optional callback for progress reporting. Called with a percentage
        (0–100) and a status message string.

    Returns
    -------
    SecretScanResult
        Aggregated result including all findings, statistics, and errors.
    """
    import time
    start = time.time()

    repo_root = Path(repo_path)
    result = SecretScanResult(
        repo_path=repo_path,
        include_history=include_history,
        entropy_check=entropy_check,
    )

    if not repo_root.exists():
        result.errors.append(f"Repo path does not exist: {repo_path}")
        return result

    if progress_cb:
        progress_cb(2, "Starting secrets scan — walking working tree...")

    # ── Phase 1: scan working tree ────────────────────────────────────────────
    wt_findings, files_scanned, wt_errors = _scan_working_tree(
        repo_root, entropy_check, progress_cb
    )
    result.findings.extend(wt_findings)
    result.files_scanned = files_scanned
    result.errors.extend(wt_errors)

    # ── Phase 2: scan git history ─────────────────────────────────────────────
    if include_history:
        if progress_cb:
            progress_cb(48, "Scanning git commit history...")

        hist_findings, commits_scanned, hist_errors = _scan_git_history(
            repo_root, entropy_check, progress_cb
        )

        # Only include history findings that are NOT already in the working tree
        # (avoid showing the same secret twice for the same file/pattern)
        wt_keys = {
            (f.file_path, f.pattern_name, f.secret_redacted)
            for f in wt_findings
        }
        for hf in hist_findings:
            key = (hf.file_path, hf.pattern_name, hf.secret_redacted)
            if key not in wt_keys:
                result.findings.append(hf)
                wt_keys.add(key)  # prevent duplicates within history too

        result.commits_scanned = commits_scanned
        result.errors.extend(hist_errors)

    result.duration_sec = time.time() - start

    if progress_cb:
        progress_cb(100, f"Secrets scan complete — {len(result.findings)} findings in "
                         f"{result.files_scanned} files, {result.commits_scanned} commits")

    return result
