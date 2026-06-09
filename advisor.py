"""
Fix Advisor: uses Claude API to generate actionable, diff-style security fixes
for each finding, enriched with MITRE context.
"""

import anthropic
from pathlib import Path
from analyzer import Finding, AnalysisResult
from sandbox import RuntimeObservation

client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

SYSTEM_PROMPT = """You are a senior application security engineer and MITRE ATT&CK expert.
Your job is to review vulnerable code findings and produce:
1. A clear explanation of the vulnerability and its exploitability.
2. The exact MITRE CWE and ATT&CK technique it maps to, with reasoning.
3. A concrete code fix as a unified diff.
4. A one-sentence remediation summary for the commit message.

Rules:
- Be precise and actionable. No generic advice.
- The diff must be syntactically correct and minimal (smallest change that fixes the issue).
- If a fix requires a library change (e.g. parameterized queries), show the import too.
- Format: use markdown with sections: ## Vulnerability, ## MITRE Mapping, ## Fix (diff block), ## Commit Message."""


def _read_file_context(repo_path: str, finding: Finding, context_lines: int = 10) -> str:
    """Read surrounding lines of a finding for richer Claude context."""
    try:
        full_path = Path(repo_path) / finding.file
        lines = full_path.read_text(errors="replace").splitlines()
        start = max(0, finding.line_start - context_lines - 1)
        end = min(len(lines), finding.line_end + context_lines)
        numbered = [f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start=start)]
        return "\n".join(numbered)
    except Exception:
        return finding.code_snippet


def advise_finding(finding: Finding, repo_path: str) -> str:
    """Call Claude to generate a fix for a single finding. Returns markdown string."""
    file_context = _read_file_context(repo_path, finding)

    mitre_hint = ""
    if finding.attack_technique:
        mitre_hint = (
            f"\nMITRE ATT&CK: {finding.attack_technique} ({finding.attack_name}) "
            f"— Tactic: {finding.attack_tactic}"
        )
    if finding.cwe:
        mitre_hint += f"\nCWE: {finding.cwe}"

    user_msg = f"""Finding from Semgrep rule `{finding.rule_id}`:
Severity: {finding.severity}
File: {finding.file}, lines {finding.line_start}–{finding.line_end}
{mitre_hint}

Semgrep message: {finding.message}

Code context (with line numbers):
```
{file_context}
```

Produce the vulnerability analysis and fix."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )
    return response.content[0].text


def advise_runtime(obs: RuntimeObservation) -> str:
    """Summarise sandbox runtime observations and flag suspicious behaviors."""
    if not obs.suspicious_behaviors and not obs.outbound_connections:
        return "No suspicious runtime behavior detected."

    behaviors = "\n".join(f"- {b}" for b in obs.suspicious_behaviors) or "None"
    connections = "\n".join(
        f"- {c['host']}:{c['port']}" for c in obs.outbound_connections
    ) or "None"
    processes = "\n".join(f"- {p}" for p in obs.processes_spawned[:20]) or "None"

    user_msg = f"""Runtime sandbox analysis of a GitHub repository:

Suspicious behaviors detected:
{behaviors}

Outbound network connections attempted:
{connections}

Processes spawned:
{processes}

stdout (truncated):
{obs.stdout[:2000]}

As a security advisor, explain what these runtime behaviors indicate,
which MITRE ATT&CK techniques they map to, and what mitigations to apply."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )
    return response.content[0].text


def enrich_findings(result: AnalysisResult, obs: Optional[RuntimeObservation] = None,
                    max_findings: int = 20) -> list[dict]:
    """
    Generate fix advice for top findings. Returns list of enriched finding dicts.
    Caps at max_findings to control API cost.
    """
    from sandbox import RuntimeObservation as RTO
    enriched = []
    top = result.findings[:max_findings]

    print(f"[*] Generating fix advice for {len(top)} findings via Claude API...")
    for i, finding in enumerate(top, 1):
        print(f"    [{i}/{len(top)}] {finding.rule_id} @ {finding.file}:{finding.line_start}")
        advice = advise_finding(finding, result.repo_path)
        finding.fix_suggestion = advice
        enriched.append(finding.to_dict())

    return enriched


# Allow Optional import for type hint above
try:
    from typing import Optional
except ImportError:
    pass
