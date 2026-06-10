"""
Fix Advisor: supports multiple LLM providers to generate actionable, diff-style
security fixes for each finding, enriched with MITRE context.

Supported providers: anthropic, openai, gemini, groq, ollama, none
"""

from pathlib import Path
from typing import Optional
from analyzer import Finding, AnalysisResult
from sandbox import RuntimeObservation

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


def get_llm_client(provider: str, api_key: str):
    """Return a callable that accepts (system, user_msg) and returns text."""

    provider = (provider or "anthropic").lower().strip()

    if provider == "anthropic":
        import anthropic as _anthropic
        import os
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        client = _anthropic.Anthropic(api_key=key)

        def call(system, user_msg):
            resp = client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=2048,
                system=system,
                messages=[{"role": "user", "content": user_msg}],
            )
            return resp.content[0].text
        return call

    elif provider == "openai":
        import openai as _openai
        import os
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        client = _openai.OpenAI(api_key=key)

        def call(system, user_msg):
            resp = client.chat.completions.create(
                model="gpt-4o",
                max_tokens=2048,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
            )
            return resp.choices[0].message.content
        return call

    elif provider == "gemini":
        import google.generativeai as genai
        import os
        key = api_key or os.environ.get("GOOGLE_API_KEY", "")
        genai.configure(api_key=key)
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction=SYSTEM_PROMPT,
        )

        def call(system, user_msg):
            resp = model.generate_content(user_msg)
            return resp.text
        return call

    elif provider == "groq":
        from groq import Groq as _Groq
        import os
        key = api_key or os.environ.get("GROQ_API_KEY", "")
        client = _Groq(api_key=key)

        def call(system, user_msg):
            resp = client.chat.completions.create(
                model="llama-3.1-70b-versatile",
                max_tokens=2048,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
            )
            return resp.choices[0].message.content
        return call

    elif provider == "ollama":
        import requests as _requests

        def call(system, user_msg):
            payload = {
                "model": "llama3",
                "prompt": f"{system}\n\n{user_msg}",
                "stream": False,
            }
            resp = _requests.post(
                "http://localhost:11434/api/generate",
                json=payload,
                timeout=120,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        return call

    elif provider == "none":
        def call(system, user_msg):
            return ""
        return call

    else:
        raise ValueError(f"Unknown LLM provider: {provider!r}")


def _read_file_context(repo_path: str, finding: Finding, context_lines: int = 10) -> str:
    """Read surrounding lines of a finding for richer context."""
    try:
        full_path = Path(repo_path) / finding.file
        lines = full_path.read_text(errors="replace").splitlines()
        start = max(0, finding.line_start - context_lines - 1)
        end = min(len(lines), finding.line_end + context_lines)
        numbered = [f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start=start)]
        return "\n".join(numbered)
    except Exception:
        return finding.code_snippet


def advise_finding(finding: Finding, repo_path: str,
                   provider: str = "anthropic", api_key: str = "") -> str:
    """Generate a fix for a single finding. Returns markdown string."""
    if provider == "none":
        return ""

    call = get_llm_client(provider, api_key)
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

    return call(SYSTEM_PROMPT, user_msg)


def advise_runtime(obs: RuntimeObservation,
                   provider: str = "anthropic", api_key: str = "") -> str:
    """Summarise sandbox runtime observations and flag suspicious behaviors."""
    if not obs.suspicious_behaviors and not obs.outbound_connections:
        return "No suspicious runtime behavior detected."
    if provider == "none":
        return ""

    call = get_llm_client(provider, api_key)

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

    return call(SYSTEM_PROMPT, user_msg)


def enrich_findings(result: AnalysisResult, obs: Optional[RuntimeObservation] = None,
                    provider: str = "anthropic", api_key: str = "",
                    max_findings: int = 20) -> list[dict]:
    """
    Generate fix advice for top findings. Returns list of enriched finding dicts.
    Caps at max_findings to control API cost.
    """
    enriched = []
    top = result.findings[:max_findings]

    print(f"[*] Generating fix advice for {len(top)} findings via {provider}...")
    for i, finding in enumerate(top, 1):
        print(f"    [{i}/{len(top)}] {finding.rule_id} @ {finding.file}:{finding.line_start}")
        advice = advise_finding(finding, result.repo_path,
                                provider=provider, api_key=api_key)
        finding.fix_suggestion = advice
        enriched.append(finding.to_dict())

    return enriched
