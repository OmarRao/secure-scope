# GitHub Security Review Tool

AI-powered security review with MITRE ATT&CK/CWE mapping, Docker sandbox execution, and automated fix commits.

## Architecture

```
main.py
 ├── analyzer.py     Static analysis (Semgrep + dependency CVEs → MITRE mapping)
 ├── sandbox.py      Docker execution (runtime behavior observation)
 ├── advisor.py      Claude API fix generation (per-finding diffs)
 ├── github_agent.py Commit fixes to GitHub branch
 └── report.py       HTML + JSON reports
```

## Prerequisites

| Tool | Purpose |
|------|---------|
| Python 3.11+ | Runtime |
| Docker Desktop | Sandbox execution |
| `git` | Repo cloning |
| Semgrep | Static analysis (installed via pip) |
| Anthropic API key | Fix advisor |
| GitHub PAT | Committing fixes (scopes: `repo`) |

## Setup

```bash
pip install -r requirements.txt
```

Set environment variables:
```bash
set ANTHROPIC_API_KEY=sk-ant-...
set GITHUB_TOKEN=ghp_...
```

## Usage

### Full review (static + sandbox + advisor + dry-run commit preview)
```bash
python main.py --repo https://github.com/owner/repo
```

### Static analysis only (no Docker, no API calls)
```bash
python main.py --repo https://github.com/owner/repo --no-sandbox --no-advisor
```

### Full review + actually commit fixes
```bash
python main.py --repo https://github.com/owner/repo --commit --branch main
```

### Custom branch, limit findings advised
```bash
python main.py --repo https://github.com/owner/repo --branch develop --max-findings 10
```

## Output

Reports are saved to `./reports/`:
- `<repo>_<timestamp>.html` — Visual report with expandable fix advisories
- `<repo>_<timestamp>.json` — Machine-readable full results
- `<repo>_<timestamp>_commits.json` — Commit log (if fixes applied)

## MITRE Mapping

| CWE | ATT&CK Technique | Tactic |
|-----|-----------------|--------|
| CWE-89 | T1190 – SQL Injection | Initial Access |
| CWE-79 | T1059.007 – XSS | Execution |
| CWE-78 | T1059 – OS Command Injection | Execution |
| CWE-22 | T1083 – Path Traversal | Discovery |
| CWE-798 | T1552.001 – Hardcoded Credentials | Credential Access |
| CWE-918 | T1090 – SSRF | Defense Evasion |
| CWE-327 | T1600 – Weak Cryptography | Defense Evasion |
| + more | See `analyzer.py:CWE_TO_ATTACK` | |

## Security Notes

- Sandbox containers run with `--network internal` (no internet), memory cap 512MB, PID limit 128
- Fixes are committed in dry-run mode by default — add `--commit` to write to GitHub
- GitHub PAT needs `repo` scope only; no admin rights required
- Repo is cloned to a temp directory and cleaned up after the run
