# SecureScope / GitHub Security Review Tool

> AI-powered security analysis for any GitHub repository. Paste a URL, get a full threat report mapped to MITRE ATT&CK and CWE, with optional Docker sandbox execution and AI-generated fix diffs from your choice of LLM.

---

## GitHub Security Review Tool

SecureScope scans any GitHub repository for security vulnerabilities, maps every finding to the MITRE ATT&CK framework and CWE identifiers, computes a composite threat score, and produces a visual interactive report. Optionally runs the target code in an isolated Docker sandbox to observe runtime behaviour, and uses an AI advisor to generate diff-style patches for each finding.

**[View Full Sample Report &rarr;](https://htmlpreview.github.io/?https://github.com/OmarRao/security-review/blob/main/reports/sample_report_ui.html)**

> Opens the complete interactive HTML threat report — threat scoring, MITRE ATT&CK mapping, Chart.js visualizations, and full findings table — rendered directly from GitHub.

---

## Landing Page

Click **Analyze Repository** to open the scan wizard. The landing page supports both dark and light themes via the toggle in the top-right corner.

### Dark Mode

![SecureScope Landing Page Dark](docs/screenshots/01_landing_dark.png)

### Light Mode

![SecureScope Landing Page Light](docs/screenshots/05_landing_light.png)

---

## Scan Wizard

Repository analysis is launched through a 3-step modal wizard.

### Step 1 — Repository

Enter the GitHub repository URL and target branch.

![Wizard Step 1 - Repository](docs/screenshots/02_modal_step1.png)

### Step 2 — AI Provider

Choose which LLM to use for fix generation. All major providers are supported with free tiers available.

| Provider | Model | Notes |
|----------|-------|-------|
| Anthropic Claude | claude-sonnet-4-5 | Best quality |
| OpenAI GPT-4o | gpt-4o | Fast and capable |
| Google Gemini | gemini-1.5-flash | Free tier |
| Groq Llama 3.1 | llama-3.1-70b-versatile | Ultra fast |
| Ollama (local) | llama3 | No API key required |
| None | N/A | Skip advisor |

![Wizard Step 2 - AI Provider](docs/screenshots/03_modal_step2_providers.png)

### Step 3 — Scan Options

Configure Docker sandbox execution and optional auto-commit of AI-generated fixes to GitHub.

![Wizard Step 3 - Options](docs/screenshots/04_modal_step3_options.png)

---

## Sample Report

The screenshots below are taken from a live scan of [`OmarRao/analyzer`](https://github.com/OmarRao/analyzer), a deliberately vulnerable Python Flask banking application containing 1000+ findings across multiple MITRE ATT&CK techniques.

**[View Full Sample Report &rarr;](https://htmlpreview.github.io/?https://github.com/OmarRao/security-review/blob/main/reports/sample_report_ui.html)**

---

### Report Overview

The report header shows the repository name, description, branch, language, license, scan timestamp, and a prominent **Risk Score** badge (0-100) with a threat grade: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. Five KPI cards break down critical findings, warnings, dependency CVEs, ATT&CK technique count, and sandbox exit code.

![Report Overview](docs/screenshots/06_report_overview.png)

---

### Threat Level

A full-width composite risk bar visualises the score against four bands. Below it, four score-breakdown cards show the weighted contribution of each finding type (errors x10, warnings x3, CVEs x8, runtime behaviors x15). A Priority Fix Queue lists the top 5 critical findings with file location, CWE, and ATT&CK technique for immediate remediation.

![Threat Level Section](docs/screenshots/07_report_threat.png)

---

### Attack Surface Analysis

Eight attack vector tiles show the exposure status of the codebase across the most common MITRE-mapped vulnerability classes. Each tile turns red (Exposed), amber (Detected), or green (Clear) based on findings present in the scan.

| Vector | CWE | ATT&CK |
|--------|-----|--------|
| SQL Injection | CWE-89 | T1190 Initial Access |
| Command Injection | CWE-78 | T1059 Execution |
| Cross-Site Scripting | CWE-79 | T1059.007 Execution |
| SSRF | CWE-918 | T1090 Defense Evasion |
| Path Traversal | CWE-22 | T1083 Discovery |
| Hardcoded Credentials | CWE-798 | T1552.001 Credential Access |
| Weak Cryptography | CWE-327 | T1600 Defense Evasion |
| Insecure Deserialization | CWE-502 | T1059 Execution |

![Attack Surface Analysis](docs/screenshots/08_report_surface.png)

---

### Analysis Charts

Six interactive Chart.js visualisations:

- **Severity Distribution** - Doughnut chart of Critical / Warning / Info counts
- **ATT&CK Technique Radar** - Radar plot across detected technique IDs
- **Findings by File** - Horizontal heatmap bars ranked by finding density
- **Severity per File** - Stacked bar chart (top 6 files, split by severity)
- **Language Risk Distribution** - Polar area chart from GitHub language stats
- **CWE Category Breakdown** - Horizontal bar of all CWE IDs ranked by frequency

![Analysis Charts](docs/screenshots/09_report_charts.png)

---

### Vulnerability Findings Table

Filterable by severity (All / Critical / Warning) with a live search box. Each row shows severity badge, Semgrep rule ID, file and line number, CWE tag, ATT&CK technique tag, tactic tag, and an expandable AI Fix Advisory panel when an LLM is configured.

![Findings Table](docs/screenshots/10_report_findings.png)

---

### Report in Light Mode

The report also works in light mode. The theme toggle persists across page reloads via localStorage.

![Report Light Mode](docs/screenshots/11_report_light.png)

---

## Architecture

```
main.py              CLI entry point
analyzer.py          Semgrep static scan + CWE -> ATT&CK mapping + dep CVEs
sandbox.py           Docker isolated runtime execution with strace observation
advisor.py           Multi-LLM fix advisor (Anthropic, OpenAI, Gemini, Groq, Ollama)
github_agent.py      Auto-commit security fixes to GitHub branch
report.py            HTML + JSON report generation
ui/
  server.py          Flask + Socket.IO web server with real-time scan progress
  github_info.py     GitHub API fetcher (stars, commits, contributors, languages)
  templates/
    index.html       Landing page with modal wizard, theme toggle, live progress
    report.html      Visual report with Chart.js, threat scoring, attack surface
```

---

## Prerequisites

| Requirement | Purpose |
|-------------|---------|
| Python 3.11+ | Runtime |
| Docker Desktop | Sandbox execution (optional) |
| `git` | Repository cloning |
| LLM API key | AI fix advisor (optional) |
| GitHub PAT (classic, `repo` scope) | Committing fixes (optional) |

---

## Setup

```bash
pip install -r requirements.txt

# For additional LLM providers (optional):
pip install openai google-generativeai groq
```

Set environment variables (the wizard also accepts keys interactively):

```bash
# Windows PowerShell
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-...", "User")
[System.Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "sk-...", "User")
[System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "...", "User")
[System.Environment]::SetEnvironmentVariable("GROQ_API_KEY", "gsk_...", "User")
[System.Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "ghp_...", "User")
```

---

## Usage

### Web UI (recommended)

```bash
python -m ui.server
# Open http://localhost:5001
```

Click **Analyze Repository** and follow the 3-step wizard:
1. Enter GitHub URL and branch
2. Choose your AI provider (or skip)
3. Configure sandbox and auto-commit options

### CLI

```bash
# Static analysis only
python main.py --repo https://github.com/owner/repo --no-sandbox --no-advisor

# Full scan with Docker sandbox
python main.py --repo https://github.com/owner/repo --no-advisor

# Full scan with AI fix advisor
python main.py --repo https://github.com/owner/repo --no-sandbox

# Full scan + commit fixes to GitHub
python main.py --repo https://github.com/owner/repo --commit --branch main
```

---

## Supported AI Providers

| Provider | Model | Free Tier | API Key Env Var |
|----------|-------|-----------|-----------------|
| Anthropic Claude | claude-sonnet-4-5 | No | `ANTHROPIC_API_KEY` |
| OpenAI | gpt-4o | Limited | `OPENAI_API_KEY` |
| Google Gemini | gemini-1.5-flash | Yes | `GEMINI_API_KEY` |
| Groq | llama-3.1-70b-versatile | Yes | `GROQ_API_KEY` |
| Ollama (local) | llama3 | Yes (local) | None required |
| None | N/A | N/A | N/A |

---

## MITRE ATT&CK Mapping

| CWE | ATT&CK Technique | Tactic |
|-----|-----------------|--------|
| CWE-89 | T1190 Exploit Public-Facing Application | Initial Access |
| CWE-79 | T1059.007 JavaScript | Execution |
| CWE-78 | T1059 Command and Scripting Interpreter | Execution |
| CWE-22 | T1083 File and Directory Discovery | Discovery |
| CWE-798 | T1552.001 Credentials in Files | Credential Access |
| CWE-918 | T1090 Proxy | Defense Evasion |
| CWE-327 | T1600 Weaken Encryption | Defense Evasion |
| CWE-502 | T1059 Command and Scripting Interpreter | Execution |
| CWE-352 | T1562 Impair Defenses | Defense Evasion |
| CWE-611 | T1190 Exploit Public-Facing Application | Initial Access |

---

## Risk Scoring

The composite risk score (0-100) is calculated as:

```
score = min(
    (critical_findings x 10) +
    (warnings x 3) +
    (dependency_CVEs x 8) +
    (sandbox_suspicious_behaviors x 15),
    100
)
```

| Score | Grade |
|-------|-------|
| 70-100 | CRITICAL |
| 45-69 | HIGH |
| 20-44 | MEDIUM |
| 0-19 | LOW |

---

## Security Notes

- Sandbox containers run with `--network internal` (no internet), 512 MB RAM cap, PID limit 128
- Fixes are committed in dry-run mode by default. Pass `--commit` to write to GitHub
- GitHub PAT needs `repo` scope only
- Cloned repositories are deleted from temp storage after each scan
- API keys entered in the wizard are used only for the current scan and are never stored
