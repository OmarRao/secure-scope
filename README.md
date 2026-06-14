# SecureScope / GitHub Security Review Tool

![Version](https://img.shields.io/badge/version-v2.0.0-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)
![License](https://img.shields.io/badge/license-MIT-green)

> AI-powered security analysis for any GitHub repository. Paste a URL, get a full threat report mapped to MITRE ATT&CK and CWE, with optional Docker sandbox execution and AI-generated fix diffs from your choice of LLM.
> **v2.0.0** adds a live Threat Intelligence Dashboard, YARA rule engine for backup/infrastructure scanning, enterprise prevention guidance, and an interactive Data Protection resilience guide.

**[View Sample Report (PDF)](https://github.com/OmarRao/secure-scope/blob/main/docs/sample_report.pdf)**

---

## Landing Page

Click **Analyze Repository** to open the scan wizard. The landing page lists all capabilities and recent scans, and supports both dark and light themes via the toggle in the top-right corner.

![SecureScope Landing Page](docs/screenshots/01_hero.png)

---

## Scan Wizard

Repository analysis is launched through a 3-step modal wizard.

### Step 1 — Repository

Enter the GitHub repository URL and target branch.

![Wizard Step 1 - Repository](docs/screenshots/02_wizard_step1.png)

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

![Wizard Step 2 - AI Provider](docs/screenshots/03_wizard_step2.png)

### Step 3 — Scan Options

Configure Docker sandbox execution and optional auto-commit of AI-generated fixes to GitHub.

![Wizard Step 3 - Options](docs/screenshots/04_wizard_step3.png)

---

## Threat Intelligence Dashboard (v2.0.0)

A live threat intelligence panel sits below the scan wizard on the main dashboard. No scan is required — it loads automatically on page visit and auto-refreshes every 60 seconds.

### Live Threat Feed & Top 10 Active Variants

Real-time tracking of 26 ransomware groups and APT actors ranked by severity. Click any row to expand full details: TTPs, CVEs, IOCs, affected sectors, and step-by-step prevention guidance.

![Threat Intelligence Feed & Top 10](docs/screenshots/05_threat_intel_feed.png)

### Data Protection & Resilience + YARA Scanner

The 3-2-1-1-0 backup rule visualised with an interactive DR testing checklist (state saved to localStorage). The YARA Scanner panel lets you scan any local path — backups, infrastructure directories — against 6 predefined rule sets in real time via WebSocket progress streaming.

![Data Protection & YARA Scanner](docs/screenshots/06_prevention_yara.png)

### Threat Intelligence Feature Summary

| Panel | Description |
|-------|-------------|
| **Live Threat Feed** | Scrollable feed of 26 tracked ransomware and APT groups, sorted by severity. Click any row to expand TTPs, CVEs, IOCs, and prevention steps. |
| **Top 10 Active Variants** | Ranked list of most active threats in the last 90 days with detection counts, severity bars, and trend indicators. |
| **Enterprise Prevention** | Tabbed cards (Ransomware / APT / Malware / Exploit) with actionable controls, difficulty ratings, and icons. |
| **Data Protection & Resilience** | 3-2-1-1-0 backup rule visual guide plus an interactive DR testing checklist (state saved to localStorage). |
| **YARA Scanner** | Scan any local path against 6 rule sets covering ransomware, LockBit, BlackCat, APT lateral movement, data exfiltration, and backup tampering. Streams live progress via Socket.IO. |

### YARA Rule Sets

| File | Coverage |
|------|----------|
| `ransomware_common.yar` | Generic ransomware: file extension change, ransom notes, VSS deletion, CryptoAPI |
| `lockbit.yar` | LockBit 3.0: ransom note format, dropper anti-analysis, defence evasion |
| `blackcat_alphv.yar` | BlackCat/ALPHV: Rust binary markers, config JSON, ESXi targeting |
| `apt_lateral_movement.yar` | Mimikatz, LSASS dump, WMI lateral movement, AD recon, scheduled task persistence |
| `data_exfiltration.yar` | Rclone cloud exfil, cURL upload, FTP staging, 7-Zip data archiving |
| `backup_tampering.yar` | Veeam service stop, Windows Backup deletion, agent process kill, NAS share deletion |

Install `yara-python` for full scanning capability:
```bash
pip install yara-python
```
Without it, the scanner gracefully degrades: files are counted but no rules are evaluated.

---

## Sample Report

The screenshots below are taken from a live scan of [`OmarRao/analyzer`](https://github.com/OmarRao/analyzer), a deliberately vulnerable Python Flask banking application containing 414+ findings across multiple MITRE ATT&CK techniques.

**[View Full Sample Report (PDF)](https://github.com/OmarRao/secure-scope/blob/main/docs/sample_report.pdf)**

---

### Report Header & KPI Summary

The report header shows repository name, branch, language, license, scan timestamp, and a prominent **Risk Score** badge (0–100) with threat grade. Five KPI cards break down critical findings, warnings, dependency CVEs, ATT&CK technique count, and sandbox exit code.

![Report Header](docs/screenshots/07_report_header.png)

---

### Ransomware Intelligence Strip & Jump Navigation

The ransomware summary strip appears at the top of every report — showing Ransomware Risk score, Blast Radius, APT/Nation-State confidence, and Behaviors/Families count at a glance. Below it, a pill navigation bar lets you jump directly to any section.

![Ransomware Strip & Jump Bar](docs/screenshots/08_report_rw_strip.png)

---

### Analysis Charts

Six interactive Chart.js visualisations:

- **Severity Distribution** — Doughnut chart of Critical / Warning / Info counts
- **ATT&CK Technique Radar** — Radar plot across detected technique IDs
- **Findings by File** — Horizontal heatmap bars ranked by finding density
- **Severity per File** — Stacked bar chart (top 6 files, split by severity)
- **Language Risk Distribution** — Polar area chart from GitHub language stats
- **CWE Category Breakdown** — Horizontal bar of all CWE IDs ranked by frequency

![Analysis Charts](docs/screenshots/09_report_charts.png)

---

### Vulnerability Findings Table

Filterable by severity (All / Critical / Warning) with a live search box across rule ID, file path, CWE, and ATT&CK technique. Each row shows severity badge, Semgrep rule ID, file and line number, CWE tag, ATT&CK technique, tactic, and an expandable AI Fix Advisory panel when an LLM is configured.

![Findings Table](docs/screenshots/10_report_findings.png)

---

### Ransomware Intelligence Section

Full ransomware intelligence breakdown: hero KPI cards (risk score, blast radius, APT likelihood), behavioural pattern table, family match cards with origin/CVE/confidence data, a canvas-rendered global impact map, CVE cross-reference table, and affected code sections list.

![Ransomware Intelligence](docs/screenshots/11_report_ransomware.png)

---

## Architecture

```
main.py              CLI entry point
analyzer.py          Semgrep static scan + CWE -> ATT&CK mapping + dep CVEs
sandbox.py           Docker isolated runtime execution with strace observation
advisor.py           Multi-LLM fix advisor (Anthropic, OpenAI, Gemini, Groq, Ollama)
ransomware.py        Ransomware detection engine (9 families, 14 behaviors, blast radius)
threat_intel.py      Threat intelligence engine: 26 threat DB, feed, prevention guide
yara_scanner.py      YARA rule engine for backup/infrastructure scanning
yara_rules/          YARA .yar rule files (6 rule sets, 23 rules total)
github_agent.py      Auto-commit security fixes to GitHub branch
report.py            HTML + JSON report generation
ui/
  server.py          Flask + Socket.IO web server (scan pipeline + threat intel API)
  github_info.py     GitHub API fetcher (stars, commits, contributors, languages)
  templates/
    index.html       Dashboard: wizard, live pipeline, threat intel panels
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

# For YARA scanning (optional):
pip install yara-python
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

The composite risk score (0–100) is calculated as:

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
| 70–100 | CRITICAL |
| 45–69 | HIGH |
| 20–44 | MEDIUM |
| 0–19 | LOW |

---

## Releases

| Version | Date | Highlights |
|---------|------|------------|
| [v2.0.0](https://github.com/OmarRao/secure-scope/releases/tag/v2.0.0) | 2026-06-12 | Threat Intelligence Dashboard, YARA scanner, enterprise prevention guide, DR checklist, collapsible report sections |
| v1.0.0 | 2026-06-09 | Initial release: Semgrep scan, Docker sandbox, multi-LLM advisor, ransomware engine, visual report |

---

## Security Notes

- Sandbox containers run with `--network internal` (no internet), 512 MB RAM cap, PID limit 128
- Fixes are committed in dry-run mode by default. Pass `--commit` to write to GitHub
- GitHub PAT needs `repo` scope only
- Cloned repositories are deleted from temp storage after each scan
- API keys entered in the wizard are used only for the current scan and are never stored

---

---

**Built by [Omar Rao](https://github.com/OmarRao)**  
Engineer — Data Resilience, Cybersecurity and Privacy  
[LinkedIn](https://www.linkedin.com/in/omarrao/) &nbsp;·&nbsp; [Substack](https://omarrao.substack.com/)
