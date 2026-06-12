# Security Policy — SecureScope

**Maintainer:** Omar Rao — Engineer, Data Resilience, Privacy & Cybersecurity Expert  
**Repository:** [OmarRao/secure-scope](https://github.com/OmarRao/secure-scope)  
**Effective date:** 2026-06-12  
**Policy version:** 2.0.0

---

## Table of Contents

1. [Supported Versions](#1-supported-versions)
2. [Reporting a Vulnerability](#2-reporting-a-vulnerability)
3. [Disclosure Policy](#3-disclosure-policy)
4. [Scope](#4-scope)
5. [Out of Scope](#5-out-of-scope)
6. [Severity Classification](#6-severity-classification)
7. [Response SLA](#7-response-sla)
8. [Security Architecture](#8-security-architecture)
9. [Secure Coding Standards](#9-secure-coding-standards)
10. [Dependency Management](#10-dependency-management)
11. [Secret & Credential Handling](#11-secret--credential-handling)
12. [Ransomware & APT Threat Response](#12-ransomware--apt-threat-response)
13. [Data Protection & Resilience Requirements](#13-data-protection--resilience-requirements)
14. [YARA Rule Governance](#14-yara-rule-governance)
15. [Incident Response](#15-incident-response)
16. [Security Contacts](#16-security-contacts)

---

## 1. Supported Versions

Only the latest release receives security patches. Older versions are not supported.

| Version | Status | Support |
|---------|--------|---------|
| **v2.0.0** | ✅ Current | Security fixes, patches |
| v1.0.0 | ⚠️ End of Life | No patches — upgrade to v2.0.0 |
| < v1.0.0 | ❌ Unsupported | No patches |

Users running any version below `v2.0.0` are strongly encouraged to upgrade immediately. Breaking changes between major versions are documented in the [Releases](https://github.com/OmarRao/secure-scope/releases) page.

---

## 2. Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Public disclosure before a patch is available puts all users at risk.

### How to Report

1. **GitHub Private Security Advisory (preferred)**  
   Use the [Security Advisories](https://github.com/OmarRao/secure-scope/security/advisories/new) tab in this repository to submit a confidential report. GitHub keeps the details private until a fix is released.

2. **Email (alternative)**  
   Send a detailed report to the maintainer. Include `[SECURITY]` in the subject line. Encrypt sensitive reports using the maintainer's public PGP key (available on request).

### What to Include

Please provide as much detail as possible to help us reproduce and fix the issue quickly:

- **Affected component** — which file, module, or endpoint
- **Vulnerability type** — e.g. RCE, SSRF, path traversal, injection, auth bypass
- **Steps to reproduce** — minimal, numbered steps from a clean state
- **Proof of concept** — code snippet, curl command, or screenshot (if safe to share)
- **Impact assessment** — what an attacker could achieve
- **Suggested fix** — if you have one
- **Your SecureScope version** — output of `git log --oneline -1`
- **Environment** — OS, Python version, Docker version (if applicable)

Reports submitted without reproduction steps may be deprioritised. We will acknowledge receipt within **48 hours** and provide an initial assessment within **5 business days**.

---

## 3. Disclosure Policy

SecureScope follows **Coordinated Vulnerability Disclosure (CVD)**:

1. Reporter submits a private report via GitHub Security Advisory or email.
2. Maintainer acknowledges receipt within **48 hours**.
3. Maintainer investigates, confirms severity, and assigns a CVE if warranted.
4. A patch is developed and tested in a private branch.
5. A patched release is published.
6. A GitHub Security Advisory is published with full details, credit, and CVE reference.
7. Reporter is credited in the advisory unless they request anonymity.

**Maximum embargo period:** 90 days from the date of initial report. If a fix is not available within 90 days, the maintainer will coordinate with the reporter on whether to extend the embargo or proceed with partial disclosure.

We will never take legal action against researchers who report in good faith and follow this policy.

---

## 4. Scope

The following are **in scope** for vulnerability reports:

| Component | Path | Risk Area |
|-----------|------|-----------|
| Flask web server | `ui/server.py` | SSRF, RCE, auth bypass, DoS |
| Semgrep analysis pipeline | `analyzer.py` | Command injection, path traversal |
| Docker sandbox | `sandbox.py` | Container escape, privilege escalation |
| AI advisor | `advisor.py` | Prompt injection, API key leakage |
| GitHub agent | `github_agent.py` | Token leakage, unauthorised commits |
| Ransomware engine | `ransomware.py` | Logic bypass, false negative manipulation |
| Threat intelligence | `threat_intel.py` | Data integrity, feed manipulation |
| YARA scanner | `yara_scanner.py` | Path traversal, rule injection |
| Report generation | `report.html`, `gen_pdf_report.py` | XSS, HTML injection in report output |
| Dependency chain | `requirements.txt` | Supply chain compromise |
| YARA rules | `yara_rules/*.yar` | Rule logic bypasses |

---

## 5. Out of Scope

The following are **not** eligible for vulnerability reports:

- Vulnerabilities in the **target repositories being scanned** — SecureScope analyses external code; findings in that code are the tool's intended output, not a vulnerability in SecureScope itself.
- Bugs requiring **physical access** to the host machine.
- **Denial of service** against the development server (`--allow-unsafe-werkzeug`) when it is correctly documented as not production-safe.
- **Self-XSS** (where the attacker can only attack themselves).
- Issues in **third-party dependencies** that do not affect SecureScope's attack surface — please report those directly to the dependency maintainers.
- **Missing security headers** on the development server (`X-Frame-Options`, `CSP`, etc.) — these are known and documented. SecureScope is not designed to run as a public-facing production service without a reverse proxy.
- **Rate limiting** on the local development server.
- Vulnerabilities that require the attacker to already have **administrator or root access** to the host.

---

## 6. Severity Classification

SecureScope uses the **CVSS v3.1** scoring system for severity classification. Severity determines patch SLA (see Section 7).

| Severity | CVSS Score | Definition | Example |
|----------|------------|------------|---------|
| **CRITICAL** | 9.0–10.0 | Unauthenticated RCE, complete system compromise, container escape | `subprocess.run(user_input, shell=True)` reachable from the web UI |
| **HIGH** | 7.0–8.9 | Authenticated RCE, sensitive data exfiltration, privilege escalation | LLM API key extracted from server response |
| **MEDIUM** | 4.0–6.9 | Partial data exposure, SSRF, CSRF, path traversal with limited impact | Scan pipeline reads arbitrary files from the host via crafted repo URL |
| **LOW** | 0.1–3.9 | Minor information disclosure, non-exploitable misconfigurations | Server version header leaking Python/Werkzeug version |
| **INFORMATIONAL** | N/A | Best-practice deviations with no direct security impact | Missing `Referrer-Policy` header |

---

## 7. Response SLA

| Severity | Acknowledgement | Initial Assessment | Patch Target | Advisory Publication |
|----------|----------------|-------------------|--------------|---------------------|
| CRITICAL | 24 hours | 48 hours | 7 days | On patch release |
| HIGH | 48 hours | 5 business days | 30 days | On patch release |
| MEDIUM | 48 hours | 7 business days | 60 days | On patch release |
| LOW | 72 hours | 14 business days | 90 days | On patch release |
| Informational | 1 week | — | Next minor release | Optional |

If a CRITICAL vulnerability is actively exploited in the wild, the SLA is **48 hours** for an emergency patch release regardless of completeness.

---

## 8. Security Architecture

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  User Browser                                                │
│  (Untrusted input: GitHub URL, LLM API key, scan options)   │
└───────────────────────┬─────────────────────────────────────┘
                        │ WebSocket + REST (localhost only)
┌───────────────────────▼─────────────────────────────────────┐
│  Flask + Socket.IO Server  (ui/server.py)                    │
│  Validates: URL format, path sanitisation, API key masking   │
└───┬───────────────┬──────────────────┬───────────────────────┘
    │               │                  │
    ▼               ▼                  ▼
┌───────┐    ┌───────────┐    ┌─────────────────┐
│ Git   │    │  Semgrep  │    │ Docker Sandbox  │
│ clone │    │  process  │    │ (--network=none │
│ (tmp) │    │           │    │  --read-only)   │
└───────┘    └───────────┘    └─────────────────┘
    │
    ▼ (cleaned up after scan)
┌──────────────────────────────┐
│  Temp directory (OS-managed) │
│  Auto-deleted after scan     │
└──────────────────────────────┘
```

### Key Security Controls

| Control | Implementation |
|---------|----------------|
| URL validation | `parse_repo_url()` in `github_info.py` — allowlists `github.com` only |
| Path sanitisation | All file paths resolved via `pathlib.Path` with `.resolve()` |
| Subprocess sandboxing | All external commands use list form (no `shell=True`) |
| Temp directory cleanup | `shutil.rmtree(workdir)` in `finally` block after every scan |
| Docker isolation | `--network=internal`, `--memory=512m`, `--pids-limit=128`, `--read-only` |
| Secret masking | API keys accepted only in-memory per session; never written to disk or logs |
| YARA path restriction | Scanner validates target path exists before traversal |
| Report output | Jinja2 auto-escaping enabled; user-supplied data passed through `tojson` filter |

---

## 9. Secure Coding Standards

All contributions to SecureScope must adhere to the following:

### Python

- **No `shell=True`** in any `subprocess` call. Use list form: `subprocess.run(["git", "clone", url, dest])`.
- **No `eval()` or `exec()`** on any data originating from user input or scanned repositories.
- **Use `pathlib.Path`** for all file path operations. Call `.resolve()` before any file read/write and validate the resolved path is within the expected directory.
- **Never log secrets.** API keys, tokens, and passwords must be masked in logs (replace with `***`).
- **Use `tempfile.mkdtemp()`** for all temporary directories. Always clean up in a `finally` block.
- **Validate all external inputs.** GitHub URLs must match the pattern `https://github.com/<owner>/<repo>` before any operation is performed.
- **Pin dependency versions** in `requirements.txt`. Use exact versions (`==`) not ranges (`>=`).

### Jinja2 / HTML

- **Auto-escaping is mandatory.** Never use `| safe` on user-supplied data.
- **JSON serialise** any data passed from Python to JavaScript using `| tojson`.
- **Never inject raw repository content** (commit messages, file names, descriptions) directly into HTML without escaping.

### JavaScript

- **No `innerHTML` on untrusted data.** Use `textContent` or `createElement`/`appendChild`.
- **No `eval()`.** Use `JSON.parse()` for JSON, not `eval()`.
- **Sanitise DOM insertations** from API responses using textContent assignments.

### Docker Sandbox

- Sandbox containers must always run with:
  - `--network=internal` (no internet access)
  - `--memory=512m`
  - `--pids-limit=128`
  - `--read-only` (read-only root filesystem)
  - `--cap-drop=ALL`
  - `--security-opt=no-new-privileges`

### YARA Rules

- YARA rules must not use `include` directives pointing to external or user-supplied paths.
- Rule strings must be reviewed to avoid catastrophic backtracking (ReDoS in regex conditions).
- All new rule files must include a header comment block with: author, date, threat family, and a description of what the rule detects.

---

## 10. Dependency Management

- All Python dependencies are pinned in `requirements.txt` using exact versions.
- `pip-audit` is run as part of every scan (`check_dependency_vulns()` in `analyzer.py`) to detect CVEs in scanned repositories' dependencies.
- SecureScope's own dependencies are audited before each release using:
  ```bash
  pip-audit -r requirements.txt
  ```
- Dependencies with known critical or high CVEs will block a release.
- No dependency may be added without a documented justification in the PR description.
- Transitive dependencies are reviewed using `pip-audit --fix --dry-run` before major releases.

### Supply Chain Controls

- No unpinned `git+` or `http+` dependencies are permitted.
- All packages must be sourced from PyPI only (no custom registries).
- The `yara-python` optional dependency is clearly documented as optional so users who do not need YARA scanning are not exposed to that attack surface.

---

## 11. Secret & Credential Handling

SecureScope handles several types of secrets at runtime. The following rules apply unconditionally:

| Secret type | Handling rule |
|-------------|--------------|
| LLM API keys (Anthropic, OpenAI, Gemini, Groq) | Accepted via wizard input or environment variable. Held in memory only for the duration of one scan. Never written to disk, logged, or included in reports. |
| GitHub Personal Access Token (PAT) | Same as above. Used only for the `github_agent.py` commit flow. Scope must be `repo` only. |
| GITHUB_TOKEN (env) | Read from environment. Never echoed to the browser or included in Socket.IO events. |
| Semgrep registry token | Not required. SecureScope uses only open-source Semgrep rules. |
| Scan report content | Reports may contain file paths and code snippets from the scanned repository. Reports are stored in the local `reports/` directory which is gitignored. |

**Developers must never commit secrets.** A `.gitignore` entry covers `.env`, `*.key`, `*.pem`, and `reports/`. Pre-commit hooks are recommended:

```bash
pip install pre-commit detect-secrets
pre-commit install
```

---

## 12. Ransomware & APT Threat Response

As a tool that analyses ransomware indicators, SecureScope itself must be defended against the threats it detects.

### If SecureScope's host is compromised:

1. **Isolate immediately.** Disconnect from the network. Do not attempt to clean the system in place.
2. **Preserve evidence.** Take a memory dump and disk image before shutting down.
3. **Check scan outputs.** Verify that no scanned repository executed malicious code outside the Docker sandbox.
4. **Rotate all secrets.** Revoke and reissue all LLM API keys, GitHub PATs, and any other credentials that were present in environment variables or in-memory during the session.
5. **Review Docker logs.** Inspect sandbox container logs for evidence of breakout attempts.
6. **Report to maintainer.** If the compromise may have affected the tool's integrity (e.g., a supply chain attack on a dependency), notify the maintainer immediately via the private reporting channel.

### APT Indicators Relevant to This Tool

SecureScope's threat intelligence database (`threat_intel.py`) tracks APT groups known to target development environments and CI/CD pipelines. If SecureScope detects any of the following in a scanned repository, treat the finding as potentially indicative of a targeted attack rather than opportunistic malware:

- Volt Typhoon, APT29/Cozy Bear, Lazarus Group, Scattered Spider

See `THREAT_DB` in `threat_intel.py` for full TTPs and IOCs.

---

## 13. Data Protection & Resilience Requirements

SecureScope processes sensitive data (code, API keys, security findings). The following data protection requirements apply to anyone operating SecureScope in an enterprise environment:

### Data Classification

| Data type | Classification | Retention |
|-----------|---------------|-----------|
| Scanned repository code | Confidential | Deleted immediately after scan (temp dir cleanup) |
| Security findings (JSON) | Confidential | `reports/` directory — operator controls retention |
| LLM API keys | Secret | In-memory only, never persisted |
| GitHub PAT | Secret | In-memory only, never persisted |
| Threat intelligence data | Internal | Bundled in `threat_intel.py`, updated with releases |
| YARA scan results | Confidential | Displayed in browser only, not written to disk |

### 3-2-1-1-0 Backup Rule

For any environment where SecureScope report outputs are retained:

- **3** copies of report data
- **2** different storage media types
- **1** copy offsite or in a separate cloud region
- **1** copy air-gapped or offline
- **0** errors verified by automated restore testing

### Operator Responsibilities

- SecureScope is designed for **local or intranet use only**. Do not expose port 5001 directly to the internet.
- If deploying behind a reverse proxy (nginx, Caddy), enforce TLS 1.2+, HSTS, and rate limiting.
- Restrict access to the `reports/` directory. Reports may contain sensitive code and vulnerability details.
- Enable OS-level audit logging on the machine running SecureScope.
- Review YARA scanner target path inputs — only scan paths within expected backup directories.

---

## 14. YARA Rule Governance

SecureScope ships with 6 predefined YARA rule sets in the `yara_rules/` directory. The following governance rules apply:

### Acceptance Criteria for New Rules

A YARA rule will be accepted into the official rule set if it meets **all** of the following:

1. **Header block present** — includes rule name, author, date, threat family, and description.
2. **No external includes** — rules must be self-contained.
3. **No ReDoS-prone regex** — all regex conditions reviewed for catastrophic backtracking.
4. **Tested against known-clean samples** — the rule must not fire on common benign files (false positive rate < 0.1%).
5. **Tested against known-malicious samples** — the rule must fire on at least one confirmed sample of the target threat.
6. **Referenced to a public threat report** — a link to a public malware analysis (e.g., CISA advisory, vendor report) must be included in the rule comment.
7. **Severity assigned** — `CRITICAL`, `HIGH`, or `MEDIUM` meta field present.

### Rule Update Schedule

- YARA rules are reviewed and updated with each SecureScope minor release (v2.x.0).
- Emergency rule updates for actively exploited threats may be shipped as patch releases (v2.0.x).
- Rules for a threat actor that has been inactive for more than 24 months may be deprecated but are never deleted.

### False Positive Handling

If a YARA rule produces false positives in your environment:

1. Open a GitHub Issue with the rule name, file type, and a sanitised sample of the matching content (no sensitive data).
2. Label the issue `yara-fp`.
3. A rule update will be prioritised in the next patch release.

---

## 15. Incident Response

### Incident Severity Levels

| Level | Definition | Example |
|-------|-----------|---------|
| **P1 — Critical** | Active exploitation, data breach, or supply chain compromise | A dependency is found to contain a backdoor; a YARA rule is found to exfiltrate data |
| **P2 — High** | Confirmed vulnerability with high exploitability | Unauthenticated RCE via the Flask server |
| **P3 — Medium** | Confirmed vulnerability with limited exploitability | Authenticated path traversal allowing config file reads |
| **P4 — Low** | Unconfirmed or theoretical risk | Potential timing side-channel in API key comparison |

### Response Playbook

#### P1 — Critical (within 24 hours)

- [ ] Take the service offline immediately if externally exposed
- [ ] Preserve all logs and memory artifacts
- [ ] Rotate all credentials and revoke all tokens
- [ ] Notify all known users via GitHub Security Advisory
- [ ] Begin root cause analysis
- [ ] Publish emergency patch release
- [ ] Publish post-incident report within 7 days

#### P2 — High (within 7 days)

- [ ] Assess whether active exploitation is occurring
- [ ] Develop and test a patch in a private branch
- [ ] Coordinate disclosure with reporter
- [ ] Publish patched release
- [ ] Publish Security Advisory with CVE

#### P3 — Medium / P4 — Low

- [ ] Confirm and reproduce the issue
- [ ] Schedule fix for next regular release
- [ ] Update Security Advisory after patch ships

### Contact for Active Incidents

For P1/P2 incidents requiring immediate attention, report via [GitHub Security Advisories](https://github.com/OmarRao/secure-scope/security/advisories/new). Include `[P1-INCIDENT]` or `[P2-INCIDENT]` in the advisory title.

---

## 16. Security Contacts

| Role | Contact |
|------|---------|
| **Primary maintainer** | Omar Rao — via [GitHub](https://github.com/OmarRao) |
| **Security reports** | [GitHub Security Advisories](https://github.com/OmarRao/secure-scope/security/advisories/new) |
| **Public vulnerabilities** | [GitHub Issues](https://github.com/OmarRao/secure-scope/issues) — for non-sensitive bugs only |

---

## Acknowledgements

We thank all security researchers who responsibly disclose vulnerabilities. Contributors who report valid security issues will be credited by name (or pseudonym, if preferred) in the Security Advisory for the patched release.

---

## Policy Review

This security policy is reviewed and updated with each major SecureScope release. Significant changes to the policy will be communicated via the [Releases](https://github.com/OmarRao/secure-scope/releases) page and noted in the commit history of this file.

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2026-06-12 | Initial policy — covers YARA governance, threat intel, ransomware response, data protection |

---

*SecureScope Security Policy — maintained by Omar Rao.*  
*Data Resilience, Privacy & Cybersecurity Expert.*
