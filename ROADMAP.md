# SecureScope Roadmap

Forward-looking plan for SecureScope. Ratings are rough: **Impact** and **Effort**
are Low / Med / High. Items are grouped by phase; within a phase, ordered by value.

> SecureScope is proprietary software — © 2026 Omar Rao, all rights reserved.
> This roadmap is indicative and may change without notice.

---

## Phase 0 — Hardening (do before promoting the public app)

| Item | Impact | Effort | Notes |
|---|---|---|---|
| Server-side auth on `start_scan` | High | Med | Verify a Firebase ID token in the backend; today the sign-in gate is client-side only and bypassable. |
| Rate limiting + per-user/IP quotas | High | Med | Prevent abuse/cost on the free instance. Optional Cloudflare Turnstile. |
| Finish durable report storage (read side) | High | Low | Write side done (gzip HTML in Firestore); make history/share links open the stored blob so they survive redeploys. |
| Rotate exposed secrets | High | Low | Rotate the Render API key + any GitHub token that ever left a secure channel. |

## Phase 1 — Platform foundations *(in progress)*

| Item | Impact | Effort | Status |
|---|---|---|---|
| **Portfolio dashboard** | High | Med | ✅ Aggregate posture across a signed-in user's scanned repos (per-repo latest state, totals, worst offenders). |
| ROADMAP.md | Low | Low | ✅ This file. |

## Phase 2 — Continuous & in-flow

| Item | Impact | Effort | Notes / blockers |
|---|---|---|---|
| **Watch a repo → KEV/CVE alerts** | High | Med | Subscribe a repo; alert when a used dependency becomes CISA-KEV-listed or a new CVE lands. Needs a scheduler — GitHub Actions cron in-repo, or a paid Render cron. |
| **GitHub App + diff-aware PR bot** | High | High | Comment new-vs-fixed findings on each PR. **Needs user action:** register a GitHub App + webhook secret. `github_app.py` is a starting point. |
| Diff / PR-aware scanning | High | Med | Scan only changed files vs a baseline; classify new / fixed / pre-existing. |
| Multi-platform repos (GitLab, Bitbucket, Azure DevOps) | Med | Low–Med | Extend clone + URL parsing beyond GitHub. |

## Phase 3 — Deeper analysis

| Item | Impact | Effort | Notes |
|---|---|---|---|
| **Attack-path / exploit-chain view** | High | Med | Stitch findings (reachable dep CVE + tainted input + secret) into a narrated kill-chain in the report. |
| AI auto-fix for SAST findings (not just deps) | High | High | Generate patch + test, open a PR. Extends `autofix.py`. |
| Interprocedural taint / data-flow | High | High | "Is this injection reachable from real user input?" — extends reachability to SAST. |
| Auto threat model (data-flow + STRIDE) | Med | Med | Generate from code structure + findings. |
| Business-logic / broken-auth detection (LLM) | Med | Med | The class pattern scanners miss. |
| Live-secret validation | Med | Med | **Ethics-gated:** ownership-verified + consented only. |

## Phase 4 — Breadth of targets

| Item | Impact | Effort | Notes |
|---|---|---|---|
| ZIP / folder / snippet upload (no repo needed) | Med | Low | |
| Container images & registries directly | Med | Med | Needs Trivy binary in the image / a daemon. |
| Mobile apps (APK/IPA static analysis) | Med | High | |
| Cloud posture (CSPM) — read-only AWS/GCP | High | High | **Needs user action:** cloud credentials/roles. |

## Phase 5 — Workflow & integrations

| Item | Impact | Effort | Notes / blockers |
|---|---|---|---|
| Public REST API + API keys | Med | Med | Gate behind Phase 0 auth first. |
| Repo security badge (shields-style SVG) | Med | Low | Reads latest stored score. |
| Slack / Teams bot + ChatOps | Med | Med | **Needs user action:** create a Slack/Teams app. |
| VS Code / JetBrains extension | High | High | Separate project + marketplace publishing. |

## Phase 6 — GRC & collaboration

| Item | Impact | Effort | Notes |
|---|---|---|---|
| Compliance evidence packs (SOC 2 / ISO 27001) | High | Med | Builds on existing PCI/NIST/OWASP mapping. |
| Team workspaces (roles, ownership, comments, accept-risk) | High | High | |
| Bidirectional ticket sync (Jira / Linear / GitHub Issues) | Med | Med | |
| SLSA provenance + SBOM attestation/sharing (VEX) | Med | Med | |

## Phase 7 — The ambitious one

| Item | Impact | Effort | Notes |
|---|---|---|---|
| Autonomous security agent | High | High | Watches a repo, scans on push, prioritises by exploitability, opens fix PRs, follows up to resolution. The natural end-state. |

---

### Items that require the maintainer's action to build
These can't be completed autonomously — they need an account, registration, or paid resource:

- **GitHub App** registration + webhook secret (PR bot).
- **Slack/Teams** app creation (ChatOps).
- **Paid Render instance** (faster scans, persistent disk, native cron).
- **Cloud credentials** (CSPM).
- **IDE marketplace** publisher accounts (VS Code / JetBrains).

### Performance note
Scans are CPU-bound (Semgrep ~2–3 min on the 0.5-CPU free tier). A paid instance
roughly halves scan time and unlocks a persistent disk for durable reports.
