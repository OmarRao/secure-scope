# SecureScope Roadmap

Forward-looking plan for SecureScope. Ratings are rough: **Impact** and **Effort**
are Low / Med / High. Items are grouped by phase; within a phase, ordered by value.

> SecureScope is dual-licensed: **AGPL-3.0-or-later OR a commercial license**
> — © 2026 Omar Rao. See `LICENSE` and `COMMERCIAL-LICENSE.md`.
> This roadmap is indicative and may change without notice.

---

## Phase 0 — Hardening (do before promoting the public app)

| Item | Impact | Effort | Status |
|---|---|---|---|
| Server-side auth on `start_scan` | High | Med | ✅ Firebase ID token verified server-side (`firebase-admin`); enforcement auto-enables when credentials are configured. Verified live. |
| Rate limiting + per-user/IP quotas | High | Med | ✅ Per-IP sliding-window limiter on `start_scan` (`SCAN_RATE_LIMIT`/`SCAN_RATE_WINDOW`), fail-open. |
| Rotate exposed secrets | High | Low | ✅ Firebase service-account key rotated; Render secrets updated. |
| Durable report storage (read side) | High | Low | ✅ History drawer, portfolio, and `view.html` all decompress and open the gzip'd report stored in Firestore (`htmlz`), falling back to any external URL — survives redeploys. |

## Phase 1 — Platform foundations *(in progress)*

| Item | Impact | Effort | Status |
|---|---|---|---|
| **Portfolio dashboard** | High | Med | ✅ Aggregate posture across a signed-in user's scanned repos (per-repo latest state, totals, worst offenders). |
| ROADMAP.md | Low | Low | ✅ This file. |

## Phase 2 — Continuous & in-flow

| Item | Impact | Effort | Notes / blockers |
|---|---|---|---|
| **Watch a repo → KEV/CVE alerts** | High | Med | ✅ Repo-level watchlist (`watchlist.json`) monitored daily by a GitHub Actions cron (`watch-monitor.yml`); new dependency CVEs — KEV-flagged — open a GitHub Issue, state committed to `watch_state.json`. No external infra. *Next:* per-user watches from the web app (needs a Firebase service-account secret). |
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
| Repo security badge (shields-style SVG) | Med | Low | ✅ `GET /badge?repo=…` serves a shields-style SVG of the latest grade/score from the durable per-repo record. |
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
