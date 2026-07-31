# Dependency License Review

**This is a technical inventory, not legal advice, and not a statement of legal
compliance.** Licenses below were identified from public package metadata and may
be incomplete or out of date. Confirm each license against the exact version you
ship, and seek legal review before relying on this for licensing decisions —
especially given this project's move to AGPL-3.0.

_Generated for the `licensing/dual-license-agpl-commercial` branch._

## 1. Direct production dependencies (`requirements.txt`)

| Package | Declared license (verify) | Notes |
|---|---|---|
| flask | BSD-3-Clause | Permissive |
| flask-socketio | MIT | Permissive |
| eventlet | MIT | Permissive |
| gunicorn | MIT | Permissive |
| anthropic | MIT | Permissive |
| openai | Apache-2.0 | Permissive (verify — some releases MIT) |
| google-generativeai | Apache-2.0 | Permissive |
| groq | Apache-2.0 | Permissive (verify) |
| **PyGithub** | **LGPL-3.0-or-later** | ⚠️ **Weak copyleft** — review linkage/interaction with an AGPL project |
| reportlab | BSD-3-Clause | Permissive (open-source toolkit; commercial add-ons separate) |
| defusedxml | PSF-2.0 | Permissive |
| docker (docker-py) | Apache-2.0 | Permissive |
| **semgrep** | **LGPL-2.1** | ⚠️ **Weak copyleft** — invoked as a separate process (CLI); confirm distribution model |
| pip-audit | Apache-2.0 | Permissive |
| urllib3 | MIT | Permissive |
| pyjwt | MIT | Permissive |
| requests | Apache-2.0 | Permissive |
| idna | BSD-3-Clause | Permissive |

## 2. External tools invoked at runtime (not Python imports)

These are executed as separate binaries/subprocesses when the relevant feature is
enabled; they are not linked into the codebase.

| Tool | Declared license (verify) | Feature |
|---|---|---|
| git | GPL-2.0 | Repository cloning (separate process) |
| **semgrep** (CLI) | **LGPL-2.1** | Static analysis |
| trivy | Apache-2.0 | Container/IaC scanning (optional) |
| checkov | Apache-2.0 | IaC scanning (optional) |
| nuclei | MIT | DAST (optional, CLI-only) |
| OWASP ZAP | Apache-2.0 | DAST (optional, CLI-only) |
| playwright / Chromium | Apache-2.0 / BSD-style | PDF rendering / screenshots |

## 3. Front-end / CDN dependencies (loaded in the browser, not bundled)

| Dependency | Declared license (verify) | Where |
|---|---|---|
| Firebase JS SDK | Apache-2.0 | Auth / Firestore (docs pages) |
| Chart.js | MIT | Report charts |
| socket.io client | MIT | Live scan progress |
| Geist / Geist Mono fonts | SIL OFL-1.1 | Web UI typography (Google Fonts) |
| Tabler Icons | MIT | Icon font (visualization widget only) |

## 4. Direct development / tooling dependencies

| Dependency | Declared license (verify) | Use |
|---|---|---|
| pytest | MIT | Test suite (`tests/`) |
| playwright (Python) | Apache-2.0 | Screenshot generation (dev only) |
| Pillow | HPND (PIL) | Screenshot verification (dev only) |

## 5. Dependencies with missing / unknown / unverified licenses

- Transitive dependencies of the packages above are **not** enumerated here and
  have **not** been reviewed.
- `openai` and `groq` license fields should be confirmed against the pinned
  release, as they have varied across versions.
- No `package.json` / `pyproject.toml` / lock file exists, so there is **no
  pinned, machine-readable dependency graph** — versions are floor-pinned in
  `requirements.txt`. A locked manifest would make this review reproducible.

## 6. Copyleft / source-available / potentially incompatible terms to review

- **PyGithub (LGPL-3.0)** — imported as a Python library. LGPL ↔ AGPL interaction
  (dynamic use, distribution) should be reviewed by counsel.
- **semgrep (LGPL-2.1)** — used both as a Python dependency and as a CLI. Review
  how it is distributed with your product.
- **git (GPL-2.0)** — used as a separate process; typically not a linkage concern,
  but noted for completeness.
- No dependency identified here declares a **non-commercial** or **AGPL** license,
  but this has not been exhaustively verified across the transitive tree.

## 7. Copied / vendored third-party code

- Based on inspection, the source files in this repository appear to be
  first-party (authored by Omar Rao). No third-party source trees appear to be
  vendored into the repository.
- `docs/firebase-config.js` contains the project's own public Firebase web config
  (not third-party code).
- This has not been checked with an automated origin/provenance scanner — confirm
  before relying on it.

## 8. Items explicitly flagged for legal review

1. AGPL-3.0 compatibility of **PyGithub (LGPL-3.0)** and **semgrep (LGPL-2.1)**.
2. Whether any **commercial-license** offering can lawfully redistribute the
   copyleft tools above, or whether they must remain user-installed.
3. Confirmation of `openai` / `groq` license for the pinned versions.
4. Transitive dependency licenses (not reviewed here).
5. Font and icon-font redistribution terms (OFL-1.1 / MIT) if assets are ever
   bundled rather than loaded from a CDN.

_This document is a starting inventory to support a legal review. It does not
assert that the project is compliant with any license or law._
