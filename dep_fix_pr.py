"""
Auto dependency-fix pull requests (close the SCA find -> fix loop).

Given the enriched dependency CVEs from a scan, this module bumps the affected
package in its manifest to the lowest version that clears every CVE for that
package, then opens a single GitHub PR — prioritising the CVEs the exploit-
intelligence layer flagged as KEV-listed / high-EPSS / reachable.

Supported manifests: requirements.txt (PyPI) and package.json (npm). Other
ecosystems are reported in the PR body as "manual upgrade required" rather than
edited, so we never write a change we can't do safely.

The version-bumping core (`bump_*`, `plan_fixes`) is pure and offline-testable;
`create_dep_fix_pr` mirrors autofix.py's branch/push/PR flow and needs a token
with write access to the target repo. Nothing here executes target code.
"""

import json
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Version comparison ──────────────────────────────────────────────────────

def _ver_key(v: str):
    """Sortable key for a version string; falls back to string on parse error."""
    try:
        from packaging.version import Version
        return (0, Version(v))
    except Exception:
        # Best-effort numeric tuple, else raw string.
        parts = re.findall(r"\d+", v or "")
        if parts:
            return (1, tuple(int(p) for p in parts))
        return (2, v or "")


def _best_fixed(versions: list) -> str:
    """Highest fixed version — guarantees every CVE for the package is cleared."""
    clean = [v for v in (versions or []) if v and str(v).strip()]
    if not clean:
        return ""
    try:
        return max(clean, key=_ver_key)
    except Exception:
        return clean[0]


# ── Manifest bumping (pure) ─────────────────────────────────────────────────

def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def bump_requirements_txt(content: str, package: str, fixed: str):
    """Pin `package` to `==fixed` in a requirements.txt. Returns (new, changed)."""
    if not fixed:
        return content, False
    target = _norm(package)
    line_re = re.compile(
        r"^(?P<pre>\s*)(?P<name>[A-Za-z0-9._-]+)(?P<extra>\[[^\]]*\])?"
        r"(?P<spec>\s*(?:==|>=|<=|~=|!=|>|<)\s*[^\s;#]+)?"
        r"(?P<rest>\s*(?:;[^#]*)?(?:#.*)?)$"
    )
    out, changed = [], False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            out.append(line)
            continue
        m = line_re.match(line)
        if m and _norm(m.group("name")) == target:
            extra = m.group("extra") or ""
            rest = m.group("rest") or ""
            out.append(f"{m.group('pre')}{m.group('name')}{extra}=={fixed}{rest}")
            changed = True
        else:
            out.append(line)
    new = "\n".join(out)
    if content.endswith("\n"):
        new += "\n"
    return new, changed


def bump_package_json(content: str, package: str, fixed: str):
    """Set `package` to `fixed` across dependency blocks. Returns (new, changed)."""
    if not fixed:
        return content, False
    try:
        data = json.loads(content)
    except Exception:
        return content, False
    changed = False
    for block in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(block)
        if isinstance(deps, dict) and package in deps:
            if deps[package] != fixed:
                deps[package] = fixed
                changed = True
    if not changed:
        return content, False
    new = json.dumps(data, indent=2, ensure_ascii=False)
    if content.endswith("\n"):
        new += "\n"
    return new, changed


_ECO_MANIFEST = {"PyPI": "requirements.txt", "npm": "package.json"}
_BUMPERS = {"requirements.txt": bump_requirements_txt, "package.json": bump_package_json}


# ── Planning ────────────────────────────────────────────────────────────────

def plan_fixes(vulns: list, repo_root: str = "") -> dict:
    """Group vulnerabilities into per-(manifest, package) upgrade actions.

    Returns {"fixable": [...], "manual": [...]}. Each fixable item:
      {manifest, ecosystem, package, current, fixed, cves, kev, epss, reachable}
    """
    root = Path(repo_root) if repo_root else None
    by_key: dict = {}
    manual = []
    for v in vulns or []:
        eco = v.get("ecosystem", "")
        pkg = v.get("package_name", "")
        fixed_versions = v.get("fixed_versions", []) or []
        cve = v.get("primary_cve") or v.get("vuln_id") or ""
        manifest = _rel_manifest(v.get("file_path", ""), eco, root)
        bumpable = manifest and Path(manifest).name in _BUMPERS and fixed_versions
        if not bumpable:
            manual.append({
                "ecosystem": eco, "package": pkg, "cve": cve,
                "current": v.get("package_version", ""),
                "fixed_versions": fixed_versions,
                "reason": "unsupported manifest" if fixed_versions else "no fixed version published",
            })
            continue
        key = (manifest, pkg)
        entry = by_key.setdefault(key, {
            "manifest": manifest, "ecosystem": eco, "package": pkg,
            "current": v.get("package_version", ""), "fixed_candidates": [],
            "cves": [], "kev": False, "epss": 0.0, "reachable": None,
        })
        entry["fixed_candidates"].extend(fixed_versions)
        if cve and cve not in entry["cves"]:
            entry["cves"].append(cve)
        entry["kev"] = entry["kev"] or bool(v.get("kev"))
        entry["epss"] = max(entry["epss"], float(v.get("epss", 0.0) or 0.0))
        if v.get("reachable") is True:
            entry["reachable"] = True
        elif entry["reachable"] is None and v.get("reachable") is not None:
            entry["reachable"] = v.get("reachable")

    fixable = []
    for entry in by_key.values():
        entry["fixed"] = _best_fixed(entry.pop("fixed_candidates"))
        if entry["fixed"]:
            fixable.append(entry)
    # Most actionable first: KEV, reachable, EPSS.
    fixable.sort(key=lambda e: (1 if e["kev"] else 0,
                                1 if e["reachable"] else 0,
                                e["epss"]), reverse=True)
    return {"fixable": fixable, "manual": manual}


def _rel_manifest(file_path: str, eco: str, root) -> str:
    """Repo-relative manifest path from a scan's absolute file_path."""
    if not file_path:
        return _ECO_MANIFEST.get(eco, "")
    p = Path(file_path)
    if root:
        try:
            return p.relative_to(root).as_posix()
        except ValueError:
            pass
    return p.name


# ── PR creation ─────────────────────────────────────────────────────────────

def create_dep_fix_pr(repo_url: str, gh_token: str, workdir: str,
                      vulns: list, ts: str) -> dict:
    """Bump manifests in the cloned workdir and open a PR. Returns a result dict."""
    import subprocess
    from github import Github

    plan = plan_fixes(vulns, workdir)
    fixable = plan["fixable"]
    if not fixable:
        return {"ok": False, "url": "", "applied": 0, "reason": "no auto-fixable CVEs"}

    branch = f"securescope/dep-fixes-{ts}"
    try:
        subprocess.run(["git", "config", "user.email", "securescope@users.noreply.github.com"], cwd=workdir, check=True)
        subprocess.run(["git", "config", "user.name", "SecureScope"], cwd=workdir, check=True)
        subprocess.run(["git", "checkout", "-b", branch], cwd=workdir, check=True)

        applied = 0
        for e in fixable:
            mpath = Path(workdir) / e["manifest"]
            if not mpath.exists():
                continue
            bumper = _BUMPERS.get(mpath.name)
            if not bumper:
                continue
            content = mpath.read_text(encoding="utf-8", errors="replace")
            new, changed = bumper(content, e["package"], e["fixed"])
            if changed:
                mpath.write_text(new, encoding="utf-8")
                applied += 1

        if applied == 0:
            return {"ok": False, "url": "", "applied": 0, "reason": "no manifest changes applied"}

        subprocess.run(["git", "add", "-A"], cwd=workdir, check=True)
        subprocess.run(["git", "commit", "-m",
                        f"[SecureScope] Upgrade {applied} vulnerable dependenc{'y' if applied == 1 else 'ies'}"],
                       cwd=workdir, check=True)

        parsed = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
        if not parsed:
            return {"ok": False, "url": "", "applied": applied, "reason": "unparseable repo url"}
        owner, repo_name = parsed.group(1), parsed.group(2)
        push_url = f"https://x-access-token:{gh_token}@github.com/{owner}/{repo_name}.git"
        subprocess.run(["git", "push", push_url, branch], cwd=workdir, check=True)

        gh = Github(gh_token)
        repo = gh.get_repo(f"{owner}/{repo_name}")
        pr = repo.create_pull(
            title=f"[SecureScope] Upgrade {applied} vulnerable dependenc{'y' if applied == 1 else 'ies'}",
            body=build_pr_body(plan, applied),
            head=branch, base=repo.default_branch,
        )
        logger.info("Dependency fix PR opened: %s", pr.html_url)
        return {"ok": True, "url": pr.html_url, "applied": applied,
                "manual": len(plan["manual"])}
    except Exception as exc:
        logger.warning("Dependency fix PR failed: %s", exc)
        return {"ok": False, "url": "", "applied": 0, "reason": str(exc)}


def build_pr_body(plan: dict, applied: int) -> str:
    lines = [
        "## SecureScope — Dependency upgrades",
        "",
        "Automatically generated by [SecureScope](https://omarrao.github.io/secure-scope/). "
        "Each package below is bumped to the lowest version that clears every known CVE "
        "for it, prioritised by real-world exploitability.",
        "",
        "| Package | Ecosystem | From | To | CVEs | Exploitability |",
        "|---|---|---|---|---|---|",
    ]
    for e in plan["fixable"]:
        tags = []
        if e.get("kev"):
            tags.append("🔴 KEV")
        if e.get("epss"):
            tags.append(f"EPSS {e['epss'] * 100:.0f}%")
        if e.get("reachable") is True:
            tags.append("reachable")
        lines.append(
            f"| `{e['package']}` | {e['ecosystem']} | {e.get('current') or '—'} | "
            f"**{e['fixed']}** | {', '.join(e['cves']) or '—'} | {' · '.join(tags) or '—'} |"
        )
    if plan.get("manual"):
        lines += ["", "### Manual upgrade required", ""]
        for m in plan["manual"]:
            fv = ", ".join(m.get("fixed_versions") or []) or "no published fix"
            lines.append(f"- `{m['package']}` ({m['ecosystem']}) — {m['cve']} — fix: {fv} "
                         f"_({m['reason']})_")
    lines += [
        "",
        "> ⚠️ Review and run your test suite before merging — a version bump can "
        "introduce breaking changes. SecureScope validates that each target version "
        "clears the CVE, not that it is API-compatible with your code.",
    ]
    return "\n".join(lines)
