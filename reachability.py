"""
Reachability analysis for dependency CVEs (SCA noise reduction).

A vulnerable package only matters if your code actually *uses* it. A CVE in a
transitive dependency you never import is far lower priority than the same CVE
in a package you call directly. This module answers, per vulnerable package:

    Is it imported / required anywhere in the first-party source?

Scope (deliberately pragmatic, not a full interprocedural call graph):
  - Python : `import pkg`, `import pkg.sub`, `from pkg import ...`
  - JS/TS  : `require('pkg')`, `import ... from 'pkg'`, `import 'pkg'`,
             dynamic `import('pkg')`  (incl. scoped @scope/pkg and subpaths)

Each vulnerability is annotated with:
  - reachable        : True (imported) | False (declared, not imported) | None
                       (ecosystem we don't statically analyse — treated as Unknown)
  - reachable_files  : number of first-party files importing the package

This is a heuristic: import presence, not execution proof. It is designed to
*demote* obviously-unused dependencies, never to hide a finding — anything we
can't analyse stays Unknown and keeps its original priority. Pure static reads
of the target's own source; no execution.
"""

import re
from pathlib import Path

# Directories that are not first-party source — skip them entirely.
_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", "site-packages", ".tox", ".mypy_cache", ".pytest_cache",
    "vendor", "third_party", "bower_components", ".next", ".nuxt", "coverage",
}

# PyPI distribution name -> import (module) name, where they differ.
_PY_ALIASES = {
    "beautifulsoup4": "bs4", "pyyaml": "yaml", "pillow": "PIL",
    "scikit-learn": "sklearn", "python-dateutil": "dateutil",
    "msgpack-python": "msgpack", "opencv-python": "cv2",
    "python-jose": "jose", "pyjwt": "jwt", "protobuf": "google.protobuf",
    "setuptools": "setuptools", "attrs": "attr", "python-magic": "magic",
    "websocket-client": "websocket", "faiss-cpu": "faiss",
    "google-cloud-storage": "google.cloud.storage", "typing-extensions": "typing_extensions",
}

_ANALYSABLE = {"PyPI", "npm"}
_MAX_BYTES = 800_000  # skip files larger than this


def _iter_source_files(repo_path: Path, exts: tuple):
    for p in repo_path.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in exts:
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


def _py_import_names(pkg: str) -> set:
    """Candidate top-level module names a PyPI package might be imported as."""
    pkg_l = pkg.lower().strip()
    names = set()
    if pkg_l in _PY_ALIASES:
        names.add(_PY_ALIASES[pkg_l].split(".")[0])
    # Common transforms: dashes/dots -> underscores.
    names.add(pkg_l.replace("-", "_").replace(".", "_"))
    names.add(pkg_l.replace("-", "").replace(".", ""))
    names.add(pkg_l)
    return {n for n in names if n}


def _npm_import_targets(pkg: str) -> set:
    """The specifier(s) an npm package is imported/required as."""
    return {pkg} if pkg else set()


def _scan_python(repo_path: Path, pkgs: set) -> dict:
    """Return {pkg: file_count} for Python packages imported in source."""
    counts = {p: 0 for p in pkgs}
    # module-name -> set(pkgs) that could produce it
    mod_to_pkgs: dict[str, set] = {}
    for p in pkgs:
        for name in _py_import_names(p):
            mod_to_pkgs.setdefault(name, set()).add(p)
    if not mod_to_pkgs:
        return counts
    import_re = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z0-9_\.]+)", re.MULTILINE)
    for f in _iter_source_files(repo_path, (".py", ".pyi")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        mods_here = {m.split(".")[0] for m in import_re.findall(text)}
        for mod in mods_here:
            for pkg in mod_to_pkgs.get(mod, ()):
                counts[pkg] += 1
    return counts


def _scan_js(repo_path: Path, pkgs: set) -> dict:
    counts = {p: 0 for p in pkgs}
    if not pkgs:
        return counts
    # require('x'), import ... from 'x', import 'x', import('x')
    spec_re = re.compile(r"""(?:require\(|from\s+|import\s+|import\()\s*['"]([^'"]+)['"]""")
    for f in _iter_source_files(repo_path, (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        specs = spec_re.findall(text)
        # Normalise a specifier to its package name: '@scope/pkg/sub' -> '@scope/pkg',
        # 'pkg/sub' -> 'pkg'. Ignore relative imports.
        seen = set()
        for s in specs:
            if s.startswith("."):
                continue
            if s.startswith("@"):
                parts = s.split("/")
                name = "/".join(parts[:2])
            else:
                name = s.split("/")[0]
            seen.add(name)
        for pkg in pkgs:
            if pkg in seen:
                counts[pkg] += 1
    return counts


def annotate(deps: dict, repo_path) -> dict:
    """Annotate deps['vulnerabilities'] with reachability and re-prioritise.

    reachable: True = imported, False = declared-but-not-imported,
               None = ecosystem not statically analysed (Unknown).
    Adds deps['reachable_count'] (vulns confirmed imported). Best-effort.
    """
    if not deps or not isinstance(deps, dict):
        return deps
    vulns = deps.get("vulnerabilities") or []
    if not vulns:
        deps.setdefault("reachable_count", 0)
        return deps
    try:
        rp = Path(repo_path)
        py_pkgs = {v.get("package_name", "") for v in vulns
                   if v.get("ecosystem") == "PyPI" and v.get("package_name")}
        npm_pkgs = {v.get("package_name", "") for v in vulns
                    if v.get("ecosystem") == "npm" and v.get("package_name")}
        py_counts = _scan_python(rp, py_pkgs) if py_pkgs else {}
        npm_counts = _scan_js(rp, npm_pkgs) if npm_pkgs else {}

        reachable_count = 0
        for v in vulns:
            eco = v.get("ecosystem")
            name = v.get("package_name", "")
            if eco not in _ANALYSABLE:
                v["reachable"] = None            # Unknown
                v["reachable_files"] = 0
                continue
            counts = py_counts if eco == "PyPI" else npm_counts
            n = counts.get(name, 0)
            v["reachable"] = n > 0
            v["reachable_files"] = n
            if n > 0:
                reachable_count += 1

        # Re-prioritise: KEV > reachable(True>Unknown>False) > EPSS > severity > CVSS.
        _reach_rank = {True: 2, None: 1, False: 0}
        _sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        vulns.sort(key=lambda v: (
            1 if v.get("kev") else 0,
            _reach_rank.get(v.get("reachable"), 1),
            v.get("epss", 0.0),
            _sev_rank.get(str(v.get("severity", "")).upper(), 0),
            v.get("cvss_score", 0.0),
        ), reverse=True)

        deps["reachable_count"] = reachable_count
    except Exception:
        deps.setdefault("reachable_count", 0)
    return deps
