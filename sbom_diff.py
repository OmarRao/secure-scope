"""
Compare two CycloneDX 1.4 JSON SBOMs and report differences.
"""

import json
from pathlib import Path
from typing import Optional


def _load_components(sbom_path: str) -> dict[str, dict]:
    """Load SBOM components keyed by name."""
    data = json.loads(Path(sbom_path).read_text())
    components = {}
    for comp in data.get("components", []):
        name = comp.get("name", "")
        if name:
            components[name] = {
                "name": name,
                "version": comp.get("version", ""),
                "purl": comp.get("purl", ""),
                "type": comp.get("type", ""),
            }
    return components


def diff_sboms(old_path: str, new_path: str) -> dict:
    """
    Compare two CycloneDX 1.4 JSON SBOMs.

    Returns dict with keys:
        added: list of new components
        removed: list of removed components
        version_changed: list of {name, old_version, new_version}
        new_vulns: list (placeholder — requires vuln DB lookup)
    """
    try:
        old = _load_components(old_path)
    except Exception:
        old = {}

    try:
        new = _load_components(new_path)
    except Exception:
        new = {}

    old_names = set(old.keys())
    new_names = set(new.keys())

    added = [new[n] for n in new_names - old_names]
    removed = [old[n] for n in old_names - new_names]

    version_changed = []
    for name in old_names & new_names:
        ov = old[name]["version"]
        nv = new[name]["version"]
        if ov != nv:
            version_changed.append({
                "name": name,
                "old_version": ov,
                "new_version": nv,
                "purl": new[name]["purl"],
                "type": new[name]["type"],
            })

    return {
        "added": added,
        "removed": removed,
        "version_changed": version_changed,
        "new_vulns": [],  # requires external vuln DB query
    }


def diff_to_html(diff_result: dict) -> str:
    """Render SBOM diff as colour-coded HTML section."""
    added = diff_result.get("added", [])
    removed = diff_result.get("removed", [])
    changed = diff_result.get("version_changed", [])

    def _comp_row(comp: dict, style: str) -> str:
        return (
            f"<tr style='{style}'>"
            f"<td>{comp.get('name','')}</td>"
            f"<td>{comp.get('version','')}</td>"
            f"<td>{comp.get('type','')}</td>"
            f"<td><code>{comp.get('purl','')}</code></td>"
            f"</tr>"
        )

    rows = ""
    for c in added:
        rows += _comp_row(c, "background:#e8f5e9")
    for c in removed:
        rows += _comp_row(c, "background:#ffebee")
    for c in changed:
        rows += (
            f"<tr style='background:#fff8e1'>"
            f"<td>{c.get('name','')}</td>"
            f"<td>{c.get('old_version','')} → {c.get('new_version','')}</td>"
            f"<td>{c.get('type','')}</td>"
            f"<td><code>{c.get('purl','')}</code></td>"
            f"</tr>"
        )

    if not rows:
        return "<h2>SBOM Diff</h2><p>No changes detected.</p>"

    return f"""
<h2>SBOM Diff</h2>
<p style='font-size:13px'>
  <span style='background:#e8f5e9;padding:2px 6px'>■ Added ({len(added)})</span>
  &nbsp;
  <span style='background:#ffebee;padding:2px 6px'>■ Removed ({len(removed)})</span>
  &nbsp;
  <span style='background:#fff8e1;padding:2px 6px'>■ Version changed ({len(changed)})</span>
</p>
<table>
  <thead><tr><th>Component</th><th>Version</th><th>Type</th><th>PURL</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def diff_to_markdown(diff_result: dict) -> str:
    """Render SBOM diff as compact Markdown table for PR comments."""
    added = diff_result.get("added", [])
    removed = diff_result.get("removed", [])
    changed = diff_result.get("version_changed", [])

    lines = ["## SBOM Diff", ""]

    if added:
        lines += ["### ➕ Added", "| Component | Version | Type |", "|---|---|---|"]
        for c in added:
            lines.append(f"| {c.get('name','')} | {c.get('version','')} | {c.get('type','')} |")
        lines.append("")

    if removed:
        lines += ["### ➖ Removed", "| Component | Version | Type |", "|---|---|---|"]
        for c in removed:
            lines.append(f"| {c.get('name','')} | {c.get('version','')} | {c.get('type','')} |")
        lines.append("")

    if changed:
        lines += ["### 🔄 Version Changed", "| Component | Old | New |", "|---|---|---|"]
        for c in changed:
            lines.append(f"| {c.get('name','')} | {c.get('old_version','')} | {c.get('new_version','')} |")
        lines.append("")

    if not added and not removed and not changed:
        lines.append("_No changes detected._")

    return "\n".join(lines)
