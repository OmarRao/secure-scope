"""
Generate a clean, professionally laid-out PDF sample report.
Renders a print-optimised A4 HTML with Playwright and saves to docs/sample_report.pdf.
"""

import asyncio, json, sys, textwrap
from collections import Counter
from datetime import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from playwright.async_api import async_playwright
from ransomware import detect as ransomware_detect

# ── Load data ─────────────────────────────────────────────────────────────────
REPORTS = Path(__file__).parent / "reports"
DOCS    = Path(__file__).parent / "docs"
DOCS.mkdir(exist_ok=True)
OUT_PDF = DOCS / "sample_report.pdf"

# Pick best JSON: prefer the analyzer one with known findings
candidates = sorted(REPORTS.glob("analyzer_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
if not candidates:
    candidates = sorted(REPORTS.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
if not candidates:
    raise SystemExit("No report JSON found in reports/. Run gen_sample.py first.")

data     = json.loads(candidates[0].read_text(encoding="utf-8"))
findings = data.get("findings", [])
summ     = data.get("summary", {})
dep_vulns= data.get("dependency_vulns", [])

REPO_URL  = data.get("repo", "https://github.com/OmarRao/analyzer")
REPO_SLUG = REPO_URL.rstrip("/").split("/")[-1]
OWNER     = REPO_URL.rstrip("/").split("/")[-2] if "/" in REPO_URL else "OmarRao"
GEN_AT    = datetime.now().strftime("%B %d, %Y at %H:%M UTC")

errors   = [f for f in findings if f.get("severity") == "ERROR"]
warnings = [f for f in findings if f.get("severity") == "WARNING"]
total    = len(findings)

raw_score = len(errors)*10 + len(warnings)*3 + len(dep_vulns)*8
score = min(raw_score, 100)
if score >= 70:   grade, grade_color = "CRITICAL", "#dc2626"
elif score >= 45: grade, grade_color = "HIGH",     "#d97706"
elif score >= 20: grade, grade_color = "MEDIUM",   "#2563eb"
else:             grade, grade_color = "LOW",      "#16a34a"

cwe_counts   = Counter(f.get("cwe","Unknown") for f in findings if f.get("cwe"))
attack_techs = Counter(f.get("attack_technique") for f in findings if f.get("attack_technique"))
attack_tactics = Counter(f.get("attack_tactic") for f in findings if f.get("attack_tactic"))

# ── Ransomware Intelligence ───────────────────────────────────────────────────
rw = ransomware_detect(findings)

ATTACK_SURFACE = [
    ("SQL Injection",           "CWE-89",  "T1190", sum(1 for f in findings if f.get("cwe")=="CWE-89")),
    ("Command Injection",       "CWE-78",  "T1059", sum(1 for f in findings if f.get("cwe")=="CWE-78")),
    ("Cross-Site Scripting",    "CWE-79",  "T1059.007", sum(1 for f in findings if f.get("cwe")=="CWE-79")),
    ("SSRF",                    "CWE-918", "T1090", sum(1 for f in findings if f.get("cwe")=="CWE-918")),
    ("Path Traversal",          "CWE-22",  "T1083", sum(1 for f in findings if f.get("cwe")=="CWE-22")),
    ("Hardcoded Credentials",   "CWE-798", "T1552.001", sum(1 for f in findings if f.get("cwe")=="CWE-798")),
    ("Weak Cryptography",       "CWE-327", "T1600", sum(1 for f in findings if f.get("cwe")=="CWE-327")),
    ("Insecure Deserialization","CWE-502", "T1059", sum(1 for f in findings if f.get("cwe")=="CWE-502")),
]


# ── HTML helpers ──────────────────────────────────────────────────────────────

def sev_chip(sev: str) -> str:
    if sev == "ERROR":
        return '<span class="chip chip-r">CRITICAL</span>'
    elif sev == "WARNING":
        return '<span class="chip chip-w">WARNING</span>'
    return f'<span class="chip chip-i">{sev}</span>'

def cwe_chip(cwe: str) -> str:
    if not cwe:
        return ""
    return f'<span class="tag">{cwe}</span>'

def atk_chip(tech: str) -> str:
    if not tech:
        return ""
    return f'<span class="tag tag-p">{tech}</span>'

def esc(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def short_rule(rule_id: str) -> str:
    parts = (rule_id or "").split(".")
    return esc(parts[-1].replace("-", " ").title() if parts else rule_id)

def short_file(path: str) -> str:
    p = (path or "")
    parts = p.replace("\\", "/").split("/")
    return esc("/".join(parts[-2:]) if len(parts) > 2 else p)

def bar_svg(pct: int, color: str = "#2563eb") -> str:
    w = max(0, min(100, pct))
    return (
        f'<div style="background:#e2e8f0;border-radius:3px;height:8px;width:100%;overflow:hidden;">'
        f'<div style="background:{color};width:{w}%;height:100%;border-radius:3px;"></div></div>'
    )

def score_bar(score: int) -> str:
    bands = [
        (20, "#16a34a", "LOW"),
        (25, "#2563eb", "MEDIUM"),
        (25, "#d97706", "HIGH"),
        (30, "#dc2626", "CRITICAL"),
    ]
    segs = ""
    offset = 0
    for width, color, label in bands:
        segs += (
            f'<div style="position:absolute;left:{offset}%;width:{width}%;height:100%;'
            f'background:{color};opacity:.18;"></div>'
        )
        offset += width
    marker_left = min(score, 99)
    return f"""
    <div style="position:relative;height:20px;background:#e2e8f0;border-radius:6px;overflow:visible;margin:6px 0 2px;">
      {segs}
      <div style="position:absolute;left:{marker_left}%;top:-4px;transform:translateX(-50%);
                  width:4px;height:28px;background:{grade_color};border-radius:2px;"></div>
    </div>
    <div style="display:flex;justify-content:space-between;font-size:9px;color:#6b7280;font-family:'Geist Mono',monospace;margin-top:2px;">
      <span>0 — LOW</span><span>20 — MEDIUM</span><span>45 — HIGH</span><span>70 — CRITICAL</span><span>100</span>
    </div>"""


# ── Build findings rows ───────────────────────────────────────────────────────

def findings_rows(flist, max_rows=None):
    rows = ""
    for i, f in enumerate(flist):
        if max_rows and i >= max_rows:
            break
        sev   = f.get("severity","")
        rule  = short_rule(f.get("rule_id",""))
        fpath = short_file(f.get("file",""))
        line  = f.get("line_start","")
        cwe   = f.get("cwe","")
        tech  = f.get("attack_technique","")
        tact  = f.get("attack_tactic","")
        msg   = esc((f.get("message","") or "")[:120])
        bg = "#fff9f9" if sev == "ERROR" else "#fffdf5" if sev == "WARNING" else "#ffffff"
        rows += f"""
        <tr style="background:{bg};page-break-inside:avoid;">
          <td style="width:90px;">{sev_chip(sev)}</td>
          <td style="font-weight:600;font-size:12px;color:#111827;">{rule}</td>
          <td style="font-family:'Geist Mono',monospace;font-size:11px;color:#374151;">{fpath}:{line}</td>
          <td>{cwe_chip(cwe)}</td>
          <td>{atk_chip(tech)}</td>
          <td style="font-size:11px;color:#6b7280;">{msg}</td>
        </tr>"""
    return rows


# ── CWE distribution rows ─────────────────────────────────────────────────────

def cwe_rows():
    rows = ""
    for cwe, count in cwe_counts.most_common(12):
        pct = round(count / total * 100) if total else 0
        color = "#dc2626" if any(f.get("cwe")==cwe and f.get("severity")=="ERROR" for f in findings) else "#d97706"
        rows += f"""
        <tr>
          <td style="font-family:'Geist Mono',monospace;font-weight:600;font-size:12px;">{esc(cwe)}</td>
          <td style="text-align:center;font-family:'Geist Mono',monospace;">{count}</td>
          <td style="text-align:center;color:#6b7280;">{pct}%</td>
          <td style="width:200px;">{bar_svg(pct, color)}</td>
        </tr>"""
    return rows


# ── ATT&CK rows ───────────────────────────────────────────────────────────────

def attack_rows():
    rows = ""
    for (name, cwe, tech, cnt) in ATTACK_SURFACE:
        status_color = "#dc2626" if cnt > 0 else "#16a34a"
        status_text  = f"{cnt} finding{'s' if cnt!=1 else ''}" if cnt > 0 else "Clear"
        rows += f"""
        <tr style="page-break-inside:avoid;">
          <td style="font-weight:600;font-size:12px;color:#111827;">{esc(name)}</td>
          <td><span class="tag">{esc(cwe)}</span></td>
          <td><span class="tag tag-p">{esc(tech)}</span></td>
          <td style="color:{status_color};font-weight:600;font-size:12px;text-align:center;">{status_text}</td>
        </tr>"""
    return rows


# ── Ransomware section builder ────────────────────────────────────────────────

def rw_color(score):
    if score >= 70: return "#dc2626"
    if score >= 40: return "#d97706"
    return "#16a34a"

def ransomware_section() -> str:
    if not rw.behavior_count and not rw.family_matches:
        return ""

    # KPI row
    bc = rw_color(rw.ransomware_score)
    blast_c = rw.blast_color
    apt_label = "APT DETECTED" if rw.is_apt else ("CRIMINAL GROUP" if rw.family_matches else "NONE")
    apt_color = "#7c3aed" if rw.is_apt else ("#d97706" if rw.family_matches else "#16a34a")

    kpi = f"""
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12pt;margin-bottom:16pt;">
      <div style="border:1px solid #e5e7eb;border-radius:8pt;padding:14pt 16pt;background:#fafafa;">
        <div style="font-size:8pt;color:#9ca3af;font-family:'Geist Mono',monospace;letter-spacing:.8px;text-transform:uppercase;margin-bottom:4pt;">Ransomware Risk Score</div>
        <div style="font-size:30pt;font-weight:900;font-family:'Geist Mono',monospace;color:{bc};letter-spacing:-1pt;line-height:1;">{rw.ransomware_score}<span style="font-size:12pt;color:#9ca3af;font-weight:400;">/100</span></div>
        <div style="font-size:11pt;font-weight:800;color:{bc};font-family:'Geist Mono',monospace;margin-top:4pt;">{"HIGH RISK" if rw.ransomware_score >= 70 else "MODERATE" if rw.ransomware_score >= 40 else "LOW RISK"}</div>
      </div>
      <div style="border:1px solid #e5e7eb;border-radius:8pt;padding:14pt 16pt;background:#fafafa;">
        <div style="font-size:8pt;color:#9ca3af;font-family:'Geist Mono',monospace;letter-spacing:.8px;text-transform:uppercase;margin-bottom:4pt;">Blast Radius</div>
        <div style="font-size:30pt;font-weight:900;font-family:'Geist Mono',monospace;color:{blast_c};letter-spacing:-1pt;line-height:1;">{rw.blast_radius_score}<span style="font-size:12pt;color:#9ca3af;font-weight:400;">/100</span></div>
        <div style="font-size:11pt;font-weight:800;color:{blast_c};font-family:'Geist Mono',monospace;margin-top:4pt;">{rw.blast_label}</div>
        <div style="font-size:9pt;color:#6b7280;margin-top:4pt;line-height:1.5;">{rw.blast_description[:90]}...</div>
      </div>
      <div style="border:1px solid #e5e7eb;border-radius:8pt;padding:14pt 16pt;background:#fafafa;">
        <div style="font-size:8pt;color:#9ca3af;font-family:'Geist Mono',monospace;letter-spacing:.8px;text-transform:uppercase;margin-bottom:4pt;">APT Attribution</div>
        <div style="font-size:16pt;font-weight:900;font-family:'Geist Mono',monospace;color:{apt_color};line-height:1.2;margin-bottom:4pt;">{apt_label}</div>
        {"<div style='font-size:9pt;color:#6b7280;line-height:1.5;'>Confidence: <strong>" + str(rw.apt_confidence) + "%</strong><br>" + (rw.primary_family.family.get('apt_group','') if rw.primary_family else '') + "<br>" + (rw.primary_family.family.get('origin_flag','') + ' ' + rw.primary_family.family.get('origin','') if rw.primary_family else '') + "</div>" if rw.is_apt or rw.family_matches else "<div style='font-size:9pt;color:#16a34a;'>No nation-state or criminal group TTPs matched in this scan.</div>"}
      </div>
    </div>"""

    # Behaviors
    beh_rows = ""
    for b in rw.detected_behaviors[:9]:
        c = "#dc2626" if b.severity == "CRITICAL" else "#d97706"
        beh_rows += f"""
        <tr style="page-break-inside:avoid;">
          <td style="font-size:14pt;">{b.icon}</td>
          <td style="font-weight:700;font-size:11pt;color:#111827;">{b.label}</td>
          <td><span style="font-family:'Geist Mono',monospace;font-size:9pt;background:#eff6ff;color:#2563eb;padding:2pt 6pt;border-radius:3pt;">{b.mitre}</span></td>
          <td style="font-size:10pt;color:#6b7280;">{b.description[:70]}</td>
          <td style="text-align:center;font-weight:700;font-size:10pt;color:{c};">{b.severity}</td>
          <td style="text-align:center;font-family:'Geist Mono',monospace;font-size:10pt;">{b.match_count}</td>
        </tr>"""

    behaviors = f"""
    <div style="font-size:8pt;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:#9ca3af;font-family:'Geist Mono',monospace;margin-bottom:8pt;display:flex;align-items:center;gap:8pt;">
      Detected Ransomware Behaviors<span style="flex:1;height:1px;background:#e5e7eb;display:inline-block;margin-left:8pt;"></span>
    </div>
    <table class="data-table" style="margin-bottom:14pt;">
      <thead><tr>
        <th></th><th>Behavior</th><th>MITRE</th><th>Description</th><th style="text-align:center;">Severity</th><th style="text-align:center;">Hits</th>
      </tr></thead>
      <tbody>{beh_rows}</tbody>
    </table>"""

    # Families
    fam_html = ""
    for i, match in enumerate(rw.family_matches[:3]):
        fam = match.family
        border = "#dc2626" if i == 0 else "#e5e7eb"
        victims = " · ".join(fam.get("known_victims", [])[:2])
        sectors = ", ".join(fam.get("sectors_targeted", [])[:4])
        matched_b = ", ".join(b.replace("_", " ") for b in match.matched_behaviors[:5])
        cves_str  = ", ".join(match.matched_cves[:3]) if match.matched_cves else "N/A"
        conf_c = "#dc2626" if match.confidence >= 70 else "#d97706" if match.confidence >= 40 else "#6b7280"
        status_c = "#dc2626" if fam.get("status") == "ACTIVE" else "#d97706"
        fam_html += f"""
        <div style="border:1.5px solid {border};border-radius:8pt;padding:14pt 16pt;margin-bottom:10pt;page-break-inside:avoid;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8pt;">
            <div>
              <div style="font-size:13pt;font-weight:900;color:#111827;letter-spacing:-.2pt;">{esc(fam['name'])} <span style="font-size:9pt;color:#9ca3af;font-weight:400;">({esc(' · '.join(fam.get('alias',[][:2])))})</span></div>
              <div style="margin-top:4pt;display:flex;gap:6pt;flex-wrap:wrap;">
                <span style="font-size:9pt;font-family:'Geist Mono',monospace;padding:2pt 7pt;border-radius:3pt;background:#eff6ff;color:#2563eb;">{esc(fam.get('origin_flag',''))} {esc(fam.get('origin',''))}</span>
                <span style="font-size:9pt;font-family:'Geist Mono',monospace;padding:2pt 7pt;border-radius:3pt;background:#fef2f2;color:{status_c};">{esc(fam.get('status',''))}</span>
                <span style="font-size:9pt;font-family:'Geist Mono',monospace;padding:2pt 7pt;border-radius:3pt;background:#f5f3ff;color:#7c3aed;">{esc(fam.get('type',''))}</span>
              </div>
            </div>
            <div style="text-align:center;background:#f9fafb;border:1px solid #e5e7eb;border-radius:6pt;padding:8pt 14pt;flex-shrink:0;">
              <div style="font-size:22pt;font-weight:900;font-family:'Geist Mono',monospace;color:{conf_c};line-height:1;">{match.confidence}%</div>
              <div style="font-size:8pt;color:#9ca3af;font-family:'Geist Mono',monospace;">match confidence</div>
            </div>
          </div>
          <div style="font-size:10pt;color:#374151;line-height:1.6;margin-bottom:8pt;">{esc(fam.get('description',''))}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10pt;font-size:9.5pt;">
            <div><strong style="color:#6b7280;font-size:8pt;text-transform:uppercase;letter-spacing:.5px;">Sectors</strong><br><span style="color:#374151;">{esc(sectors)}</span></div>
            <div><strong style="color:#6b7280;font-size:8pt;text-transform:uppercase;letter-spacing:.5px;">Known Victims</strong><br><span style="color:#374151;font-family:'Geist Mono',monospace;">{esc(victims)}</span></div>
            <div><strong style="color:#6b7280;font-size:8pt;text-transform:uppercase;letter-spacing:.5px;">Matched CVEs</strong><br><span style="color:#dc2626;font-family:'Geist Mono',monospace;">{esc(cves_str)}</span></div>
          </div>
          {"<div style='margin-top:8pt;font-size:8.5pt;'><strong style='color:#6b7280;'>Matched Behaviors:</strong> <span style='color:#dc2626;font-family:Geist Mono,monospace;'>" + esc(matched_b) + "</span></div>" if matched_b else ""}
        </div>"""

    # CVE table
    cve_rows_html = ""
    for cve in rw.active_cves[:8]:
        cvss_c = "#dc2626" if cve.get("cvss",0) >= 9 else "#d97706" if cve.get("cvss",0) >= 7 else "#16a34a"
        cve_rows_html += f"""
        <tr style="page-break-inside:avoid;">
          <td><span style="font-family:'Geist Mono',monospace;font-size:9pt;font-weight:700;background:#fee2e2;color:#dc2626;padding:2pt 6pt;border-radius:3pt;">{esc(cve['id'])}</span></td>
          <td style="font-weight:700;font-size:10pt;">{esc(cve.get('name',''))}</td>
          <td style="font-size:10pt;color:#6b7280;">{esc((cve.get('desc',''))[:70])}</td>
          <td style="text-align:center;font-weight:800;font-family:'Geist Mono',monospace;color:{cvss_c};">{cve.get('cvss','')}</td>
          <td style="font-size:9.5pt;color:#6b7280;font-family:'Geist Mono',monospace;">{esc(cve.get('family_name',''))}</td>
        </tr>"""

    cve_section = f"""
    <div style="font-size:8pt;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:#9ca3af;font-family:'Geist Mono',monospace;margin:14pt 0 8pt;display:flex;align-items:center;gap:8pt;">
      Active CVE Variants Exploited<span style="flex:1;height:1px;background:#e5e7eb;display:inline-block;margin-left:8pt;"></span>
    </div>
    <table class="data-table" style="margin-bottom:14pt;">
      <thead><tr><th>CVE ID</th><th>Vulnerability</th><th>Description</th><th style="text-align:center;">CVSS</th><th>Family</th></tr></thead>
      <tbody>{cve_rows_html}</tbody>
    </table>""" if cve_rows_html else ""

    # Affected sections
    aff_rows = ""
    for sec in rw.affected_sections[:10]:
        behs = ", ".join(sec["behaviors"][:3])
        aff_rows += f"""
        <tr>
          <td style="font-family:'Geist Mono',monospace;font-size:10pt;">{esc(sec['file'])}</td>
          <td style="font-size:9.5pt;color:#d97706;">{esc(behs)}</td>
          <td style="text-align:center;font-weight:700;font-family:'Geist Mono',monospace;">{sec['behavior_count']}</td>
        </tr>"""

    aff_section = f"""
    <div style="font-size:8pt;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:#9ca3af;font-family:'Geist Mono',monospace;margin:14pt 0 8pt;display:flex;align-items:center;gap:8pt;">
      Affected Code Sections<span style="flex:1;height:1px;background:#e5e7eb;display:inline-block;margin-left:8pt;"></span>
    </div>
    <table class="data-table" style="margin-bottom:14pt;">
      <thead><tr><th>File</th><th>Matched Behaviors</th><th style="text-align:center;">Count</th></tr></thead>
      <tbody>{aff_rows}</tbody>
    </table>""" if aff_rows else ""

    return f"""
<!-- ══════════════════════════════════════════════════════════════════ -->
<!-- RANSOMWARE INTELLIGENCE                                             -->
<!-- ══════════════════════════════════════════════════════════════════ -->
<div class="pb-before">
  <div class="section-eye">Ransomware Intelligence</div>
  <div class="section-title">Ransomware &amp; APT Threat Assessment</div>
  <p style="font-size:10.5pt;color:#6b7280;margin-bottom:14pt;line-height:1.6;">
    Static analysis findings analysed against {len(rw.detected_behaviors)} known ransomware behavioral patterns,
    {len(rw.family_matches)} threat actor families, and {len(rw.active_cves)} active CVEs exploited in ransomware campaigns.
    Blast radius estimates the maximum damage potential if an attacker exploited all detected vulnerabilities.
  </p>

  {kpi}
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:16pt 0;">
  {behaviors}
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:16pt 0;">
  <div style="font-size:8pt;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:#9ca3af;font-family:'Geist Mono',monospace;margin-bottom:8pt;display:flex;align-items:center;gap:8pt;">
    Matched Threat Actor Families<span style="flex:1;height:1px;background:#e5e7eb;display:inline-block;margin-left:8pt;"></span>
  </div>
  {fam_html}
  {cve_section}
  {aff_section}
</div>"""


# ── Full HTML ─────────────────────────────────────────────────────────────────

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SecureScope Security Report — {esc(REPO_SLUG)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700;900&family=Geist+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    /* ── Page setup ───────────────────────────────────────────────── */
    @page {{
      size: A4;
      margin: 18mm 16mm 20mm 16mm;
    }}

    /* ── Base ─────────────────────────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html, body {{
      font-family: 'Geist', sans-serif;
      font-size: 11pt;
      color: #1f2937;
      background: #ffffff;
      line-height: 1.55;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }}
    a {{ color: #2563eb; text-decoration: none; }}
    code, pre, .mono {{ font-family: 'Geist Mono', monospace; }}

    /* ── Page-break helpers ────────────────────────────────────────── */
    .pb-before {{ page-break-before: always; }}
    .no-break  {{ page-break-inside: avoid; }}

    /* ── Utility ──────────────────────────────────────────────────── */
    .divider {{ border: none; border-top: 1px solid #e5e7eb; margin: 18pt 0; }}
    .section-eye {{
      font-size: 8pt; font-weight: 700; letter-spacing: 1.6px;
      text-transform: uppercase; color: #9ca3af;
      font-family: 'Geist Mono', monospace;
      display: flex; align-items: center; gap: 8pt; margin-bottom: 10pt;
    }}
    .section-eye::after {{ content: ''; flex: 1; height: 1px; background: #e5e7eb; }}
    .section-title {{
      font-size: 16pt; font-weight: 800; color: #111827;
      letter-spacing: -0.4pt; margin-bottom: 14pt; line-height: 1.1;
    }}

    /* ── Chips & tags ─────────────────────────────────────────────── */
    .chip {{
      display: inline-block; font-family: 'Geist Mono', monospace;
      font-size: 8.5pt; font-weight: 700; padding: 2pt 7pt;
      border-radius: 4pt; letter-spacing: .4px;
    }}
    .chip-r  {{ background: #fee2e2; color: #dc2626; }}
    .chip-w  {{ background: #fef3c7; color: #d97706; }}
    .chip-i  {{ background: #e0f2fe; color: #0284c7; }}
    .chip-ok {{ background: #dcfce7; color: #16a34a; }}
    .tag {{
      display: inline-block; font-family: 'Geist Mono', monospace;
      font-size: 8pt; font-weight: 600; padding: 1.5pt 6pt;
      border-radius: 3pt; background: #f1f5f9; color: #475569;
      border: 1px solid #e2e8f0;
    }}
    .tag-p {{ background: #f5f3ff; color: #7c3aed; border-color: #e9d5ff; }}

    /* ── Cover page ───────────────────────────────────────────────── */
    .cover {{
      min-height: 240mm;
      display: flex; flex-direction: column; justify-content: space-between;
      padding-bottom: 12pt;
    }}
    .cover-header {{
      display: flex; justify-content: space-between; align-items: flex-start;
      padding-bottom: 18pt; border-bottom: 2px solid #111827; margin-bottom: 36pt;
    }}
    .brand-mark {{
      font-size: 15pt; font-weight: 900; letter-spacing: -0.5pt; color: #111827;
    }}
    .brand-mark sup {{
      font-size: 7pt; font-weight: 600; color: #2563eb;
      letter-spacing: .8px; text-transform: uppercase;
      vertical-align: super; margin-left: 3pt;
      font-family: 'Geist Mono', monospace;
    }}
    .cover-meta-line {{
      font-size: 9pt; color: #6b7280;
      font-family: 'Geist Mono', monospace;
    }}
    .cover-hero {{ margin-bottom: 36pt; }}
    .cover-eyebrow {{
      font-size: 9pt; font-weight: 600; letter-spacing: 1.6px;
      text-transform: uppercase; color: #2563eb;
      font-family: 'Geist Mono', monospace; margin-bottom: 10pt;
    }}
    .cover-title {{
      font-size: 34pt; font-weight: 900; color: #111827;
      letter-spacing: -1pt; line-height: 1.05; margin-bottom: 8pt;
    }}
    .cover-repo {{
      font-size: 13pt; font-weight: 500; color: #374151; margin-bottom: 4pt;
    }}
    .cover-repo a {{ color: #2563eb; }}
    .cover-date {{ font-size: 9.5pt; color: #9ca3af; }}

    /* Risk score box on cover */
    .cover-score-box {{
      display: flex; gap: 18pt; margin-top: 30pt; margin-bottom: 36pt;
    }}
    .score-card {{
      flex: 1; border: 1px solid #e5e7eb; border-radius: 8pt;
      padding: 16pt 18pt; background: #f9fafb;
    }}
    .score-card.accent {{ background: #eff6ff; border-color: #bfdbfe; }}
    .score-num {{
      font-size: 30pt; font-weight: 900; font-family: 'Geist Mono', monospace;
      color: {grade_color}; letter-spacing: -1pt; line-height: 1;
    }}
    .score-label {{ font-size: 9pt; color: #6b7280; margin-top: 4pt; font-weight: 500; }}
    .grade-badge {{
      font-size: 11pt; font-weight: 800; letter-spacing: 1px;
      text-transform: uppercase; color: {grade_color};
      font-family: 'Geist Mono', monospace;
    }}

    /* KPI row on cover */
    .kpi-row {{
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 10pt;
      margin-top: 18pt;
    }}
    .kpi {{
      border: 1px solid #e5e7eb; border-radius: 8pt;
      padding: 13pt 15pt; background: #f9fafb;
    }}
    .kpi-num {{
      font-size: 22pt; font-weight: 900;
      font-family: 'Geist Mono', monospace;
      letter-spacing: -0.5pt; line-height: 1;
    }}
    .kpi-lbl {{ font-size: 8.5pt; color: #6b7280; margin-top: 3pt; }}
    .kpi-num.r {{ color: #dc2626; }}
    .kpi-num.w {{ color: #d97706; }}
    .kpi-num.b {{ color: #2563eb; }}
    .kpi-num.g {{ color: #16a34a; }}

    /* Cover footer strip */
    .cover-footer-strip {{
      border-top: 1px solid #e5e7eb; padding-top: 12pt;
      display: flex; justify-content: space-between; align-items: center;
      font-size: 8.5pt; color: #9ca3af;
      font-family: 'Geist Mono', monospace;
    }}
    .founder-line {{ font-size: 8.5pt; color: #6b7280; text-align: right; }}

    /* ── Exec summary tables ───────────────────────────────────────── */
    .summary-grid {{
      display: grid; grid-template-columns: 1fr 1fr; gap: 14pt;
      margin-bottom: 18pt;
    }}
    .info-box {{
      border: 1px solid #e5e7eb; border-radius: 8pt;
      padding: 14pt 16pt; background: #f9fafb;
    }}
    .info-box h3 {{
      font-size: 9pt; font-weight: 700; text-transform: uppercase;
      letter-spacing: 1px; color: #9ca3af;
      font-family: 'Geist Mono', monospace;
      margin-bottom: 10pt;
    }}
    .info-row {{
      display: flex; justify-content: space-between; align-items: center;
      padding: 5pt 0; border-bottom: 1px solid #f3f4f6; font-size: 10.5pt;
    }}
    .info-row:last-child {{ border-bottom: none; }}
    .info-key {{ color: #6b7280; font-weight: 500; }}
    .info-val {{ font-weight: 600; color: #111827; font-family: 'Geist Mono', monospace; font-size: 10pt; }}

    /* ── Data tables ──────────────────────────────────────────────── */
    .data-table {{
      width: 100%; border-collapse: collapse;
      font-size: 10pt; margin-bottom: 14pt;
    }}
    .data-table th {{
      text-align: left; padding: 7pt 10pt;
      font-size: 8pt; font-weight: 700; letter-spacing: .8px;
      text-transform: uppercase; color: #9ca3af;
      font-family: 'Geist Mono', monospace;
      background: #f8fafc;
      border-bottom: 1.5px solid #e5e7eb;
      border-top: 1.5px solid #e5e7eb;
    }}
    .data-table td {{
      padding: 7pt 10pt; border-bottom: 1px solid #f3f4f6;
      vertical-align: top;
    }}
    .data-table tr:last-child td {{ border-bottom: none; }}
    .data-table tr:nth-child(even) {{ background: #fafafa; }}

    /* ── Score bar ────────────────────────────────────────────────── */
    .score-bar-wrap {{ margin: 10pt 0 4pt; }}

    /* ── Priority box ─────────────────────────────────────────────── */
    .priority-box {{
      border-left: 4px solid #dc2626;
      background: #fff9f9;
      border-radius: 0 8pt 8pt 0;
      padding: 12pt 16pt; margin-bottom: 10pt;
      page-break-inside: avoid;
    }}
    .priority-box.w {{
      border-left-color: #d97706;
      background: #fffdf5;
    }}
    .priority-rule {{
      font-size: 11pt; font-weight: 700; color: #111827; margin-bottom: 3pt;
    }}
    .priority-file {{
      font-family: 'Geist Mono', monospace;
      font-size: 9.5pt; color: #6b7280; margin-bottom: 6pt;
    }}
    .priority-msg {{ font-size: 10pt; color: #374151; line-height: 1.5; }}
    .priority-tags {{ margin-top: 7pt; display: flex; gap: 6pt; flex-wrap: wrap; }}
  </style>
</head>
<body>

<!-- ══════════════════════════════════════════════════════════════════ -->
<!-- COVER PAGE                                                         -->
<!-- ══════════════════════════════════════════════════════════════════ -->
<div class="cover no-break">

  <div class="cover-header">
    <div>
      <div class="brand-mark">SecureScope<sup>BETA</sup></div>
      <div class="cover-meta-line" style="margin-top:4pt;">GitHub Security Analysis Platform</div>
    </div>
    <div style="text-align:right;">
      <div class="cover-meta-line">Generated: {GEN_AT}</div>
      <div class="cover-meta-line" style="margin-top:3pt;">MITRE ATT&amp;CK v14 · CWE Top 25</div>
    </div>
  </div>

  <div class="cover-hero">
    <div class="cover-eyebrow">Security Vulnerability Report</div>
    <div class="cover-title">Static Analysis<br>&amp; Threat Assessment</div>
    <div class="cover-repo">
      Repository: <a href="{esc(REPO_URL)}">{esc(OWNER)}/{esc(REPO_SLUG)}</a>
    </div>
    <div class="cover-date">Branch: main &nbsp;·&nbsp; Analysis Engine: Semgrep + MITRE ATT&amp;CK Mapping</div>
  </div>

  <div class="cover-score-box">
    <div class="score-card accent no-break">
      <div class="score-num">{score}</div>
      <div style="font-size:8.5pt;color:#9ca3af;margin:3pt 0 6pt;font-family:'Geist Mono',monospace;">/ 100</div>
      <div class="grade-badge">{grade}</div>
      <div class="score-label">Composite Risk Score</div>
      <div class="score-bar-wrap">{score_bar(score)}</div>
    </div>
    <div style="flex:2;display:flex;flex-direction:column;gap:10pt;">
      <div class="info-box no-break">
        <h3>Scoring Breakdown</h3>
        <div class="info-row">
          <span class="info-key">Critical findings &times; 10</span>
          <span class="info-val" style="color:#dc2626;">+{len(errors)*10}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Warning findings &times; 3</span>
          <span class="info-val" style="color:#d97706;">+{len(warnings)*3}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Dependency CVEs &times; 8</span>
          <span class="info-val" style="color:#2563eb;">+{len(dep_vulns)*8}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Capped at</span>
          <span class="info-val">100</span>
        </div>
      </div>
    </div>
  </div>

  <div class="kpi-row no-break">
    <div class="kpi">
      <div class="kpi-num r">{len(errors)}</div>
      <div class="kpi-lbl">Critical Findings</div>
    </div>
    <div class="kpi">
      <div class="kpi-num w">{len(warnings)}</div>
      <div class="kpi-lbl">Warnings</div>
    </div>
    <div class="kpi">
      <div class="kpi-num b">{len(dep_vulns)}</div>
      <div class="kpi-lbl">Dependency CVEs</div>
    </div>
    <div class="kpi">
      <div class="kpi-num g">{len(cwe_counts)}</div>
      <div class="kpi-lbl">CWE Categories</div>
    </div>
  </div>

  <div class="cover-footer-strip">
    <div>
      <strong>SecureScope</strong> · Open Source Security Analysis Platform<br>
      Findings mapped to MITRE ATT&amp;CK v14 · CWE Top 25 · OWASP Top 10
    </div>
    <div class="founder-line">
      <strong>Omar Rao</strong><br>
      Engineer by trait · Data Resilience, Privacy &amp; Cybersecurity Expert<br>
      Founder, SecureScope
    </div>
  </div>

</div>


<!-- ══════════════════════════════════════════════════════════════════ -->
<!-- PAGE 2 — EXECUTIVE SUMMARY                                         -->
<!-- ══════════════════════════════════════════════════════════════════ -->
<div class="pb-before">
  <div class="section-eye">Executive Summary</div>
  <div class="section-title">Scan Overview</div>

  <div class="summary-grid no-break">
    <div class="info-box">
      <h3>Repository</h3>
      <div class="info-row">
        <span class="info-key">Owner</span>
        <span class="info-val">{esc(OWNER)}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Repository</span>
        <span class="info-val">{esc(REPO_SLUG)}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Branch</span>
        <span class="info-val">main</span>
      </div>
      <div class="info-row">
        <span class="info-key">Analysis Engine</span>
        <span class="info-val">Semgrep</span>
      </div>
      <div class="info-row">
        <span class="info-key">Generated</span>
        <span class="info-val">{GEN_AT}</span>
      </div>
    </div>

    <div class="info-box">
      <h3>Finding Breakdown</h3>
      <div class="info-row">
        <span class="info-key">Total Findings</span>
        <span class="info-val">{total}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Critical (ERROR)</span>
        <span class="info-val" style="color:#dc2626;">{len(errors)}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Warning</span>
        <span class="info-val" style="color:#d97706;">{len(warnings)}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Dependency CVEs</span>
        <span class="info-val">{len(dep_vulns)}</span>
      </div>
      <div class="info-row">
        <span class="info-key">CWE Categories Hit</span>
        <span class="info-val">{len(cwe_counts)}</span>
      </div>
    </div>
  </div>

  <hr class="divider">
  <div class="section-eye">Risk Score Detail</div>
  <div class="section-title">Composite Risk Assessment</div>

  <div style="border:1px solid #e5e7eb;border-radius:8pt;padding:18pt 20pt;background:#f9fafb;" class="no-break">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12pt;">
      <div>
        <div style="font-size:9pt;color:#9ca3af;font-family:'Geist Mono',monospace;letter-spacing:.8px;text-transform:uppercase;margin-bottom:4pt;">Risk Score</div>
        <div style="font-size:36pt;font-weight:900;font-family:'Geist Mono',monospace;color:{grade_color};letter-spacing:-1pt;line-height:1;">{score}<span style="font-size:14pt;color:#9ca3af;font-weight:400;">/100</span></div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:9pt;color:#9ca3af;font-family:'Geist Mono',monospace;letter-spacing:.8px;text-transform:uppercase;margin-bottom:4pt;">Threat Grade</div>
        <div style="font-size:22pt;font-weight:900;font-family:'Geist Mono',monospace;color:{grade_color};letter-spacing:1px;">{grade}</div>
      </div>
    </div>
    {score_bar(score)}
    <div style="font-size:9pt;color:#6b7280;margin-top:10pt;line-height:1.6;">
      Score calculated as: <span class="mono">(critical &times; 10) + (warnings &times; 3) + (CVEs &times; 8) + (sandbox behaviors &times; 15)</span>, capped at 100.
      A score of 70+ is rated CRITICAL and indicates immediate remediation is required.
    </div>
  </div>

  <hr class="divider">
  <div class="section-eye">CWE Distribution</div>
  <div class="section-title">Vulnerability Category Breakdown</div>

  <table class="data-table no-break">
    <thead>
      <tr>
        <th>CWE Identifier</th>
        <th style="text-align:center;">Count</th>
        <th style="text-align:center;">Share</th>
        <th>Distribution</th>
      </tr>
    </thead>
    <tbody>{cwe_rows()}</tbody>
  </table>
</div>


<!-- ══════════════════════════════════════════════════════════════════ -->
<!-- PAGE 3 — ATTACK SURFACE                                            -->
<!-- ══════════════════════════════════════════════════════════════════ -->
<div class="pb-before">
  <div class="section-eye">MITRE ATT&amp;CK Mapping</div>
  <div class="section-title">Attack Surface Analysis</div>
  <p style="font-size:10.5pt;color:#6b7280;margin-bottom:16pt;line-height:1.6;">
    Each vulnerability class is mapped to the corresponding MITRE ATT&amp;CK technique and tactic.
    Counts reflect findings from the static analysis phase. Exposed vectors require immediate
    remediation per the AI Fix Advisor output.
  </p>

  <table class="data-table">
    <thead>
      <tr>
        <th>Vulnerability Type</th>
        <th>CWE</th>
        <th>ATT&amp;CK Technique</th>
        <th style="text-align:center;">Status</th>
      </tr>
    </thead>
    <tbody>{attack_rows()}</tbody>
  </table>

  <hr class="divider">
  <div class="section-eye">Top Priority Findings</div>
  <div class="section-title">Critical Issues Requiring Immediate Action</div>

  {"".join(f'''
  <div class="priority-box {'w' if f.get('severity')=='WARNING' else ''} no-break">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:4pt;">
      <div class="priority-rule">{short_rule(f.get("rule_id",""))}</div>
      {sev_chip(f.get("severity",""))}
    </div>
    <div class="priority-file">{short_file(f.get("file",""))} · line {f.get("line_start","")}</div>
    <div class="priority-msg">{esc((f.get("message","") or "")[:220])}</div>
    <div class="priority-tags">
      {cwe_chip(f.get("cwe",""))}
      {atk_chip(f.get("attack_technique",""))}
      {('<span class="tag">' + esc(f.get("attack_tactic","")) + '</span>') if f.get("attack_tactic") else ""}
    </div>
  </div>
  ''' for f in errors[:8])}
</div>


<!-- ══════════════════════════════════════════════════════════════════ -->
<!-- PAGE 4+ — FULL FINDINGS TABLE                                      -->
<!-- ══════════════════════════════════════════════════════════════════ -->
<div class="pb-before">
  <div class="section-eye">Vulnerability Findings</div>
  <div class="section-title">Complete Findings Table ({total} findings)</div>

  <table class="data-table" style="font-size:9.5pt;">
    <thead>
      <tr>
        <th style="width:80pt;">Severity</th>
        <th>Rule / Vulnerability</th>
        <th>File &amp; Line</th>
        <th style="width:70pt;">CWE</th>
        <th style="width:70pt;">ATT&amp;CK</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      {findings_rows(errors + warnings)}
    </tbody>
  </table>
</div>


{ransomware_section()}

<!-- ══════════════════════════════════════════════════════════════════ -->
<!-- FINAL PAGE — METHODOLOGY & DISCLOSURE                              -->
<!-- ══════════════════════════════════════════════════════════════════ -->
<div class="pb-before">
  <div class="section-eye">Methodology</div>
  <div class="section-title">How This Report Was Generated</div>

  <div class="summary-grid">
    <div class="info-box no-break">
      <h3>Analysis Engine</h3>
      <div class="info-row"><span class="info-key">Static Analysis</span><span class="info-val">Semgrep OSS</span></div>
      <div class="info-row"><span class="info-key">Rulesets</span><span class="info-val">OWASP, CWE-25, Secrets</span></div>
      <div class="info-row"><span class="info-key">Threat Framework</span><span class="info-val">MITRE ATT&amp;CK v14</span></div>
      <div class="info-row"><span class="info-key">CVE Audit</span><span class="info-val">pip-audit / npm audit</span></div>
    </div>
    <div class="info-box no-break">
      <h3>Scoring Model</h3>
      <div class="info-row"><span class="info-key">Critical weight</span><span class="info-val">&times; 10 per finding</span></div>
      <div class="info-row"><span class="info-key">Warning weight</span><span class="info-val">&times; 3 per finding</span></div>
      <div class="info-row"><span class="info-key">CVE weight</span><span class="info-val">&times; 8 per CVE</span></div>
      <div class="info-row"><span class="info-key">Score cap</span><span class="info-val">100</span></div>
    </div>
  </div>

  <hr class="divider">
  <div class="section-eye">Responsible Disclosure</div>
  <div style="border:1px solid #e5e7eb;border-radius:8pt;padding:16pt 18pt;background:#f9fafb;font-size:10pt;color:#374151;line-height:1.7;">
    <p style="margin-bottom:8pt;">
      This report is generated automatically by SecureScope and is intended for the repository owner
      and their authorised security team. Findings reflect the state of the codebase at the time of
      analysis. They should be validated by a qualified security engineer before remediation work begins.
    </p>
    <p style="margin-bottom:8pt;">
      SecureScope maps findings to MITRE ATT&amp;CK v14 and CWE identifiers. These mappings are
      best-effort and should not be treated as a definitive classification. False positives are
      possible — Semgrep static analysis is pattern-based and does not perform dynamic execution.
    </p>
    <p>
      For questions about this report or the SecureScope platform, refer to the project repository at
      <a href="https://github.com/OmarRao/secure-scope">github.com/OmarRao/secure-scope</a>.
    </p>
  </div>

  <hr class="divider">

  <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-top:24pt;" class="no-break">
    <div>
      <div style="font-size:14pt;font-weight:900;color:#111827;letter-spacing:-.3pt;margin-bottom:4pt;">
        SecureScope<sup style="font-size:7pt;color:#2563eb;font-family:'Geist Mono',monospace;vertical-align:super;margin-left:3pt;">BETA</sup>
      </div>
      <div style="font-size:9pt;color:#9ca3af;font-family:'Geist Mono',monospace;">
        AI-Powered GitHub Security Analysis · MITRE ATT&amp;CK v14 · CWE Top 25
      </div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:11pt;font-weight:700;color:#111827;">Omar Rao</div>
      <div style="font-size:9pt;color:#6b7280;line-height:1.6;">
        Engineer by trait<br>
        Data Resilience, Privacy &amp; Cybersecurity Expert<br>
        Founder, SecureScope
      </div>
    </div>
  </div>
</div>

</body>
</html>"""


# ── Render PDF ────────────────────────────────────────────────────────────────

async def render():
    tmp_html = DOCS / "_tmp_report.html"
    tmp_html.write_text(HTML, encoding="utf-8")
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            page = await browser.new_page()
            await page.goto(tmp_html.as_uri(), wait_until="networkidle")
            await page.wait_for_timeout(2500)   # let Google Fonts load
            await page.pdf(
                path=str(OUT_PDF),
                format="A4",
                print_background=True,
                margin={"top": "18mm", "bottom": "14mm", "left": "16mm", "right": "16mm"},
                display_header_footer=True,
                header_template="<span></span>",
                footer_template="""<div style="width:100%;padding:0 16mm;display:flex;
                    justify-content:space-between;font-family:'Courier New',monospace;
                    font-size:8px;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:5px;">
                  <span>SecureScope Security Report &nbsp;&middot;&nbsp; """
                    + esc(OWNER) + "/" + esc(REPO_SLUG) + """</span>
                  <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
                </div>""",
            )
            await browser.close()
    finally:
        tmp_html.unlink(missing_ok=True)

    sz = OUT_PDF.stat().st_size / 1024
    print(f"PDF saved: {OUT_PDF}  ({sz:.0f} KB)")


if __name__ == "__main__":
    asyncio.run(render())
