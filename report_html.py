"""
Single source of truth for the SecureScope PDF report HTML.

`build_html(data)` returns the print-optimised A4 HTML used to render BOTH:
  - docs/sample_report.pdf  (via gen_pdf_report.py)
  - the live "Print Report" download  (via pdf_render.py → Playwright)

This guarantees every generated report follows the exact same standard as the
sample report — white background, Geist fonts, identical header/footer,
eyebrows, headings, cards, tables, distribution bars and sections.

`data` is the report JSON produced by report.to_json (keys: repo, summary,
findings, dependency_vulns) and is also compatible with the richer report_data
dict (repo_url/repo_slug/gh_info).
"""

from collections import Counter
from datetime import datetime


def esc(s) -> str:
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_html(data: dict) -> tuple:
    """Return (html, owner, repo_slug) for the given report data dict."""
    findings = data.get("findings", []) or []
    summ = data.get("summary", {}) or {}
    dep_vulns = data.get("dependency_vulns", []) or []

    repo_url = data.get("repo") or data.get("repo_url") or "https://github.com/OmarRao/analyzer"
    repo_slug = repo_url.rstrip("/").split("/")[-1]
    owner = repo_url.rstrip("/").split("/")[-2] if "/" in repo_url.rstrip("/") else "OmarRao"
    gen_at = data.get("generated_at") or datetime.now().strftime("%B %d, %Y at %H:%M UTC")
    branch = (data.get("gh_info") or {}).get("default_branch", "main")

    errors = [f for f in findings if f.get("severity") == "ERROR"]
    warnings = [f for f in findings if f.get("severity") == "WARNING"]
    total = len(findings)

    raw_score = len(errors) * 10 + len(warnings) * 3 + len(dep_vulns) * 8
    score = min(raw_score, 100)
    if score >= 70:
        grade, grade_color = "CRITICAL", "#dc2626"
    elif score >= 45:
        grade, grade_color = "HIGH", "#d97706"
    elif score >= 20:
        grade, grade_color = "MEDIUM", "#2563eb"
    else:
        grade, grade_color = "LOW", "#16a34a"

    cwe_counts = Counter(f.get("cwe", "Unknown") for f in findings if f.get("cwe"))

    # ── Ransomware intelligence (optional / guarded) ─────────────────────────
    rw = None
    try:
        from ransomware import detect as ransomware_detect
        rw = ransomware_detect(findings)
    except Exception:
        rw = None

    attack_surface = [
        ("SQL Injection", "CWE-89", "T1190", sum(1 for f in findings if f.get("cwe") == "CWE-89")),
        ("Command Injection", "CWE-78", "T1059", sum(1 for f in findings if f.get("cwe") == "CWE-78")),
        ("Cross-Site Scripting", "CWE-79", "T1059.007", sum(1 for f in findings if f.get("cwe") == "CWE-79")),
        ("SSRF", "CWE-918", "T1090", sum(1 for f in findings if f.get("cwe") == "CWE-918")),
        ("Path Traversal", "CWE-22", "T1083", sum(1 for f in findings if f.get("cwe") == "CWE-22")),
        ("Hardcoded Credentials", "CWE-798", "T1552.001", sum(1 for f in findings if f.get("cwe") == "CWE-798")),
        ("Weak Cryptography", "CWE-327", "T1600", sum(1 for f in findings if f.get("cwe") == "CWE-327")),
        ("Insecure Deserialization", "CWE-502", "T1059", sum(1 for f in findings if f.get("cwe") == "CWE-502")),
    ]

    # ── HTML helpers ─────────────────────────────────────────────────────────
    def sev_chip(sev):
        if sev == "ERROR":
            return '<span class="chip chip-r">CRITICAL</span>'
        if sev == "WARNING":
            return '<span class="chip chip-w">WARNING</span>'
        return f'<span class="chip chip-i">{esc(sev)}</span>'

    def cwe_chip(cwe):
        return f'<span class="tag">{esc(cwe)}</span>' if cwe else ""

    def atk_chip(tech):
        return f'<span class="tag tag-p">{esc(tech)}</span>' if tech else ""

    def short_rule(rule_id):
        parts = (rule_id or "").split(".")
        return esc(parts[-1].replace("-", " ").title() if parts else rule_id)

    def short_file(path):
        p = (path or "").replace("\\", "/").split("/")
        return esc("/".join(p[-2:]) if len(p) > 2 else (path or ""))

    def bar_svg(pct, color="#2563eb"):
        w = max(0, min(100, pct))
        return (
            f'<div style="background:#e2e8f0;border-radius:3px;height:8px;width:100%;overflow:hidden;">'
            f'<div style="background:{color};width:{w}%;height:100%;border-radius:3px;"></div></div>'
        )

    def score_bar(sc):
        bands = [(20, "#16a34a"), (25, "#2563eb"), (25, "#d97706"), (30, "#dc2626")]
        segs, offset = "", 0
        for width, color in bands:
            segs += (f'<div style="position:absolute;left:{offset}%;width:{width}%;height:100%;'
                     f'background:{color};opacity:.18;"></div>')
            offset += width
        marker_left = min(sc, 99)
        return f"""
        <div style="position:relative;height:20px;background:#e2e8f0;border-radius:6px;overflow:visible;margin:6px 0 2px;">
          {segs}
          <div style="position:absolute;left:{marker_left}%;top:-4px;transform:translateX(-50%);
                      width:4px;height:28px;background:{grade_color};border-radius:2px;"></div>
        </div>
        <div style="display:flex;justify-content:space-between;font-size:9px;color:#6b7280;font-family:'Geist Mono',monospace;margin-top:2px;">
          <span>0 — LOW</span><span>20 — MEDIUM</span><span>45 — HIGH</span><span>70 — CRITICAL</span><span>100</span>
        </div>"""

    def cwe_rows():
        rows = ""
        for cwe, count in cwe_counts.most_common(12):
            pct = round(count / total * 100) if total else 0
            color = "#dc2626" if any(f.get("cwe") == cwe and f.get("severity") == "ERROR" for f in findings) else "#d97706"
            rows += f"""
            <tr>
              <td style="font-family:'Geist Mono',monospace;font-weight:600;font-size:12px;">{esc(cwe)}</td>
              <td style="text-align:center;font-family:'Geist Mono',monospace;">{count}</td>
              <td style="text-align:center;color:#6b7280;">{pct}%</td>
              <td style="width:200px;">{bar_svg(pct, color)}</td>
            </tr>"""
        return rows

    def attack_rows():
        rows = ""
        for (name, cwe, tech, cnt) in attack_surface:
            status_color = "#dc2626" if cnt > 0 else "#16a34a"
            status_text = f"{cnt} finding{'s' if cnt != 1 else ''}" if cnt > 0 else "Clear"
            rows += f"""
            <tr style="page-break-inside:avoid;">
              <td style="font-weight:600;font-size:12px;color:#111827;">{esc(name)}</td>
              <td><span class="tag">{esc(cwe)}</span></td>
              <td><span class="tag tag-p">{esc(tech)}</span></td>
              <td style="color:{status_color};font-weight:600;font-size:12px;text-align:center;">{status_text}</td>
            </tr>"""
        return rows

    def findings_rows(flist):
        rows = ""
        for f in flist:
            sev = f.get("severity", "")
            bg = "#fff9f9" if sev == "ERROR" else "#fffdf5" if sev == "WARNING" else "#ffffff"
            rows += f"""
            <tr style="background:{bg};page-break-inside:avoid;">
              <td style="width:90px;">{sev_chip(sev)}</td>
              <td style="font-weight:600;font-size:12px;color:#111827;">{short_rule(f.get("rule_id", ""))}</td>
              <td style="font-family:'Geist Mono',monospace;font-size:11px;color:#374151;">{short_file(f.get("file", ""))}:{esc(f.get("line_start", ""))}</td>
              <td>{cwe_chip(f.get("cwe", ""))}</td>
              <td>{atk_chip(f.get("attack_technique", ""))}</td>
              <td style="font-size:11px;color:#6b7280;">{esc((f.get("message", "") or "")[:120])}</td>
            </tr>"""
        return rows

    def ransomware_section():
        if not rw or (not getattr(rw, "behavior_count", 0) and not getattr(rw, "family_matches", [])):
            return ""
        bc = "#dc2626" if rw.ransomware_score >= 70 else "#d97706" if rw.ransomware_score >= 40 else "#16a34a"
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
            <div style="font-size:11pt;font-weight:800;color:{blast_c};font-family:'Geist Mono',monospace;margin-top:4pt;">{esc(rw.blast_label)}</div>
          </div>
          <div style="border:1px solid #e5e7eb;border-radius:8pt;padding:14pt 16pt;background:#fafafa;">
            <div style="font-size:8pt;color:#9ca3af;font-family:'Geist Mono',monospace;letter-spacing:.8px;text-transform:uppercase;margin-bottom:4pt;">APT Attribution</div>
            <div style="font-size:16pt;font-weight:900;font-family:'Geist Mono',monospace;color:{apt_color};line-height:1.2;">{apt_label}</div>
          </div>
        </div>"""
        beh_rows = ""
        for b in rw.detected_behaviors[:9]:
            c = "#dc2626" if b.severity == "CRITICAL" else "#d97706"
            beh_rows += f"""
            <tr style="page-break-inside:avoid;">
              <td style="font-size:14pt;">{b.icon}</td>
              <td style="font-weight:700;font-size:11pt;color:#111827;">{esc(b.label)}</td>
              <td><span style="font-family:'Geist Mono',monospace;font-size:9pt;background:#eff6ff;color:#2563eb;padding:2pt 6pt;border-radius:3pt;">{esc(b.mitre)}</span></td>
              <td style="text-align:center;font-weight:700;font-size:10pt;color:{c};">{esc(b.severity)}</td>
              <td style="text-align:center;font-family:'Geist Mono',monospace;font-size:10pt;">{b.match_count}</td>
            </tr>"""
        behaviors = f"""
        <div class="section-eye" style="margin-top:14pt;">Detected Ransomware Behaviors</div>
        <table class="data-table" style="margin-bottom:14pt;">
          <thead><tr><th></th><th>Behavior</th><th>MITRE</th><th style="text-align:center;">Severity</th><th style="text-align:center;">Hits</th></tr></thead>
          <tbody>{beh_rows}</tbody>
        </table>""" if beh_rows else ""
        return f"""
        <div class="pb-before">
          <div class="section-eye">Ransomware Intelligence</div>
          <div class="section-title">Ransomware &amp; APT Threat Assessment</div>
          <p style="font-size:10.5pt;color:#6b7280;margin-bottom:14pt;line-height:1.6;">
            Static analysis findings analysed against known ransomware behavioral patterns, threat actor
            families, and active CVEs exploited in ransomware campaigns. Blast radius estimates the maximum
            damage potential if an attacker exploited all detected vulnerabilities.
          </p>
          {kpi}
          {behaviors}
        </div>"""

    HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SecureScope Security Report — {esc(repo_slug)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700;900&family=Geist+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    @page {{ size: A4; margin: 18mm 16mm 20mm 16mm; }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html, body {{
      font-family: 'Geist', sans-serif; font-size: 11pt; color: #1f2937;
      background: #ffffff; line-height: 1.55;
      -webkit-print-color-adjust: exact; print-color-adjust: exact;
    }}
    a {{ color: #2563eb; text-decoration: none; }}
    code, pre, .mono {{ font-family: 'Geist Mono', monospace; }}
    .pb-before {{ page-break-before: always; }}
    .no-break  {{ page-break-inside: avoid; }}
    .divider {{ border: none; border-top: 1px solid #e5e7eb; margin: 18pt 0; }}
    .section-eye {{
      font-size: 8pt; font-weight: 700; letter-spacing: 1.6px; text-transform: uppercase;
      color: #9ca3af; font-family: 'Geist Mono', monospace;
      display: flex; align-items: center; gap: 8pt; margin-bottom: 10pt;
    }}
    .section-eye::after {{ content: ''; flex: 1; height: 1px; background: #e5e7eb; }}
    .section-title {{ font-size: 16pt; font-weight: 800; color: #111827; letter-spacing: -0.4pt; margin-bottom: 14pt; line-height: 1.1; }}
    .chip {{ display: inline-block; font-family: 'Geist Mono', monospace; font-size: 8.5pt; font-weight: 700; padding: 2pt 7pt; border-radius: 4pt; letter-spacing: .4px; }}
    .chip-r {{ background: #fee2e2; color: #dc2626; }}
    .chip-w {{ background: #fef3c7; color: #d97706; }}
    .chip-i {{ background: #e0f2fe; color: #0284c7; }}
    .tag {{ display: inline-block; font-family: 'Geist Mono', monospace; font-size: 8pt; font-weight: 600; padding: 1.5pt 6pt; border-radius: 3pt; background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }}
    .tag-p {{ background: #f5f3ff; color: #7c3aed; border-color: #e9d5ff; }}
    .cover {{ min-height: 240mm; display: flex; flex-direction: column; justify-content: space-between; padding-bottom: 12pt; }}
    .cover-header {{ display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 18pt; border-bottom: 2px solid #111827; margin-bottom: 36pt; }}
    .brand-mark {{ font-size: 15pt; font-weight: 900; letter-spacing: -0.5pt; color: #111827; }}
    .brand-mark sup {{ font-size: 7pt; font-weight: 600; color: #2563eb; letter-spacing: .8px; text-transform: uppercase; vertical-align: super; margin-left: 3pt; font-family: 'Geist Mono', monospace; }}
    .cover-meta-line {{ font-size: 9pt; color: #6b7280; font-family: 'Geist Mono', monospace; }}
    .cover-hero {{ margin-bottom: 36pt; }}
    .cover-eyebrow {{ font-size: 9pt; font-weight: 600; letter-spacing: 1.6px; text-transform: uppercase; color: #2563eb; font-family: 'Geist Mono', monospace; margin-bottom: 10pt; }}
    .cover-title {{ font-size: 34pt; font-weight: 900; color: #111827; letter-spacing: -1pt; line-height: 1.05; margin-bottom: 8pt; }}
    .cover-repo {{ font-size: 13pt; font-weight: 500; color: #374151; margin-bottom: 4pt; }}
    .cover-repo a {{ color: #2563eb; }}
    .cover-date {{ font-size: 9.5pt; color: #9ca3af; }}
    .cover-score-box {{ display: flex; gap: 18pt; margin-top: 30pt; margin-bottom: 36pt; }}
    .score-card {{ flex: 1; border: 1px solid #e5e7eb; border-radius: 8pt; padding: 16pt 18pt; background: #f9fafb; }}
    .score-card.accent {{ background: #eff6ff; border-color: #bfdbfe; }}
    .score-num {{ font-size: 30pt; font-weight: 900; font-family: 'Geist Mono', monospace; color: {grade_color}; letter-spacing: -1pt; line-height: 1; }}
    .score-label {{ font-size: 9pt; color: #6b7280; margin-top: 4pt; font-weight: 500; }}
    .grade-badge {{ font-size: 11pt; font-weight: 800; letter-spacing: 1px; text-transform: uppercase; color: {grade_color}; font-family: 'Geist Mono', monospace; }}
    .kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10pt; margin-top: 18pt; }}
    .kpi {{ border: 1px solid #e5e7eb; border-radius: 8pt; padding: 13pt 15pt; background: #f9fafb; }}
    .kpi-num {{ font-size: 22pt; font-weight: 900; font-family: 'Geist Mono', monospace; letter-spacing: -0.5pt; line-height: 1; }}
    .kpi-lbl {{ font-size: 8.5pt; color: #6b7280; margin-top: 3pt; }}
    .kpi-num.r {{ color: #dc2626; }} .kpi-num.w {{ color: #d97706; }} .kpi-num.b {{ color: #2563eb; }} .kpi-num.g {{ color: #16a34a; }}
    .cover-footer-strip {{ border-top: 1px solid #e5e7eb; padding-top: 12pt; display: flex; justify-content: space-between; align-items: center; font-size: 8.5pt; color: #9ca3af; font-family: 'Geist Mono', monospace; }}
    .founder-line {{ font-size: 8.5pt; color: #6b7280; text-align: right; }}
    .summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14pt; margin-bottom: 18pt; }}
    .info-box {{ border: 1px solid #e5e7eb; border-radius: 8pt; padding: 14pt 16pt; background: #f9fafb; }}
    .info-box h3 {{ font-size: 9pt; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #9ca3af; font-family: 'Geist Mono', monospace; margin-bottom: 10pt; }}
    .info-row {{ display: flex; justify-content: space-between; align-items: center; padding: 5pt 0; border-bottom: 1px solid #f3f4f6; font-size: 10.5pt; }}
    .info-row:last-child {{ border-bottom: none; }}
    .info-key {{ color: #6b7280; font-weight: 500; }}
    .info-val {{ font-weight: 600; color: #111827; font-family: 'Geist Mono', monospace; font-size: 10pt; }}
    .data-table {{ width: 100%; border-collapse: collapse; font-size: 10pt; margin-bottom: 14pt; }}
    .data-table th {{ text-align: left; padding: 7pt 10pt; font-size: 8pt; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; color: #9ca3af; font-family: 'Geist Mono', monospace; background: #f8fafc; border-bottom: 1.5px solid #e5e7eb; border-top: 1.5px solid #e5e7eb; }}
    .data-table td {{ padding: 7pt 10pt; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
    .data-table tr:last-child td {{ border-bottom: none; }}
    .data-table tr:nth-child(even) {{ background: #fafafa; }}
    .priority-box {{ border-left: 4px solid #dc2626; background: #fff9f9; border-radius: 0 8pt 8pt 0; padding: 12pt 16pt; margin-bottom: 10pt; page-break-inside: avoid; }}
    .priority-box.w {{ border-left-color: #d97706; background: #fffdf5; }}
    .priority-rule {{ font-size: 11pt; font-weight: 700; color: #111827; margin-bottom: 3pt; }}
    .priority-file {{ font-family: 'Geist Mono', monospace; font-size: 9.5pt; color: #6b7280; margin-bottom: 6pt; }}
    .priority-msg {{ font-size: 10pt; color: #374151; line-height: 1.5; }}
    .priority-tags {{ margin-top: 7pt; display: flex; gap: 6pt; flex-wrap: wrap; }}
  </style>
</head>
<body>

<div class="cover no-break">
  <div class="cover-header">
    <div>
      <div class="brand-mark">SecureScope<sup>BETA</sup></div>
      <div class="cover-meta-line" style="margin-top:4pt;">GitHub Security Analysis Platform</div>
    </div>
    <div style="text-align:right;">
      <div class="cover-meta-line">Generated: {esc(gen_at)}</div>
      <div class="cover-meta-line" style="margin-top:3pt;">MITRE ATT&amp;CK v14 · CWE Top 25</div>
    </div>
  </div>

  <div class="cover-hero">
    <div class="cover-eyebrow">Security Vulnerability Report</div>
    <div class="cover-title">Static Analysis<br>&amp; Threat Assessment</div>
    <div class="cover-repo">Repository: <a href="{esc(repo_url)}">{esc(owner)}/{esc(repo_slug)}</a></div>
    <div class="cover-date">Branch: {esc(branch)} &nbsp;·&nbsp; Analysis Engine: Semgrep + MITRE ATT&amp;CK Mapping</div>
  </div>

  <div class="cover-score-box">
    <div class="score-card accent no-break">
      <div class="score-num">{score}</div>
      <div style="font-size:8.5pt;color:#9ca3af;margin:3pt 0 6pt;font-family:'Geist Mono',monospace;">/ 100</div>
      <div class="grade-badge">{grade}</div>
      <div class="score-label">Composite Risk Score</div>
      <div style="margin:10pt 0 4pt;">{score_bar(score)}</div>
    </div>
    <div style="flex:2;display:flex;flex-direction:column;gap:10pt;">
      <div class="info-box no-break">
        <h3>Scoring Breakdown</h3>
        <div class="info-row"><span class="info-key">Critical findings &times; 10</span><span class="info-val" style="color:#dc2626;">+{len(errors)*10}</span></div>
        <div class="info-row"><span class="info-key">Warning findings &times; 3</span><span class="info-val" style="color:#d97706;">+{len(warnings)*3}</span></div>
        <div class="info-row"><span class="info-key">Dependency CVEs &times; 8</span><span class="info-val" style="color:#2563eb;">+{len(dep_vulns)*8}</span></div>
        <div class="info-row"><span class="info-key">Capped at</span><span class="info-val">100</span></div>
      </div>
    </div>
  </div>

  <div class="kpi-row no-break">
    <div class="kpi"><div class="kpi-num r">{len(errors)}</div><div class="kpi-lbl">Critical Findings</div></div>
    <div class="kpi"><div class="kpi-num w">{len(warnings)}</div><div class="kpi-lbl">Warnings</div></div>
    <div class="kpi"><div class="kpi-num b">{len(dep_vulns)}</div><div class="kpi-lbl">Dependency CVEs</div></div>
    <div class="kpi"><div class="kpi-num g">{len(cwe_counts)}</div><div class="kpi-lbl">CWE Categories</div></div>
  </div>

  <div class="cover-footer-strip">
    <div><strong>SecureScope</strong> · Open Source Security Analysis Platform<br>Findings mapped to MITRE ATT&amp;CK v14 · CWE Top 25 · OWASP Top 10</div>
    <div class="founder-line"><strong>Omar Rao</strong><br>Engineer — Data Resilience, Cybersecurity and Privacy<br>Founder, SecureScope</div>
  </div>
</div>

<div class="pb-before">
  <div class="section-eye">Executive Summary</div>
  <div class="section-title">Scan Overview</div>
  <div class="summary-grid no-break">
    <div class="info-box">
      <h3>Repository</h3>
      <div class="info-row"><span class="info-key">Owner</span><span class="info-val">{esc(owner)}</span></div>
      <div class="info-row"><span class="info-key">Repository</span><span class="info-val">{esc(repo_slug)}</span></div>
      <div class="info-row"><span class="info-key">Branch</span><span class="info-val">{esc(branch)}</span></div>
      <div class="info-row"><span class="info-key">Analysis Engine</span><span class="info-val">Semgrep</span></div>
      <div class="info-row"><span class="info-key">Generated</span><span class="info-val">{esc(gen_at)}</span></div>
    </div>
    <div class="info-box">
      <h3>Finding Breakdown</h3>
      <div class="info-row"><span class="info-key">Total Findings</span><span class="info-val">{total}</span></div>
      <div class="info-row"><span class="info-key">Critical (ERROR)</span><span class="info-val" style="color:#dc2626;">{len(errors)}</span></div>
      <div class="info-row"><span class="info-key">Warning</span><span class="info-val" style="color:#d97706;">{len(warnings)}</span></div>
      <div class="info-row"><span class="info-key">Dependency CVEs</span><span class="info-val">{len(dep_vulns)}</span></div>
      <div class="info-row"><span class="info-key">CWE Categories Hit</span><span class="info-val">{len(cwe_counts)}</span></div>
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
    <thead><tr><th>CWE Identifier</th><th style="text-align:center;">Count</th><th style="text-align:center;">Share</th><th>Distribution</th></tr></thead>
    <tbody>{cwe_rows()}</tbody>
  </table>
</div>

<div class="pb-before">
  <div class="section-eye">MITRE ATT&amp;CK Mapping</div>
  <div class="section-title">Attack Surface Analysis</div>
  <p style="font-size:10.5pt;color:#6b7280;margin-bottom:16pt;line-height:1.6;">
    Each vulnerability class is mapped to the corresponding MITRE ATT&amp;CK technique and tactic.
    Counts reflect findings from the static analysis phase. Exposed vectors require immediate
    remediation per the AI Fix Advisor output.
  </p>
  <table class="data-table">
    <thead><tr><th>Vulnerability Type</th><th>CWE</th><th>ATT&amp;CK Technique</th><th style="text-align:center;">Status</th></tr></thead>
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
    <div class="priority-file">{short_file(f.get("file",""))} · line {esc(f.get("line_start",""))}</div>
    <div class="priority-msg">{esc((f.get("message","") or "")[:220])}</div>
    <div class="priority-tags">{cwe_chip(f.get("cwe",""))}{atk_chip(f.get("attack_technique",""))}</div>
  </div>''' for f in errors[:8])}
</div>

<div class="pb-before">
  <div class="section-eye">Vulnerability Findings</div>
  <div class="section-title">Complete Findings Table ({total} findings)</div>
  <table class="data-table" style="font-size:9.5pt;">
    <thead><tr><th style="width:80pt;">Severity</th><th>Rule / Vulnerability</th><th>File &amp; Line</th><th style="width:70pt;">CWE</th><th style="width:70pt;">ATT&amp;CK</th><th>Description</th></tr></thead>
    <tbody>{findings_rows(errors + warnings)}</tbody>
  </table>
</div>

{ransomware_section()}

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
    <p style="margin-bottom:8pt;">This report is generated automatically by SecureScope and is intended for the repository owner and their authorised security team. Findings reflect the state of the codebase at the time of analysis and should be validated by a qualified security engineer before remediation work begins.</p>
    <p>SecureScope maps findings to MITRE ATT&amp;CK v14 and CWE identifiers. These mappings are best-effort. False positives are possible — Semgrep static analysis is pattern-based and does not perform dynamic execution.</p>
  </div>
</div>

</body>
</html>"""
    return HTML, owner, repo_slug
