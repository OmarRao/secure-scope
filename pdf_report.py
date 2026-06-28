"""
PDF report generator for SecureScope.

Produces a structured multi-page PDF matching the sample_report.pdf layout:
  Page 1  — Cover (logo, repo, risk score, key stats)
  Page 2  — Executive Summary + Risk Score Detail
  Page 3  — CWE Distribution table
  Page 4  — MITRE ATT&CK Mapping table
  Page 5+ — Full Findings (paginated, one card per finding)

Usage:
    from pdf_report import generate as generate_pdf
    pdf_bytes = generate_pdf(report_data)
"""

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, KeepTogether,
)

# ── Brand palette ──────────────────────────────────────────────────────────
C_BG       = colors.HexColor("#0a0c0f")
C_ACCENT   = colors.HexColor("#4f8ef7")
C_DANGER   = colors.HexColor("#f25757")
C_WARN     = colors.HexColor("#e6a817")
C_OK       = colors.HexColor("#3ecf79")
C_TAG      = colors.HexColor("#a78bfa")
C_MUTED    = colors.HexColor("#6b7785")
C_RULE     = colors.HexColor("#252b35")
C_WHITE    = colors.white
C_DARK_ROW = colors.HexColor("#f7fafc")

W, H   = A4
MARGIN = 1.8 * cm


def _sev_color(sev: str):
    s = (sev or "").upper()
    return C_DANGER if s in ("ERROR", "CRITICAL") else (C_WARN if s == "WARNING" else C_ACCENT)


def _grade(score: int) -> str:
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"


def _score_color(score: int):
    if score >= 70: return C_DANGER
    if score >= 45: return C_WARN
    if score >= 20: return C_ACCENT
    return C_OK


# ── Paragraph styles ───────────────────────────────────────────────────────
def _s(name, **kw):
    defaults = dict(fontName="Helvetica", fontSize=9, leading=13,
                    textColor=colors.HexColor("#1a202c"))
    return ParagraphStyle(name, **{**defaults, **kw})


ST = {
    "cover_h1":   _s("ch1", fontSize=36, leading=42, textColor=C_WHITE, fontName="Helvetica-Bold"),
    "cover_sub":  _s("csub", fontSize=12, leading=16, textColor=colors.HexColor("#a0aec0")),
    "cover_meta": _s("cmeta", fontSize=8, leading=12, textColor=colors.HexColor("#6b7785"), fontName="Courier"),
    "cover_score":_s("csc", fontSize=76, leading=84, textColor=C_DANGER, fontName="Helvetica-Bold", alignment=TA_CENTER),
    "cover_grade":_s("cg", fontSize=15, leading=20, textColor=C_DANGER, fontName="Helvetica-Bold", alignment=TA_CENTER),
    "section":    _s("sec", fontSize=8, leading=11, textColor=C_ACCENT, fontName="Courier-Bold", letterSpacing=1.4),
    "h2":         _s("h2", fontSize=14, leading=18, textColor=colors.HexColor("#0a0c0f"), fontName="Helvetica-Bold"),
    "body":       _s("body", fontSize=9, leading=13, textColor=colors.HexColor("#2d3748")),
    "mono":       _s("mono", fontSize=8, leading=11, fontName="Courier", textColor=colors.HexColor("#4a5568")),
    "label":      _s("lbl", fontSize=7, leading=10, fontName="Courier-Bold", textColor=C_MUTED, letterSpacing=0.8),
    "tbl_hdr":    _s("th", fontSize=7, leading=10, fontName="Helvetica-Bold", textColor=C_WHITE),
    "tbl_cell":   _s("tc", fontSize=8, leading=11, textColor=colors.HexColor("#1a202c")),
    "tbl_mono":   _s("tm", fontSize=7, leading=10, fontName="Courier", textColor=colors.HexColor("#2d3748")),
    "danger":     _s("dng", fontSize=8, leading=11, fontName="Helvetica-Bold", textColor=C_DANGER),
    "warn":       _s("wrn", fontSize=8, leading=11, fontName="Helvetica-Bold", textColor=C_WARN),
    "ok":         _s("ok_", fontSize=8, leading=11, fontName="Courier", textColor=C_OK),
}


def _hr(color=C_RULE, thickness=0.5, space=6):
    return HRFlowable(width="100%", thickness=thickness, color=color,
                      spaceAfter=space, spaceBefore=space)


def _sec_head(text: str):
    return KeepTogether([
        Spacer(1, 0.35 * cm),
        Paragraph(text.upper(), ST["section"]),
        _hr(C_ACCENT, 0.8, 4),
    ])


# ── Page templates ─────────────────────────────────────────────────────────
def _draw_cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, H - 5, W, 5, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#111419"))
    canvas.rect(0, 0, W, 100, fill=1, stroke=0)
    canvas.restoreState()


def _draw_body(canvas, doc):
    canvas.saveState()
    # Header
    canvas.setFillColor(C_BG)
    canvas.rect(0, H - 36, W, 36, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, H - 39, W, 3, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(MARGIN, H - 22, "SecureScope")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#6b7785"))
    canvas.drawString(MARGIN + 68, H - 22, "BETA")
    canvas.setFont("Courier", 7)
    canvas.setFillColor(colors.HexColor("#a0aec0"))
    canvas.drawRightString(W - MARGIN, H - 22, getattr(doc, "_slug", ""))
    # Footer
    canvas.setFillColor(colors.HexColor("#f0f4f8"))
    canvas.rect(0, 0, W, 28, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#cbd5e0"))
    canvas.rect(0, 28, W, 0.5, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#718096"))
    canvas.drawString(MARGIN, 9, f"SecureScope Security Report — {getattr(doc,'_slug','')}")
    canvas.drawRightString(W - MARGIN, 9, f"Page {doc.page}")
    canvas.restoreState()


# ── Finding card ───────────────────────────────────────────────────────────
def _finding_card(f: dict, idx: int, usable_w: float):
    sev = (f.get("severity") or "INFO").upper()
    sc  = _sev_color(sev)
    title = (f.get("rule_id") or "").split(".")[-1].replace("-", " ").title() or f"Finding {idx}"
    file_line = f"{f.get('file','?')} — line {f.get('line_start','?')}"
    meta_parts = [x for x in [f.get("cwe"), f.get("attack_technique"), f.get("attack_tactic")] if x]
    msg = (f.get("message") or "")[:320]
    fix = (f.get("fix_suggestion") or "")[:220]

    lw, rw = usable_w * 0.78, usable_w * 0.22
    rows = [
        [Paragraph(f"{idx}. {title}", _s("ft", fontSize=8, fontName="Helvetica-Bold", textColor=sc, leading=11)),
         Paragraph(sev, _s("fs", fontSize=7, fontName="Helvetica-Bold", textColor=sc, leading=10, alignment=TA_RIGHT))],
        [Paragraph(file_line, _s("ff", fontSize=7, fontName="Courier", textColor=C_MUTED, leading=10)),
         Paragraph("  ·  ".join(meta_parts), _s("fm", fontSize=7, fontName="Courier", textColor=C_MUTED, leading=10, alignment=TA_RIGHT))],
    ]
    spans = []
    if msg:
        rows.append([Paragraph(msg, _s("fmsg", fontSize=8, textColor=colors.HexColor("#2d3748"), leading=12)), ""])
        spans.append(("SPAN", (0, len(rows)-1), (1, len(rows)-1)))
    if fix:
        rows.append([Paragraph(f"→ {fix}", _s("ffix", fontSize=7, fontName="Courier", textColor=C_OK, leading=11)), ""])
        spans.append(("SPAN", (0, len(rows)-1), (1, len(rows)-1)))

    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("LINEABOVE",     (0, 0), (-1, 0),  1.5, sc),
        ("BOX",           (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ] + spans

    tbl = Table(rows, colWidths=[lw, rw])
    tbl.setStyle(TableStyle(style_cmds))
    return KeepTogether([tbl, Spacer(1, 4)])


# ── Main entry point ───────────────────────────────────────────────────────
def generate(report_data: dict) -> bytes:
    """Return raw PDF bytes for the given report_data dict."""
    buf = io.BytesIO()

    repo_url    = report_data.get("repo_url", "")
    repo_slug   = report_data.get("repo_slug", "repo")
    generated   = report_data.get("generated_at",
                    datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC"))
    gh          = report_data.get("gh_info") or {}
    summary     = report_data.get("summary") or {}
    findings    = report_data.get("findings") or []
    dep_vulns   = report_data.get("dependency_vulns") or []

    owner     = gh.get("owner", "")
    repo_name = gh.get("name", repo_slug)
    branch    = gh.get("default_branch", "main")
    language  = gh.get("primary_language", "Unknown")

    total     = len(findings)
    critical  = sum(1 for f in findings if (f.get("severity") or "").upper() in ("ERROR", "CRITICAL"))
    warnings  = sum(1 for f in findings if (f.get("severity") or "").upper() == "WARNING")
    dep_cnt   = len(dep_vulns)
    cwe_set   = set(f.get("cwe", "") for f in findings if f.get("cwe"))
    score     = min(100, critical * 10 + warnings * 3 + dep_cnt * 8)
    sc        = _score_color(score)
    grade     = _grade(score)
    slug      = f"{owner}/{repo_name}" if owner else repo_name

    doc = BaseDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN + 0.4 * cm, bottomMargin=1.6 * cm,
    )
    doc._slug = slug

    cover_frame = Frame(0, 0, W, H, leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0)
    body_frame  = Frame(MARGIN, 1.5 * cm, W - 2 * MARGIN, H - MARGIN - 2.2 * cm,
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=_draw_cover),
        PageTemplate(id="body",  frames=[body_frame],  onPage=_draw_body),
    ])

    UW = W - 2 * MARGIN   # usable width on body pages
    story = []

    # ── COVER ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 2.2 * cm))
    px = 2 * cm
    story.append(Paragraph("SecureScope", _s("cl", fontSize=38, leading=44,
        textColor=C_WHITE, fontName="Helvetica-Bold", leftIndent=px)))
    story.append(Paragraph("BETA — GitHub Security Analysis Platform",
        _s("cs", fontSize=12, leading=16, textColor=colors.HexColor("#a0aec0"), leftIndent=px)))
    story.append(Spacer(1, 0.25 * cm))
    story.append(Paragraph(f"Generated: {generated}",
        _s("cg2", fontSize=9, leading=12, textColor=colors.HexColor("#6b7785"),
           fontName="Courier", leftIndent=px)))
    story.append(Paragraph("MITRE ATT&CK v14  ·  CWE Top 25",
        _s("cm2", fontSize=9, leading=12, textColor=colors.HexColor("#6b7785"),
           fontName="Courier", leftIndent=px)))
    story.append(Spacer(1, 1.0 * cm))

    bw = W - 4 * cm
    score_box = Table([
        [Paragraph("SECURITY VULNERABILITY REPORT",
            _s("cvt", fontSize=8, fontName="Courier-Bold", textColor=C_ACCENT,
               letterSpacing=1.5, alignment=TA_CENTER))],
        [Paragraph("Static Analysis &amp; Threat Assessment",
            _s("cvs", fontSize=17, fontName="Helvetica-Bold", textColor=C_WHITE,
               alignment=TA_CENTER, leading=22))],
        [Paragraph(
            f"Repository: {slug}  ·  Branch: {branch}  ·  Engine: Semgrep + MITRE ATT&amp;CK",
            _s("cvr", fontSize=8, fontName="Courier", textColor=colors.HexColor("#a0aec0"),
               alignment=TA_CENTER))],
        [Spacer(1, 0.4 * cm)],
        [Paragraph(str(score), _s("cvsc", fontSize=84, fontName="Helvetica-Bold",
           textColor=sc, alignment=TA_CENTER, leading=92))],
        [Paragraph("/ 100", _s("cvd", fontSize=14, textColor=colors.HexColor("#6b7785"),
           alignment=TA_CENTER))],
        [Paragraph(grade, _s("cvg", fontSize=17, fontName="Helvetica-Bold",
           textColor=sc, alignment=TA_CENTER))],
        [Spacer(1, 0.2 * cm)],
        [Paragraph("0 — LOW  ·  20 — MEDIUM  ·  45 — HIGH  ·  70 — CRITICAL  ·  100",
            _s("crl", fontSize=8, fontName="Courier", textColor=colors.HexColor("#6b7785"),
               alignment=TA_CENTER))],
    ], colWidths=[bw])
    score_box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#111419")),
        ("BOX",           (0, 0), (-1, -1), 1, C_RULE),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING",   (0, 0), (-1, -1), 22),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 22),
    ]))
    story.append(score_box)
    story.append(Spacer(1, 0.7 * cm))

    sw = bw / 4
    stat_box = Table([
        [Paragraph(str(critical), _s("s1", fontSize=30, fontName="Helvetica-Bold",
             textColor=C_DANGER, alignment=TA_CENTER)),
         Paragraph(str(warnings), _s("s2", fontSize=30, fontName="Helvetica-Bold",
             textColor=C_WARN, alignment=TA_CENTER)),
         Paragraph(str(dep_cnt), _s("s3", fontSize=30, fontName="Helvetica-Bold",
             textColor=C_ACCENT, alignment=TA_CENTER)),
         Paragraph(str(len(cwe_set)), _s("s4", fontSize=30, fontName="Helvetica-Bold",
             textColor=C_TAG, alignment=TA_CENTER))],
        [Paragraph("Critical Findings", _s("l1", fontSize=7, fontName="Courier", textColor=C_MUTED, alignment=TA_CENTER)),
         Paragraph("Warnings",          _s("l2", fontSize=7, fontName="Courier", textColor=C_MUTED, alignment=TA_CENTER)),
         Paragraph("Dependency CVEs",   _s("l3", fontSize=7, fontName="Courier", textColor=C_MUTED, alignment=TA_CENTER)),
         Paragraph("CWE Categories",    _s("l4", fontSize=7, fontName="Courier", textColor=C_MUTED, alignment=TA_CENTER))],
    ], colWidths=[sw, sw, sw, sw])
    stat_box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#0d1117")),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_RULE),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_RULE),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(stat_box)
    story.append(Spacer(1, 1.4 * cm))
    story.append(Paragraph(
        "SecureScope  ·  Open Source Security Analysis Platform",
        _s("bf1", fontSize=8, textColor=colors.HexColor("#6b7785"), fontName="Courier", leftIndent=px)))
    story.append(Paragraph(
        "Findings mapped to MITRE ATT&amp;CK v14  ·  CWE Top 25  ·  OWASP Top 10",
        _s("bf2", fontSize=8, textColor=colors.HexColor("#6b7785"), fontName="Courier", leftIndent=px)))
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ──────────────────────────────────────────────────
    story.append(_sec_head("Executive Summary"))
    story.append(Spacer(1, 0.15 * cm))

    lw2, rw2 = UW * 0.46, UW * 0.46
    gap = UW * 0.08

    left_rows = [
        [Paragraph("REPOSITORY", ST["label"]), ""],
        [Paragraph("Owner",          ST["body"]), Paragraph(owner,     ST["mono"])],
        [Paragraph("Repository",     ST["body"]), Paragraph(repo_name, ST["mono"])],
        [Paragraph("Branch",         ST["body"]), Paragraph(branch,    ST["mono"])],
        [Paragraph("Language",       ST["body"]), Paragraph(language,  ST["mono"])],
        [Paragraph("Generated",      ST["body"]), Paragraph(generated, ST["mono"])],
        [Spacer(1, 4), ""],
        [Paragraph("FINDING BREAKDOWN", ST["label"]), ""],
        [Paragraph("Total Findings",    ST["body"]), Paragraph(str(total),    ST["mono"])],
        [Paragraph("Critical (ERROR)",  ST["body"]), Paragraph(str(critical), ST["danger"])],
        [Paragraph("Warning",           ST["body"]), Paragraph(str(warnings), ST["warn"])],
        [Paragraph("Dependency CVEs",   ST["body"]), Paragraph(str(dep_cnt),  ST["mono"])],
        [Paragraph("CWE Categories",    ST["body"]), Paragraph(str(len(cwe_set)), ST["mono"])],
    ]
    left_tbl = Table(left_rows, colWidths=[lw2 * 0.52, lw2 * 0.48])
    left_tbl.setStyle(TableStyle([
        ("LINEBELOW",     (0, 0), (-1, 0), 0.5, colors.HexColor("#e2e8f0")),
        ("LINEBELOW",     (0, 7), (-1, 7), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))

    right_rows = [
        [Paragraph("RISK SCORE DETAIL", ST["label"]), ""],
        [Paragraph(str(score), _s("rs", fontSize=44, fontName="Helvetica-Bold",
            textColor=sc, leading=50)),
         Paragraph(f"/100\n{grade}", _s("rg", fontSize=12, fontName="Helvetica-Bold",
            textColor=sc, leading=18))],
        [Paragraph(
            "Score = (critical×10) + (warnings×3) + (CVEs×8), capped at 100.",
            _s("rf", fontSize=7, fontName="Courier", textColor=C_MUTED, leading=10)), ""],
        [Spacer(1, 4), ""],
        [Paragraph("SCORING BREAKDOWN", ST["label"]), ""],
        [Paragraph("Critical findings", ST["body"]),
         Paragraph(f"× 10 = +{critical*10}", ST["mono"])],
        [Paragraph("Warning findings",  ST["body"]),
         Paragraph(f"× 3  = +{warnings*3}",  ST["mono"])],
        [Paragraph("Dependency CVEs",   ST["body"]),
         Paragraph(f"× 8  = +{dep_cnt*8}",  ST["mono"])],
        [Paragraph("Capped at",         ST["body"]),
         Paragraph("100", _s("cap", fontSize=8, fontName="Helvetica-Bold", textColor=sc))],
    ]
    right_tbl = Table(right_rows, colWidths=[rw2 * 0.55, rw2 * 0.45])
    right_tbl.setStyle(TableStyle([
        ("LINEBELOW",     (0, 0), (-1, 0), 0.5, colors.HexColor("#e2e8f0")),
        ("LINEBELOW",     (0, 4), (-1, 4), 0.5, colors.HexColor("#e2e8f0")),
        ("SPAN",          (0, 2), (-1, 2)),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ]))

    two_col = Table([[left_tbl, Spacer(gap, 1), right_tbl]],
                    colWidths=[lw2, gap, rw2])
    two_col.setStyle(TableStyle([
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",(0, 0), (-1, -1), 0),
    ]))
    story.append(two_col)
    story.append(PageBreak())

    # ── CWE DISTRIBUTION ──────────────────────────────────────────────────
    story.append(_sec_head("CWE Distribution"))
    story.append(Paragraph("Vulnerability Category Breakdown", ST["body"]))
    story.append(Spacer(1, 0.25 * cm))

    cwe_map: dict[str, int] = {}
    for f in findings:
        k = f.get("cwe") or "Unknown"
        cwe_map[k] = cwe_map.get(k, 0) + 1
    cwe_sorted = sorted(cwe_map.items(), key=lambda x: -x[1])
    tf = len(findings) or 1

    cw = [UW * 0.18, UW * 0.10, UW * 0.10, UW * 0.62]
    cwe_rows = [[Paragraph(h, ST["tbl_hdr"]) for h in
                 ["CWE IDENTIFIER", "COUNT", "SHARE", "DISTRIBUTION"]]]
    for cwe, cnt in cwe_sorted[:25]:
        pct = cnt / tf * 100
        bar = "█" * int(pct / 3) + "░" * (33 - int(pct / 3))
        cwe_rows.append([
            Paragraph(cwe, ST["tbl_mono"]),
            Paragraph(str(cnt), ST["tbl_cell"]),
            Paragraph(f"{pct:.0f}%", ST["tbl_cell"]),
            Paragraph(bar[:33], _s("bar", fontSize=6, fontName="Courier", textColor=C_ACCENT)),
        ])

    cwe_tbl = Table(cwe_rows, colWidths=cw, repeatRows=1)
    cwe_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), C_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_DARK_ROW]),
        ("LINEBELOW",      (0, 0), (-1, 0), 1, C_ACCENT),
        ("GRID",           (0, 1), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
    ]))
    story.append(cwe_tbl)
    story.append(PageBreak())

    # ── MITRE ATT&CK MAPPING ──────────────────────────────────────────────
    story.append(_sec_head("MITRE ATT&CK Mapping"))
    story.append(Paragraph(
        "Attack Surface Analysis — each vulnerability class mapped to MITRE ATT&CK technique and tactic.",
        ST["body"]))
    story.append(Spacer(1, 0.25 * cm))

    tech_map: dict[tuple, int] = {}
    for f in findings:
        tq  = f.get("attack_technique") or ""
        cwe = f.get("cwe") or ""
        nm  = (f.get("attack_name") or
               (f.get("rule_id") or "").split(".")[-1].replace("-", " ").title())
        tac = f.get("attack_tactic") or ""
        if tq:
            k = (nm[:38], cwe, tq, tac)
            tech_map[k] = tech_map.get(k, 0) + 1

    mw = [UW * 0.28, UW * 0.12, UW * 0.14, UW * 0.28, UW * 0.18]
    mitre_rows = [[Paragraph(h, ST["tbl_hdr"]) for h in
                   ["VULNERABILITY TYPE", "CWE", "ATT&CK TECHNIQUE", "TACTIC", "COUNT"]]]
    for (nm, cwe, tq, tac), cnt in sorted(tech_map.items(), key=lambda x: -x[1])[:30]:
        cc = C_DANGER if cnt > 10 else C_WARN
        mitre_rows.append([
            Paragraph(nm, ST["tbl_cell"]),
            Paragraph(cwe, ST["tbl_mono"]),
            Paragraph(tq,  ST["tbl_mono"]),
            Paragraph(tac[:22], ST["tbl_cell"]),
            Paragraph(f"{cnt} findings", _s("mc", fontSize=8, textColor=cc)),
        ])
    if len(mitre_rows) == 1:
        mitre_rows.append([Paragraph("No ATT&CK techniques mapped in findings.", ST["body"]),
                           "", "", "", ""])

    mitre_tbl = Table(mitre_rows, colWidths=mw, repeatRows=1)
    mitre_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), C_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_DARK_ROW]),
        ("LINEBELOW",      (0, 0), (-1, 0), 1, C_ACCENT),
        ("GRID",           (0, 1), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
    ]))
    story.append(mitre_tbl)
    story.append(PageBreak())

    # ── FINDINGS ──────────────────────────────────────────────────────────
    sorted_f = sorted(findings, key=lambda f: (
        0 if (f.get("severity") or "").upper() in ("ERROR", "CRITICAL") else
        1 if (f.get("severity") or "").upper() == "WARNING" else 2
    ))

    story.append(_sec_head("Top Priority Findings"))
    story.append(Paragraph("Critical Issues Requiring Immediate Action", ST["body"]))
    story.append(Spacer(1, 0.2 * cm))

    for i, f in enumerate(sorted_f, 1):
        story.append(_finding_card(f, i, UW))
        if i % 35 == 0 and i < len(sorted_f):
            story.append(PageBreak())
            story.append(_sec_head(f"Findings — continued ({i+1}–{min(i+35, len(sorted_f))} of {len(sorted_f)})"))

    if not sorted_f:
        story.append(Paragraph(
            "✅ No findings — repository passed all security checks.", ST["body"]))

    doc.build(story)
    return buf.getvalue()
