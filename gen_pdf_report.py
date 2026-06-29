"""
Regenerate docs/sample_report.pdf from the latest analyzer report JSON.

This is a thin wrapper over the SAME pipeline the live "Print Report" download
uses (report_html.build_html → pdf_render → Playwright/Chromium), so the
committed sample and every generated report always follow one identical
standard — white background, Geist fonts, matching header/footer and sections.

Usage:  python gen_pdf_report.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

REPORTS = Path(__file__).parent / "reports"
DOCS = Path(__file__).parent / "docs"
DOCS.mkdir(exist_ok=True)
OUT_PDF = DOCS / "sample_report.pdf"


def _latest_json() -> Path:
    candidates = sorted(REPORTS.glob("analyzer_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not candidates:
        candidates = sorted(REPORTS.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not candidates:
        raise SystemExit("No report JSON found in reports/. Run a scan first.")
    return candidates[0]


if __name__ == "__main__":
    from pdf_render import render_json_to_pdf
    src = _latest_json()
    print(f"Rendering sample from {src.name} …")
    render_json_to_pdf(str(src), str(OUT_PDF))
    sz = OUT_PDF.stat().st_size / 1024
    print(f"PDF saved: {OUT_PDF}  ({sz:.0f} KB)")
