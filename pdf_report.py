"""
PDF report generator for SecureScope.

`generate(report_data)` returns PDF bytes that follow the EXACT standard set by
docs/sample_report.pdf — white background, Geist fonts, identical header/footer,
eyebrows, headings, cards, tables, distribution bars and sections.

It does this by rendering the shared HTML template (report_html.build_html) with
Chromium via Playwright — the same pipeline that produced sample_report.pdf —
so the live "Print Report" download and the committed sample never diverge.

Chromium is launched in a separate subprocess (pdf_render.py) to avoid any
collision with the eventlet/asyncio loop used by the gunicorn worker.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

_RENDERER = str(Path(__file__).parent / "pdf_render.py")


def generate(report_data: dict) -> bytes:
    """Render report_data to a sample-identical PDF and return the raw bytes."""
    tmpdir = Path(tempfile.mkdtemp(prefix="securescope_pdf_"))
    json_path = tmpdir / "report.json"
    pdf_path = tmpdir / "report.pdf"
    try:
        json_path.write_text(json.dumps(report_data), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, _RENDERER, str(json_path), str(pdf_path)],
            capture_output=True, text=True, timeout=180,
        )
        if proc.returncode != 0 or not pdf_path.exists():
            raise RuntimeError(
                "PDF render failed: " + (proc.stderr.strip() or proc.stdout.strip() or "unknown error")
            )
        return pdf_path.read_bytes()
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
