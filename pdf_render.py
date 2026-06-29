"""
HTML → PDF renderer using Playwright/Chromium.

Renders the SecureScope report HTML (from report_html.build_html) to an A4 PDF
that is pixel-identical in style to docs/sample_report.pdf — white background,
Geist fonts, print backgrounds, and the standard page footer.

Run as a subprocess so Chromium never collides with the eventlet/asyncio loop
used by the gunicorn worker:

    python pdf_render.py <input.json> <output.pdf>

<input.json> is a report JSON (report.to_json shape).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def render_json_to_pdf(json_path: str, out_pdf: str) -> None:
    import json
    from report_html import build_html, esc

    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    html, owner, slug = build_html(data)

    tmp_html = Path(out_pdf).with_suffix(".html")
    tmp_html.write_text(html, encoding="utf-8")
    try:
        from playwright.sync_api import sync_playwright
        footer = (
            '<div style="width:100%;padding:0 16mm;display:flex;justify-content:space-between;'
            'font-family:\'Courier New\',monospace;font-size:8px;color:#9ca3af;'
            'border-top:1px solid #e5e7eb;padding-top:5px;">'
            f'<span>SecureScope Security Report &nbsp;&middot;&nbsp; {esc(owner)}/{esc(slug)}</span>'
            '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>'
            '</div>'
        )
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page()
            page.goto(tmp_html.as_uri(), wait_until="networkidle")
            page.wait_for_timeout(2200)  # allow Google Fonts to load
            page.pdf(
                path=out_pdf,
                format="A4",
                print_background=True,
                margin={"top": "18mm", "bottom": "14mm", "left": "16mm", "right": "16mm"},
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=footer,
            )
            browser.close()
    finally:
        tmp_html.unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python pdf_render.py <input.json> <output.pdf>", file=sys.stderr)
        sys.exit(2)
    render_json_to_pdf(sys.argv[1], sys.argv[2])
