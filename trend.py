"""
Historical scan trend tracking.
Records per-scan metrics to a JSONL file and renders an SVG sparkline.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


_TREND_FILE = "trend.jsonl"


def append_scan_record(result, out_dir: str) -> None:
    """
    Append a one-line JSON record to {out_dir}/trend.jsonl.

    Record schema:
        {"ts": ISO8601, "repo": url, "total": N, "error": N, "warning": N, "info": N, "dep_vulns": N}
    """
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "repo": result.repo_url,
        "total": len(result.findings),
        "error": counts.get("ERROR", 0),
        "warning": counts.get("WARNING", 0),
        "info": counts.get("INFO", 0),
        "dep_vulns": len(result.dependency_vulns),
    }

    trend_path = Path(out_dir) / _TREND_FILE
    try:
        with open(trend_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        print(f"[trend] Cannot write trend record: {exc}")


def load_trend(repo_url: str, out_dir: str) -> list[dict]:
    """
    Read trend.jsonl and return records for repo_url, sorted by ts ascending.
    Returns an empty list if the file doesn't exist or cannot be parsed.
    """
    trend_path = Path(out_dir) / _TREND_FILE
    if not trend_path.exists():
        return []

    records = []
    try:
        for line in trend_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("repo") == repo_url:
                records.append(rec)
    except OSError:
        return []

    records.sort(key=lambda r: r.get("ts", ""))
    return records


def trend_to_html(records: list[dict]) -> str:
    """
    Render trend records as an HTML section with an inline SVG sparkline.

    X axis = scan date, Y axis = total findings count.
    Uses a simple SVG polyline — no external libraries.
    """
    if not records:
        return ""

    totals = [r.get("total", 0) for r in records]
    dates = [r.get("ts", "")[:10] for r in records]

    max_val = max(totals) if totals else 1
    min_val = min(totals) if totals else 0

    # SVG dimensions
    width, height, pad = 500, 100, 10
    n = len(totals)

    if n == 1:
        # Single point — draw a dot
        cx = width // 2
        cy = height // 2
        svg_inner = f'<circle cx="{cx}" cy="{cy}" r="4" fill="#4f8ef7"/>'
    else:
        def x_pos(i: int) -> float:
            return pad + i * (width - 2 * pad) / (n - 1)

        def y_pos(v: int) -> float:
            if max_val == min_val:
                return height / 2
            return height - pad - (v - min_val) / (max_val - min_val) * (height - 2 * pad)

        points = " ".join(f"{x_pos(i):.1f},{y_pos(v):.1f}" for i, v in enumerate(totals))
        svg_inner = (
            f'<polyline points="{points}" fill="none" stroke="#4f8ef7" stroke-width="2"/>'
        )
        # Dots
        for i, v in enumerate(totals):
            svg_inner += (
                f'<circle cx="{x_pos(i):.1f}" cy="{y_pos(v):.1f}" r="3" fill="#4f8ef7"/>'
            )

    svg = (
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="width:100%;max-width:{width}px;height:{height}px;background:#181c23;'
        f'border-radius:6px;display:block">'
        f'{svg_inner}'
        f'</svg>'
    )

    # Simple table below sparkline
    rows = ""
    for rec in records[-10:]:  # show last 10
        rows += (
            f"<tr>"
            f"<td>{rec.get('ts','')[:19]}</td>"
            f"<td>{rec.get('total',0)}</td>"
            f"<td style='color:#d32f2f'>{rec.get('error',0)}</td>"
            f"<td style='color:#f57c00'>{rec.get('warning',0)}</td>"
            f"<td>{rec.get('dep_vulns',0)}</td>"
            f"</tr>"
        )

    return f"""
<div class="sec" id="trend">
  <h2>Historical Scan Trend</h2>
  <p style="color:#888;font-size:12px">{len(records)} scans recorded for this repository.</p>
  {svg}
  <br>
  <table style="margin-top:12px">
    <thead><tr><th>Timestamp</th><th>Total</th><th>ERROR</th><th>WARNING</th><th>Dep CVEs</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
