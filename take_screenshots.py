"""Take screenshots of the UI and report for the README."""
import asyncio, os
from pathlib import Path
from playwright.async_api import async_playwright

REPORT_PATH = Path(__file__).parent / "reports" / "sample_report_ui.html"
SHOTS_DIR   = Path(__file__).parent / "docs" / "screenshots"
SHOTS_DIR.mkdir(parents=True, exist_ok=True)

LANDING_URL = "http://localhost:5001"
REPORT_URL  = REPORT_PATH.as_uri()

async def shot(page, path, full=False):
    await page.wait_for_timeout(1800)
    await page.screenshot(path=str(path), full_page=full)
    print(f"  Saved: {path.name}")

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await ctx.new_page()

        # 1. Landing page
        print("[1] Landing page...")
        await page.goto(LANDING_URL, wait_until="networkidle")
        await shot(page, SHOTS_DIR / "01_landing.png")

        # 2. Landing with scan in progress (simulate filled URL)
        print("[2] Landing with URL filled...")
        await page.fill("#repoUrl", "https://github.com/OmarRao/analyzer")
        await shot(page, SHOTS_DIR / "02_ready_to_scan.png")

        # 3. Full report - overview
        print("[3] Report - overview section...")
        await page.goto(REPORT_URL, wait_until="domcontentloaded")
        await page.wait_for_timeout(2500)   # charts animate
        await shot(page, SHOTS_DIR / "03_report_overview.png")

        # 4. Threat level section
        print("[4] Report - threat level...")
        await page.evaluate("document.getElementById('threat')?.scrollIntoView()")
        await page.wait_for_timeout(600)
        await shot(page, SHOTS_DIR / "04_report_threat.png")

        # 5. Attack surface
        print("[5] Report - attack surface...")
        await page.evaluate("document.getElementById('surface')?.scrollIntoView()")
        await page.wait_for_timeout(600)
        await shot(page, SHOTS_DIR / "05_report_surface.png")

        # 6. Charts section
        print("[6] Report - analysis charts...")
        await page.evaluate("document.getElementById('charts')?.scrollIntoView()")
        await page.wait_for_timeout(1200)
        await shot(page, SHOTS_DIR / "06_report_charts.png")

        # 7. GitHub info section
        print("[7] Report - github info...")
        await page.evaluate("document.getElementById('github')?.scrollIntoView()")
        await page.wait_for_timeout(600)
        await shot(page, SHOTS_DIR / "07_report_github.png")

        # 8. Findings table
        print("[8] Report - findings table...")
        await page.evaluate("document.getElementById('findings')?.scrollIntoView()")
        await page.wait_for_timeout(600)
        await shot(page, SHOTS_DIR / "08_report_findings.png")

        # 9. MITRE ATT&CK tiles
        print("[9] Report - MITRE ATT&CK...")
        await page.evaluate("document.getElementById('mitre')?.scrollIntoView()")
        await page.wait_for_timeout(600)
        await shot(page, SHOTS_DIR / "09_report_mitre.png")

        # 10. Full report page (tall)
        print("[10] Full report scrollable...")
        await page.goto(REPORT_URL, wait_until="domcontentloaded")
        await page.wait_for_timeout(2500)
        await shot(page, SHOTS_DIR / "10_report_full.png", full=True)

        await browser.close()
        print(f"\nAll screenshots saved to: {SHOTS_DIR}")

asyncio.run(main())
