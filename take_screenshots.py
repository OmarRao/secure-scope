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
    await page.wait_for_timeout(1200)
    await page.screenshot(path=str(path), full_page=full)
    print(f"  Saved: {path.name}")

async def click_first(page, selectors, timeout=5000):
    """Try a list of selectors in order until one works."""
    for sel in selectors:
        try:
            await page.click(sel, timeout=timeout)
            return True
        except Exception:
            pass
    return False

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await ctx.new_page()

        # 1. Landing page - dark mode
        print("[1] Landing page (dark)...")
        await page.goto(LANDING_URL, wait_until="networkidle")
        await shot(page, SHOTS_DIR / "01_landing_dark.png")

        # 2. Open modal - Step 1
        print("[2] Modal wizard - step 1 (repo URL)...")
        opened = await click_first(page, [
            "text=Analyze Repository",
            ".hero-cta",
            "#openModal",
            "button:has-text('Analyze')",
            "button:has-text('Scan')",
        ])
        await page.wait_for_timeout(800)
        await shot(page, SHOTS_DIR / "02_modal_step1.png")

        # 3. Step 2 - Provider selection
        print("[3] Modal wizard - step 2 (AI provider)...")
        await click_first(page, [
            "text=Next",
            ".btn-next",
            "#nextBtn",
            "button:has-text('Next')",
            "button:has-text('Continue')",
        ])
        await page.wait_for_timeout(600)
        await shot(page, SHOTS_DIR / "03_modal_step2_providers.png")

        # 4. Step 3 - Scan options
        print("[4] Modal wizard - step 3 (scan options)...")
        await click_first(page, [
            "text=Next",
            ".btn-next",
            "#nextBtn",
            "button:has-text('Next')",
            "button:has-text('Continue')",
        ])
        await page.wait_for_timeout(600)
        await shot(page, SHOTS_DIR / "04_modal_step3_options.png")

        # 5. Close modal, switch to light mode
        print("[5] Landing page (light mode)...")
        await page.keyboard.press("Escape")
        await page.wait_for_timeout(400)
        await click_first(page, [
            ".theme-btn",
            "#themeToggle",
            "button[aria-label*='theme']",
            "button[title*='theme']",
            "button[title*='Theme']",
            "button[title*='Light']",
        ])
        await page.wait_for_timeout(800)
        await shot(page, SHOTS_DIR / "05_landing_light.png")

        # Back to dark
        await click_first(page, [
            ".theme-btn",
            "#themeToggle",
            "button[aria-label*='theme']",
            "button[title*='theme']",
        ])
        await page.wait_for_timeout(400)

        # 6-11: Report screenshots (if sample report exists)
        if REPORT_PATH.exists():
            print("[6] Report - overview...")
            await page.goto(REPORT_URL, wait_until="domcontentloaded")
            await page.wait_for_timeout(2500)
            await shot(page, SHOTS_DIR / "06_report_overview.png")

            print("[7] Report - threat level...")
            await page.evaluate("document.getElementById('threat')?.scrollIntoView()")
            await page.wait_for_timeout(600)
            await shot(page, SHOTS_DIR / "07_report_threat.png")

            print("[8] Report - attack surface...")
            await page.evaluate("document.getElementById('surface')?.scrollIntoView()")
            await page.wait_for_timeout(600)
            await shot(page, SHOTS_DIR / "08_report_surface.png")

            print("[9] Report - charts...")
            await page.evaluate("document.getElementById('charts')?.scrollIntoView()")
            await page.wait_for_timeout(1200)
            await shot(page, SHOTS_DIR / "09_report_charts.png")

            print("[10] Report - findings table...")
            await page.evaluate("document.getElementById('findings')?.scrollIntoView()")
            await page.wait_for_timeout(600)
            await shot(page, SHOTS_DIR / "10_report_findings.png")

            # Light mode report
            print("[11] Report - light mode...")
            await click_first(page, [
                ".theme-btn", "#themeToggle",
                "button[title*='theme']", "button[title*='Light']",
            ])
            await page.wait_for_timeout(700)
            await page.evaluate("window.scrollTo(0,0)")
            await page.wait_for_timeout(400)
            await shot(page, SHOTS_DIR / "11_report_light.png")
        else:
            print("  [skip] No sample report found - run gen_sample.py first")

        await browser.close()
        print(f"\nAll screenshots saved to: {SHOTS_DIR}")

asyncio.run(main())
