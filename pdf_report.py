"""
Export SecureScope HTML report to PDF.
Falls back gracefully if weasyprint is not installed.
"""

from pathlib import Path
from typing import Optional


def install_hint() -> None:
    """Print installation instructions for weasyprint."""
    print("  pip install weasyprint")
    print("  # On Linux also: apt-get install libpango-1.0-0 libpangocairo-1.0-0")


def to_pdf(html_path: str, pdf_path: str) -> Optional[str]:
    """
    Convert an HTML report file to PDF.

    Tries weasyprint first. If not installed, prints a hint and returns None.

    Args:
        html_path: Path to the source HTML file.
        pdf_path:  Destination path for the PDF file.

    Returns:
        pdf_path if successful, None if weasyprint is unavailable.
    """
    try:
        from weasyprint import HTML  # type: ignore
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        print(f"[+] PDF report: {pdf_path}")
        return pdf_path
    except ImportError:
        print("[!] weasyprint not installed — PDF export skipped.")
        print("[!] To enable PDF export, install weasyprint:")
        install_hint()
        return None
    except Exception as exc:
        print(f"[!] PDF export failed: {exc}")
        return None
