"""
yara_scanner.py — SecureScope YARA Rule Engine

Executes predefined YARA rules against target paths (backup directories,
infrastructure files, staging areas). Returns structured match results
suitable for streaming to the SecureScope UI via Socket.IO.

Falls back gracefully if the 'yara' Python package is not installed:
all functions remain callable but return a YaraScanResult with yara_available=False
and a note in the errors list.

Install yara-python for full functionality:
    pip install yara-python

On Windows, yara-python may require Visual C++ Build Tools. An alternative
is to install via conda: conda install -c conda-forge yara-python
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# ── Graceful YARA import ──────────────────────────────────────────────────────
# If yara-python is not installed, YARA_AVAILABLE is set to False and all scan
# functions degrade gracefully, returning simulated results with an advisory note.
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None  # type: ignore[assignment]

# ── Path to the bundled YARA rules directory ──────────────────────────────────
# Rules live alongside this module in the yara_rules/ subdirectory.
YARA_RULES_DIR = Path(__file__).parent / "yara_rules"

# ── File extensions that YARA scanning is meaningful for ─────────────────────
# Avoid scanning binary media, archive blobs, or very large data files by default.
SCANNABLE_EXTENSIONS = {
    # Scripts and source code
    ".py", ".js", ".ts", ".sh", ".ps1", ".bat", ".cmd", ".vbs", ".wsf",
    ".rb", ".pl", ".php", ".go", ".rs", ".c", ".cpp", ".cs", ".java",
    # Configuration and data
    ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".toml",
    # Documents that may contain macros or ransom notes
    ".txt", ".html", ".htm", ".md",
    # Executables and libraries (when scanning for malware)
    ".exe", ".dll", ".sys", ".so", ".dylib",
    # Backup-related extensions
    ".bak", ".vbk", ".vib", ".vrb", ".sql",
}

# ── Maximum file size to scan (bytes) — skip very large binary files ──────────
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class YaraMatch:
    """
    Represents a single YARA rule match against a file.

    Attributes:
        rule_name:       Name of the matched YARA rule.
        threat_family:   Threat family from the rule's meta.threat_family field.
        severity:        Severity level from the rule's meta.severity field.
        file_path:       Absolute path of the file that triggered the match.
        offset:          Byte offset within the file where the first match occurred.
        matched_strings: List of string identifiers that triggered the rule match.
    """

    rule_name: str
    threat_family: str
    severity: str
    file_path: str
    offset: int
    matched_strings: list[str]

    def to_dict(self) -> dict:
        """Serialise this match to a plain dict for JSON encoding."""
        return {
            "rule_name": self.rule_name,
            "threat_family": self.threat_family,
            "severity": self.severity,
            "file_path": self.file_path,
            "offset": self.offset,
            "matched_strings": self.matched_strings,
        }


@dataclass
class YaraScanResult:
    """
    Aggregated result of a YARA scan over a target path.

    Attributes:
        scan_path:      The path that was scanned.
        rules_loaded:   List of rule file names that were loaded.
        files_scanned:  Number of files examined.
        matches:        List of YaraMatch objects for all rule hits.
        errors:         List of error/warning strings encountered during the scan.
        duration_sec:   Wall-clock seconds the scan took.
        yara_available: Whether the yara-python package was available.
    """

    scan_path: str
    rules_loaded: list[str]
    files_scanned: int
    matches: list[YaraMatch]
    errors: list[str]
    duration_sec: float
    yara_available: bool

    def to_dict(self) -> dict:
        """Serialise this scan result to a plain dict for JSON encoding."""
        return {
            "scan_path": self.scan_path,
            "rules_loaded": self.rules_loaded,
            "files_scanned": self.files_scanned,
            "matches": [m.to_dict() for m in self.matches],
            "errors": self.errors,
            "duration_sec": round(self.duration_sec, 2),
            "yara_available": self.yara_available,
        }


# ── Rule catalogue ────────────────────────────────────────────────────────────

def list_rules() -> list[dict]:
    """
    Return metadata for all available YARA rule files in YARA_RULES_DIR.

    Each entry includes the filename, the display name derived from the filename,
    and the number of rules contained in the file (counted by 'rule ' keyword).

    Returns:
        List of dicts with keys: filename, display_name, rule_count, path.
        Returns an empty list if the rules directory does not exist.
    """
    # If the rules directory does not exist, return empty catalogue
    if not YARA_RULES_DIR.exists():
        return []

    catalogue = []
    for yar_file in sorted(YARA_RULES_DIR.glob("*.yar")):
        # Derive a human-readable display name from the filename
        display_name = yar_file.stem.replace("_", " ").title()

        # Count 'rule ' occurrences as an estimate of rule count
        try:
            content = yar_file.read_text(encoding="utf-8", errors="ignore")
            rule_count = content.lower().count("\nrule ")
        except OSError:
            rule_count = 0

        catalogue.append({
            "filename": yar_file.name,
            "display_name": display_name,
            "rule_count": rule_count,
            "path": str(yar_file),
        })

    return catalogue


# ── Rule loading ──────────────────────────────────────────────────────────────

def _load_rules(rule_names: Optional[list[str]] = None):
    """
    Load and compile the requested YARA rules.

    If rule_names is None or empty, all .yar files in YARA_RULES_DIR are loaded.
    Returns a compiled yara.Rules object or None on failure.

    Args:
        rule_names: Optional list of .yar filenames to load (e.g. ["lockbit.yar"]).

    Returns:
        Tuple of (compiled_rules, loaded_filenames, error_messages).
    """
    # Determine which files to load
    if rule_names:
        # Filter to only the requested rule files
        yar_files = [YARA_RULES_DIR / name for name in rule_names
                     if (YARA_RULES_DIR / name).exists()]
    else:
        # Load all available .yar files
        yar_files = sorted(YARA_RULES_DIR.glob("*.yar"))

    if not yar_files:
        return None, [], ["No YARA rule files found in rules directory"]

    # Build a dict mapping namespace -> filepath for yara.compile(filepaths=...)
    filepaths = {}
    errors = []
    loaded_names = []

    for yar_file in yar_files:
        # Use the stem as the namespace to avoid rule name collisions across files
        namespace = yar_file.stem
        filepaths[namespace] = str(yar_file)
        loaded_names.append(yar_file.name)

    try:
        # Compile all selected rules in one pass
        compiled = yara.compile(filepaths=filepaths)
        return compiled, loaded_names, errors
    except Exception as exc:
        errors.append(f"YARA compile error: {exc}")
        return None, loaded_names, errors


# ── File collection ───────────────────────────────────────────────────────────

def _collect_files(target_path: str) -> list[Path]:
    """
    Collect all scannable files under target_path.

    Walks the directory tree (or handles a single file) and returns paths
    for files matching SCANNABLE_EXTENSIONS that are under MAX_FILE_SIZE_BYTES.

    Args:
        target_path: File or directory path to scan.

    Returns:
        Sorted list of Path objects for files to scan.
    """
    root = Path(target_path)
    files = []

    if root.is_file():
        # Single file mode
        if root.stat().st_size <= MAX_FILE_SIZE_BYTES:
            files.append(root)
    elif root.is_dir():
        # Walk the directory tree
        for dirpath, _dirnames, filenames in os.walk(root):
            for fname in filenames:
                fpath = Path(dirpath) / fname
                # Only scan files with recognised extensions
                if fpath.suffix.lower() in SCANNABLE_EXTENSIONS:
                    try:
                        if fpath.stat().st_size <= MAX_FILE_SIZE_BYTES:
                            files.append(fpath)
                    except OSError:
                        pass  # Skip files we cannot stat

    return sorted(files)


# ── Core scan function ────────────────────────────────────────────────────────

def scan_path(
    target_path: str,
    rule_names: Optional[list[str]] = None,
    progress_cb: Optional[Callable[[float, str], None]] = None,
) -> YaraScanResult:
    """
    Scan a target path with the specified YARA rules.

    If YARA_AVAILABLE is False, performs a simulated scan (traverses files,
    counts them, returns 0 matches) and notes in errors that yara-python
    is not installed.

    Progress updates are emitted via progress_cb(pct: float, current_file: str)
    if provided. pct ranges from 0.0 to 100.0.

    Args:
        target_path:  File or directory path to scan.
        rule_names:   Optional list of .yar filenames to restrict scanning to.
                      Pass None to use all available rules.
        progress_cb:  Optional callable(pct, current_file) for progress streaming.

    Returns:
        YaraScanResult with all findings and metadata populated.
    """
    start_time = time.time()
    errors: list[str] = []
    matches: list[YaraMatch] = []
    rules_loaded: list[str] = []

    # ── Collect files to scan ─────────────────────────────────────────────────
    files = _collect_files(target_path)
    total_files = len(files)

    # Notify caller that we have started
    if progress_cb:
        progress_cb(0.0, f"Collected {total_files} files to scan")

    # ── Graceful degradation when yara-python is not installed ────────────────
    if not YARA_AVAILABLE:
        errors.append(
            "yara-python package is not installed. Install with: pip install yara-python. "
            "File traversal completed but no rules were evaluated."
        )
        # Simulate scanning (iterate files for count, emit progress)
        for i, fpath in enumerate(files):
            pct = ((i + 1) / max(total_files, 1)) * 100.0
            if progress_cb:
                progress_cb(pct, str(fpath))
            # Small yield to allow progress to stream
            time.sleep(0)  # cooperative yield

        return YaraScanResult(
            scan_path=target_path,
            rules_loaded=[],
            files_scanned=total_files,
            matches=[],
            errors=errors,
            duration_sec=time.time() - start_time,
            yara_available=False,
        )

    # ── Load and compile YARA rules ───────────────────────────────────────────
    compiled_rules, rules_loaded, load_errors = _load_rules(rule_names)
    errors.extend(load_errors)

    if compiled_rules is None:
        # Rule compilation failed — return empty result with errors
        return YaraScanResult(
            scan_path=target_path,
            rules_loaded=rules_loaded,
            files_scanned=0,
            matches=[],
            errors=errors,
            duration_sec=time.time() - start_time,
            yara_available=True,
        )

    # ── Scan each file ────────────────────────────────────────────────────────
    files_scanned = 0
    for i, fpath in enumerate(files):
        # Emit progress update: percentage + current filename
        pct = (i / max(total_files, 1)) * 100.0
        if progress_cb:
            progress_cb(pct, str(fpath))

        try:
            # Read file bytes for YARA matching
            file_bytes = fpath.read_bytes()
            # Run compiled rules against this file
            yara_matches = compiled_rules.match(data=file_bytes)
            files_scanned += 1

            # Convert YARA match objects to our YaraMatch dataclass
            for m in yara_matches:
                # Extract meta fields with defaults
                meta = m.meta if hasattr(m, "meta") else {}
                threat_family = meta.get("threat_family", "Unknown")
                severity = meta.get("severity", "MEDIUM")

                # Collect matched string identifiers
                matched_strs = []
                if hasattr(m, "strings"):
                    for string_match in m.strings:
                        # string_match is a StringMatch object: (offset, identifier, data)
                        if hasattr(string_match, "identifier"):
                            matched_strs.append(string_match.identifier)
                        elif isinstance(string_match, tuple) and len(string_match) >= 2:
                            matched_strs.append(str(string_match[1]))

                # Get the first match offset for reporting
                first_offset = 0
                if hasattr(m, "strings") and m.strings:
                    try:
                        first_offset = m.strings[0].instances[0].offset if hasattr(m.strings[0], "instances") else 0
                    except (IndexError, AttributeError):
                        first_offset = 0

                matches.append(YaraMatch(
                    rule_name=m.rule,
                    threat_family=threat_family,
                    severity=severity,
                    file_path=str(fpath),
                    offset=first_offset,
                    matched_strings=matched_strs[:10],  # cap at 10 strings per match
                ))

        except PermissionError:
            errors.append(f"Permission denied: {fpath}")
        except OSError as exc:
            errors.append(f"Read error on {fpath}: {exc}")
        except Exception as exc:
            # Catch-all for unexpected YARA errors on individual files
            errors.append(f"YARA error scanning {fpath}: {exc}")

    # Final progress callback
    if progress_cb:
        progress_cb(100.0, f"Scan complete — {files_scanned} files, {len(matches)} matches")

    return YaraScanResult(
        scan_path=target_path,
        rules_loaded=rules_loaded,
        files_scanned=files_scanned,
        matches=matches,
        errors=errors,
        duration_sec=time.time() - start_time,
        yara_available=True,
    )
