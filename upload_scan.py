# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Safe ingestion for the upload scan flow (ZIP / folder / snippet — no repo URL).

Extracting an attacker-supplied archive is dangerous: path traversal ("zip
slip") can write outside the target directory, and zip bombs can exhaust disk.
This module extracts defensively — every member path is confined to the
destination, and total size / file count / compression ratio are capped.

Pure filesystem helpers, no network. Raises UploadError on anything unsafe.
"""

import io
import os
import zipfile
from pathlib import Path

MAX_FILES = 3000
MAX_TOTAL_BYTES = 60 * 1024 * 1024   # 60 MB uncompressed
MAX_RATIO = 200                       # uncompressed/compressed guard (zip bomb)
_SKIP_PREFIXES = ("__MACOSX/",)


class UploadError(Exception):
    """Raised when an upload is malformed or unsafe to extract."""


def _is_within(base: Path, target: Path) -> bool:
    """True if resolved target stays inside base (blocks path traversal)."""
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except (ValueError, OSError):
        return False


def safe_extract_zip(zip_bytes: bytes, dest_dir: str) -> int:
    """Extract a ZIP into dest_dir defensively. Returns the number of files written.

    Guards against zip-slip (path traversal), too many files, excessive total
    size, and high-ratio zip bombs.
    """
    base = Path(dest_dir)
    base.mkdir(parents=True, exist_ok=True)
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as e:
        raise UploadError("not a valid ZIP archive") from e

    infos = [i for i in zf.infolist()
             if not i.filename.startswith(_SKIP_PREFIXES)]
    if len(infos) > MAX_FILES:
        raise UploadError(f"archive has too many files (> {MAX_FILES})")

    total_uncomp = sum(i.file_size for i in infos)
    total_comp = sum(i.compress_size for i in infos) or 1
    if total_uncomp > MAX_TOTAL_BYTES:
        raise UploadError("archive too large when uncompressed")
    if total_uncomp / total_comp > MAX_RATIO and total_uncomp > 5 * 1024 * 1024:
        raise UploadError("suspicious compression ratio (possible zip bomb)")

    written = 0
    for info in infos:
        name = info.filename
        if not name or name.endswith("/"):
            continue  # directory entry
        target = base / name
        if not _is_within(base, target):
            raise UploadError(f"unsafe path in archive: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as dst:
            dst.write(src.read())
        written += 1
    if written == 0:
        raise UploadError("archive contained no files")
    return written


def write_snippet(code: str, filename: str, dest_dir: str) -> str:
    """Write a pasted snippet to a single file in dest_dir. Returns the path."""
    if not code or not code.strip():
        raise UploadError("empty snippet")
    if len(code.encode("utf-8", "ignore")) > 2 * 1024 * 1024:
        raise UploadError("snippet too large (> 2 MB)")
    safe_name = os.path.basename((filename or "snippet.txt").strip()) or "snippet.txt"
    base = Path(dest_dir)
    base.mkdir(parents=True, exist_ok=True)
    target = base / safe_name
    if not _is_within(base, target):
        raise UploadError("invalid filename")
    target.write_text(code, encoding="utf-8")
    return str(target)
