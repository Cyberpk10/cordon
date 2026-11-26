"""Static, offline attachment inspection. Reads bytes only: nothing is executed, detonated,
decompressed or fetched, and the bytes are never stored.

- Content sniffing by magic bytes (PE executable, ZIP, OLE, PDF, HTML, Windows shortcut).
- ZIP archives: only the central directory is read (member names and the encrypted flag), so
  a zip bomb can't expand. Nested archives are listed by name, never opened.
- Macros: an OOXML package containing vbaProject.bin, or an OLE file carrying the
  _VBA_PROJECT stream name.

Every name read from inside an attachment is attacker-controlled; callers treat it as data
(app.indicators.attachment_risk sanitizes it before it becomes evidence).
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field

MAX_INSPECT_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 200

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00"
_VBA_MARKERS = (b"_VBA_PROJECT", "_VBA_PROJECT".encode("utf-16-le"))
_HTML_PREFIXES = (b"<!doctype html", b"<html", b"<script", b"<head", b"<body", b"<meta", b"<form", b"<svg")


@dataclass
class AttachmentInspection:
    sniffed_type: str | None = None  # "pe", "zip", "ole", "pdf", "html", "lnk", or None
    archive_members: list[str] = field(default_factory=list)
    archive_member_count: int = 0
    archive_encrypted: bool = False
    has_macros: bool = False
    inspected: bool = True  # False when skipped (too large) or unreadable


def _sniff(payload: bytes) -> str | None:
    if payload.startswith(b"MZ"):
        return "pe"
    if payload.startswith(b"PK\x03\x04") or payload.startswith(b"PK\x05\x06"):
        return "zip"
    if payload.startswith(_OLE_MAGIC):
        return "ole"
    if payload.startswith(b"%PDF"):
        return "pdf"
    if payload.startswith(_LNK_MAGIC):
        return "lnk"
    head = payload[:512].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith(_HTML_PREFIXES):
        return "html"
    return None


def inspect(filename: str, content_type: str | None, payload: bytes) -> AttachmentInspection:
    if len(payload) > MAX_INSPECT_BYTES:
        return AttachmentInspection(inspected=False)
    result = AttachmentInspection(sniffed_type=_sniff(payload))
    try:
        if result.sniffed_type == "zip":
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                infos = zf.infolist()  # central directory only; nothing is decompressed
            result.archive_member_count = len(infos)
            result.archive_members = [i.filename for i in infos[:MAX_ARCHIVE_MEMBERS]]
            result.archive_encrypted = any(i.flag_bits & 0x1 for i in infos)
            result.has_macros = any(i.filename.lower().endswith("vbaproject.bin") for i in infos)
        elif result.sniffed_type == "ole":
            result.has_macros = any(m in payload for m in _VBA_MARKERS)
    except (zipfile.BadZipFile, ValueError, OSError, EOFError):
        result.inspected = False
    return result
