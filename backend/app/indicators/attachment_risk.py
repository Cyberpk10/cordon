"""Attachment-based risk indicators: risky extensions, double extensions, macro-enabled
documents, HTML attachments, and (from the parser's static inspection, see
app.parsing.attachment_inspect) archive contents, encrypted archives, content/name type
mismatches and content-detected macros. Filenames are attacker-controlled: they're sanitized
and truncated before becoming evidence."""

from __future__ import annotations

import re

from app.indicators.base import make_indicator
from app.models.schemas import Indicator, Severity
from app.channels.message import Message
from app.sender_history.aggregation import SenderHistorySnapshot
from app.parsing.eml_parser import is_macro_enabled_filename

_RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".ps1", ".msi", ".jar", ".lnk", ".hta", ".cpl", ".reg", ".apk", ".chm",
    # Disk images and OneNote: popular containers for smuggling executables past filters.
    ".iso", ".img", ".vhd", ".vhdx", ".one",
}
_HTML_EXTENSIONS = {".htm", ".html", ".shtml", ".xhtml", ".svg"}
_ARCHIVE_RISKY_MEMBER_EXTENSIONS = _RISKY_EXTENSIONS | _HTML_EXTENSIONS
_DOCUMENT_OR_IMAGE_EXTENSIONS = {"." + e for e in {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "csv", "rtf"}}
_MAX_NAME = 120

_BENIGN_LOOKING_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "csv"}

_DOUBLE_EXT_RE = re.compile(r"^.+\.([a-z0-9]{2,5})\.([a-z0-9]{2,5})$", re.IGNORECASE)


def _clean(name: str) -> str:
    """Attacker-controlled name -> safe evidence text."""
    cleaned = "".join(c if c.isprintable() else "?" for c in name)
    return cleaned if len(cleaned) <= _MAX_NAME else cleaned[: _MAX_NAME - 1] + "…"


def _is_double_ext(filename: str) -> bool:
    match = _DOUBLE_EXT_RE.match(filename)
    if not match:
        return False
    first_ext, second_ext = match.group(1).lower(), match.group(2).lower()
    return first_ext in _BENIGN_LOOKING_EXTENSIONS and f".{second_ext}" in _ARCHIVE_RISKY_MEMBER_EXTENSIONS


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


def evaluate(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    risky_evidence: list[str] = []
    double_ext_evidence: list[str] = []
    macro_evidence: list[str] = []
    html_evidence: list[str] = []
    archive_evidence: list[str] = []
    encrypted_evidence: list[str] = []
    mismatch_evidence: list[str] = []

    for attachment in email.attachments:
        filename = attachment.filename
        shown = _clean(filename)
        ext = _extension(filename)
        info = attachment.inspection

        if ext in _RISKY_EXTENSIONS:
            risky_evidence.append(f"{shown} ({attachment.content_type or 'unknown type'})")

        if _is_double_ext(filename):
            double_ext_evidence.append(shown)

        if is_macro_enabled_filename(filename):
            macro_evidence.append(shown)
        elif info is not None and info.has_macros:
            macro_evidence.append(f"{shown} (contains a VBA macro project)")

        if ext in _HTML_EXTENSIONS or (info is not None and info.sniffed_type == "html" and ext not in _DOCUMENT_OR_IMAGE_EXTENSIONS):
            html_evidence.append(shown)

        if info is None:
            continue

        if info.sniffed_type in ("pe", "html", "lnk") and ext in _DOCUMENT_OR_IMAGE_EXTENSIONS:
            kind = {"pe": "a Windows executable", "html": "an HTML page", "lnk": "a Windows shortcut"}[info.sniffed_type]
            mismatch_evidence.append(f"{shown} is named like a document/image but its content is {kind}")
        elif info.sniffed_type == "pe" and ext not in _RISKY_EXTENSIONS:
            mismatch_evidence.append(f"{shown} is a Windows executable under a non-executable name")

        if info.archive_encrypted:
            encrypted_evidence.append(f"{shown} (password-protected; contents can't be scanned)")

        risky_members = [
            m for m in info.archive_members
            if _extension(m.rsplit("/", 1)[-1]) in _ARCHIVE_RISKY_MEMBER_EXTENSIONS or _is_double_ext(m.rsplit("/", 1)[-1])
        ]
        if risky_members:
            listed = ", ".join(_clean(m) for m in risky_members[:5])
            more = f" (+{len(risky_members) - 5} more)" if len(risky_members) > 5 else ""
            archive_evidence.append(f"{shown} contains {listed}{more}")

    indicators: list[Indicator] = []

    if risky_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_RISKY_EXTENSION",
                category="attachment",
                title="Attachment has an executable/script file extension",
                description=(
                    "One or more attachments use a file extension commonly used to deliver "
                    "malware (executables, scripts, or installers)."
                ),
                evidence=risky_evidence,
                severity=Severity.HIGH,
                score=20,
            )
        )

    if double_ext_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_DOUBLE_EXTENSION",
                category="attachment",
                title="Attachment uses a disguised double extension",
                description=(
                    "An attachment's filename ends in a benign-looking extension followed by an "
                    "executable/script extension (e.g. 'invoice.pdf.exe'), a technique used to "
                    "trick recipients into opening malware."
                ),
                evidence=double_ext_evidence,
                severity=Severity.HIGH,
                score=15,
            )
        )

    if macro_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_MACRO_ENABLED",
                category="attachment",
                title="Macro-enabled Office document attached",
                description=(
                    "One or more attachments are macro-enabled Office documents (.docm/.xlsm/"
                    ".pptm, or a document found to contain a VBA project), a common vector for "
                    "delivering malicious macros."
                ),
                evidence=macro_evidence,
                severity=Severity.MEDIUM,
                score=15,
            )
        )

    if html_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_HTML",
                category="attachment",
                title="HTML file attached",
                description=(
                    "An attachment is an HTML page. Attached HTML opens a local web page that can "
                    "imitate a sign-in screen and post whatever is typed to an attacker, outside "
                    "the protection of link scanning."
                ),
                evidence=html_evidence,
                severity=Severity.MEDIUM,
                score=10,
            )
        )

    if archive_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_ARCHIVE_RISKY_CONTENT",
                category="attachment",
                title="Archive contains an executable, script or HTML file",
                description=(
                    "An attached archive holds a file type commonly used to deliver malware or "
                    "phishing pages. Packing it in an archive is a common way to slip it past "
                    "attachment filters."
                ),
                evidence=archive_evidence,
                severity=Severity.HIGH,
                score=25,
            )
        )

    if encrypted_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_ENCRYPTED_ARCHIVE",
                category="attachment",
                title="Password-protected archive attached",
                description=(
                    "An attached archive is encrypted, so neither Cordon nor a mail gateway can see "
                    "inside it. Attackers use this to hide malware from scanners."
                ),
                evidence=encrypted_evidence,
                severity=Severity.MEDIUM,
                score=15,
            )
        )

    if mismatch_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_TYPE_MISMATCH",
                category="attachment",
                title="Attachment's content doesn't match its name",
                description=(
                    "An attachment's actual content is executable or a web page while its name "
                    "presents it as something harmless, a disguise used to get it opened."
                ),
                evidence=mismatch_evidence,
                severity=Severity.HIGH,
                score=20,
            )
        )

    return indicators
