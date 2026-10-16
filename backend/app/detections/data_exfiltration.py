"""Data exfiltration: a large single transfer/download to an unfamiliar destination, or
a large database export."""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity

_TRANSFER_ACTIONS = frozenset({"data_transfer", "file_download"})

# Set only by app.activity_log.parser for a BULK_DOWNLOAD row from a source with no
# byte-count data at all — never by the live /api/events path. Lets a bulk-download event
# still fire this finding on its own (there's no size to compare against a threshold),
# without touching the threshold-based logic below for every other transfer/download event.
_BULK_DOWNLOAD_OUTCOME = "bulk_download"

_UNSIZED_BULK_DOWNLOAD_POINTS = 20


def _is_allowlisted(target: str | None) -> bool:
    if target is None:
        return False
    return target in settings.exfil_allowlisted_destinations


def _format_bytes(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    # Doesn't use behavioral baselines — a large transfer to an unfamiliar destination is
    # suspicious regardless of the actor's history. Accepts the parameter only for a
    # uniform engine signature.
    findings: list[Finding] = []

    large_transfers = [
        e
        for e in window.events
        if e.action in _TRANSFER_ACTIONS
        and (e.bytes or 0) > settings.exfil_large_transfer_bytes
        and not _is_allowlisted(e.target)
    ]
    if large_transfers:
        total_bytes = sum(e.bytes or 0 for e in large_transfers)
        severity = Severity.HIGH if len(large_transfers) > 1 else Severity.MEDIUM
        points = min(60, 30 + 10 * (len(large_transfers) - 1))
        findings.append(
            make_finding(
                id="DATA_EXFIL_LARGE_TRANSFER",
                category="exfiltration",
                title="Large transfer to an unfamiliar destination",
                description=(
                    f"'{window.actor}' transferred {_format_bytes(total_bytes)} across "
                    f"{len(large_transfers)} transfer(s) to destination(s) not on the "
                    f"known-good allowlist."
                ),
                severity=severity,
                points=points,
                evidence_event_ids=[e.id for e in large_transfers if e.id is not None],
            )
        )
    else:
        # Nothing cleared the byte threshold above (either nothing qualifies, or the source
        # never reported a size) — but a bulk-download result was still reported for this
        # actor. The event itself is the trigger; we never substitute a placeholder size for
        # evidence we don't have.
        unsized_bulk_downloads = [
            e
            for e in window.events
            if e.action in _TRANSFER_ACTIONS
            and e.outcome == _BULK_DOWNLOAD_OUTCOME
            and not _is_allowlisted(e.target)
        ]
        if unsized_bulk_downloads:
            findings.append(
                make_finding(
                    id="DATA_EXFIL_LARGE_TRANSFER",
                    category="exfiltration",
                    title="Large transfer to an unfamiliar destination",
                    description=(
                        f"Bulk download event detected for '{window.actor}' "
                        f"({len(unsized_bulk_downloads)} event(s)); the source did not "
                        "report a transfer size."
                    ),
                    severity=Severity.MEDIUM,
                    points=_UNSIZED_BULK_DOWNLOAD_POINTS,
                    evidence_event_ids=[
                        e.id for e in unsized_bulk_downloads if e.id is not None
                    ],
                )
            )

    large_exports = [
        e
        for e in window.events
        if e.action == "db_query" and (e.bytes or 0) > settings.exfil_large_db_export_bytes
    ]
    if large_exports:
        total_bytes = sum(e.bytes or 0 for e in large_exports)
        severity = Severity.HIGH if len(large_exports) > 1 else Severity.MEDIUM
        points = min(60, 35 + 10 * (len(large_exports) - 1))
        findings.append(
            make_finding(
                id="DATA_EXFIL_LARGE_DB_EXPORT",
                category="exfiltration",
                title="Large database export",
                description=(
                    f"'{window.actor}' ran {len(large_exports)} database quer(y/ies) "
                    f"returning {total_bytes:,} bytes total."
                ),
                severity=severity,
                points=points,
                evidence_event_ids=[e.id for e in large_exports if e.id is not None],
            )
        )

    return findings
