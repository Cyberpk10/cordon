"""Cumulative-volume exfiltration (Stage 1 detection hardening): total data_transfer/
file_download bytes to non-allowlisted destinations across a rolling window meaningfully
wider than the standard 24h detection window (see
app.core.config.exfil_cumulative_window_days) — catches "low and slow" exfiltration spread
across many small transfers, none of which individually crosses
app.detections.data_exfiltration's single-event threshold, and none of which any single
daily ingest batch's own 24h window would ever see all of at once.

Same evaluate(window, baseline) signature shape as every rule in app.detections.engine's
_RULES for testability, but NOT registered there: it needs a 7-day window, not the standard
24h one, so app.api.routes.events calls it directly with a separately queried wide window.
"""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.detections.data_exfiltration import _TRANSFER_ACTIONS, _is_allowlisted
from app.models.schemas import Finding, Severity


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    # Doesn't use behavioral baselines — same rationale as data_exfiltration.py.
    qualifying = [
        e
        for e in window.events
        if e.action in _TRANSFER_ACTIONS and (e.bytes or 0) > 0 and not _is_allowlisted(e.target)
    ]
    if len(qualifying) < settings.exfil_cumulative_min_transfers:
        return []

    total_bytes = sum(e.bytes or 0 for e in qualifying)
    if total_bytes <= settings.exfil_cumulative_volume_bytes:
        return []

    return [
        make_finding(
            id="CUMULATIVE_EXFIL_VOLUME",
            category="exfiltration",
            title="Cumulative exfiltration volume over rolling window",
            description=(
                f"'{window.actor}' transferred {total_bytes:,} bytes across "
                f"{len(qualifying)} transfer(s)/download(s) to destination(s) not on the "
                f"known-good allowlist, over a rolling "
                f"{settings.exfil_cumulative_window_days}-day window — no single transfer "
                f"crossed the large-transfer threshold, but the sustained total did."
            ),
            severity=Severity.HIGH,
            points=min(
                60.0, 30.0 + 5.0 * (len(qualifying) - settings.exfil_cumulative_min_transfers)
            ),
            evidence_event_ids=[e.id for e in qualifying if e.id is not None],
        )
    ]
