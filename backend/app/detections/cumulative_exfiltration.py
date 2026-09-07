"""Cumulative-volume exfiltration (Stage 1 detection hardening; extended in Cordon detection
max-out Stage C with multiple rolling windows) — total data_transfer/file_download bytes to
non-allowlisted destinations, evaluated at three time-scales (7/30/90 days by default)
instead of one. app.api.routes.events feeds this a single window wide enough for the
longest tier; evaluate() slices it into short/medium/long sub-windows internally rather than
the caller querying three times.

Closes Phase 3 #2 and Phase 4 #4: both pace transfers further apart than the short window can
see, so the short tier's own min-transfers gate never sees more than one transfer at a time no
matter how large the total gets over months — the longer tiers still accumulate enough of them
to cross a (separately, deliberately lower-scaled) threshold.

Same evaluate(window, baseline) signature shape as every rule in app.detections.engine's
_RULES for testability, but NOT registered there — see the module docstring precedent this
already followed before Stage C.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from app.baselines.aggregation import BaselineSnapshot
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.detections.data_exfiltration import _TRANSFER_ACTIONS, _is_allowlisted
from app.events.schema import ActivityEvent
from app.models.schemas import Finding, Severity


@dataclass(frozen=True)
class _Tier:
    label: str
    window_days: int
    volume_threshold_bytes: int
    base_points: float
    max_points: float


def _tiers() -> list[_Tier]:
    return [
        _Tier("short", settings.exfil_cumulative_window_days, settings.exfil_cumulative_volume_bytes, 30.0, 60.0),
        _Tier("medium", settings.exfil_cumulative_window_days_medium, settings.exfil_cumulative_volume_bytes_medium, 40.0, 65.0),
        _Tier("long", settings.exfil_cumulative_window_days_long, settings.exfil_cumulative_volume_bytes_long, 50.0, 70.0),
    ]


@dataclass(frozen=True)
class _TierResult:
    tier: _Tier
    qualifying: list[ActivityEvent]
    qualifying_bytes: int
    total_bytes: int
    ratio: float

    @property
    def fired(self) -> bool:
        return (
            len(self.qualifying) >= settings.exfil_cumulative_min_transfers
            and self.qualifying_bytes > self.tier.volume_threshold_bytes
        )


def _evaluate_tier(events: list[ActivityEvent], window_end, tier: _Tier) -> _TierResult:
    cutoff = window_end - timedelta(days=tier.window_days)
    sub_events = [e for e in events if e.timestamp >= cutoff]

    all_transfers = [e for e in sub_events if e.action in _TRANSFER_ACTIONS and (e.bytes or 0) > 0]
    qualifying = [e for e in all_transfers if not _is_allowlisted(e.target)]

    qualifying_bytes = sum(e.bytes or 0 for e in qualifying)
    total_bytes = sum(e.bytes or 0 for e in all_transfers)
    ratio = (qualifying_bytes / total_bytes) if total_bytes > 0 else (1.0 if qualifying_bytes > 0 else 0.0)

    return _TierResult(tier=tier, qualifying=qualifying, qualifying_bytes=qualifying_bytes, total_bytes=total_bytes, ratio=ratio)


def _ratio_weight(ratio: float) -> float:
    if settings.exfil_cumulative_ratio_full_weight_at <= 0:
        return 1.0
    raw = ratio / settings.exfil_cumulative_ratio_full_weight_at
    return max(settings.exfil_cumulative_ratio_min_weight, min(1.0, raw))


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    # Doesn't use behavioral baselines — same rationale as data_exfiltration.py.
    if not window.events:
        return []

    window_end = max(e.timestamp for e in window.events)
    results = [_evaluate_tier(window.events, window_end, tier) for tier in _tiers()]
    fired = [r for r in results if r.fired]
    if not fired:
        return []

    # The longest firing tier is the strongest, most complete evidence — its qualifying set
    # is a superset of any shorter tier's (all sub-windows end at the same point and only
    # differ in how far back they start).
    winner = max(fired, key=lambda r: r.tier.window_days)

    extra_transfers = len(winner.qualifying) - settings.exfil_cumulative_min_transfers
    raw_points = min(winner.tier.max_points, winner.tier.base_points + 5.0 * extra_transfers)
    weight = _ratio_weight(winner.ratio)
    points = round(raw_points * weight, 1)
    severity = Severity.HIGH if weight >= 0.7 else Severity.MEDIUM

    return [
        make_finding(
            id="CUMULATIVE_EXFIL_VOLUME",
            category="exfiltration",
            title="Cumulative exfiltration volume over rolling window",
            description=(
                f"'{window.actor}' transferred {winner.qualifying_bytes:,} bytes across "
                f"{len(winner.qualifying)} transfer(s)/download(s) to destination(s) not on "
                f"the known-good allowlist, over a rolling {winner.tier.window_days}-day "
                f"window ({winner.ratio:.0%} of their total transfer volume in that window) "
                "— no single transfer crossed the large-transfer threshold, but the sustained "
                "total did."
            ),
            severity=severity,
            points=points,
            evidence_event_ids=[e.id for e in winner.qualifying if e.id is not None],
        )
    ]
