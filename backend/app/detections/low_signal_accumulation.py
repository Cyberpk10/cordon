"""Long-dwell / low-signal correlation (Cordon detection max-out Stage D) — a per-actor
"suspicious pattern" accumulator over individually-benign, sub-detector-floor events (a
handful of failed logins, a small transfer to an unfamiliar host, an atypical-hour session,
a first touch of a sensitive class while still cold-start). Each is too weak on its own to
trip any existing rule; app.baselines.aggregation.project_suspicious_pattern_score decays a
persisted score over a long (90+ day) horizon and only lets a batch feed it when 2+ distinct
categories co-occur in the same batch — see that function's module section for the
calibration behind the co-occurrence gate and the exponential half-life.

Same evaluate(window, baseline) signature shape as every rule in app.detections.engine's
_RULES for testability, but NOT registered there — app.api.routes.events calls this directly
with the just-ingested BATCH (not the standard lookback window), matching exactly what
update_baseline consumes, since the co-occurrence gate is inherently batch-scoped.

HONEST LIMIT (stated here again, not just in aggregation.py, per the Stage D requirement to
be explicit about the ceiling): a disciplined attacker who never trips two categories in the
same batch, or who paces slowly enough that decay outruns accumulation, evades this. Pure
living-off-the-land within otherwise-normal patterns needs endpoint telemetry this system
doesn't have — unchanged by this stage.
"""

from __future__ import annotations

from app.baselines.aggregation import (
    BaselineSnapshot,
    empty_baseline,
    project_suspicious_pattern_score,
)
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    if not window.events:
        return []

    effective_baseline = baseline or empty_baseline(window.actor)
    now = max(e.timestamp for e in window.events)
    score, contribution = project_suspicious_pattern_score(
        effective_baseline.suspicious_pattern_score,
        effective_baseline.last_updated,
        window.events,
        effective_baseline,
        now=now,
    )

    if score <= settings.low_signal_chronic_threshold:
        return []

    points = min(45.0, 10.0 + (score - settings.low_signal_chronic_threshold))
    severity = Severity.HIGH if score >= 65.0 else Severity.MEDIUM
    categories = ", ".join(sorted(contribution.categories)) or "none this batch"

    return [
        make_finding(
            id="LOW_SIGNAL_PATTERN_ACCUMULATION",
            category="insider_threat",
            title="Accumulated low-signal behavioral pattern",
            description=(
                f"'{window.actor}' has accumulated a suspicious-pattern score of "
                f"{score:.1f} (threshold {settings.low_signal_chronic_threshold:.0f}) from "
                f"repeated, individually-benign weak signals across multiple categories over "
                f"an extended period — this batch's contributing categories: {categories}. "
                "No single event or short window crossed any other detector's floor; the "
                "sustained, co-occurring pattern itself is the signal."
            ),
            severity=severity,
            points=round(points, 1),
            evidence_event_ids=contribution.evidence_event_ids,
        )
    ]
