"""Anti-poisoning ramp detection (Cordon detection max-out, Stage B) — closes Phase 3
red-team scenario 3 and Phase 4 scenario 5, both of which defeat
app.detections.mass_file_access's single-day mean+3*stddev check by never spiking on any one
day: the anomaly is the TREND across many days, not any individual day. Delegates the actual
trend math to app.baselines.aggregation.evaluate_ramp_anomaly (pure, no DB) and turns whichever
of its three sub-signals fired into one Finding, mirroring app.indicators.trusted_sender_
anomaly's "one finding, named corroborators in evidence" shape from Stage A.

Weighting (a resolved product decision, not an oversight): a rising raw daily-volume trend
alone is common and often benign (role changes, seasonal workload) — it contributes a low
score that can never flip a verdict by itself. A rising SHARE of an actor's activity landing
on sensitive resource classes specifically, or a drift against the long-term (harder-to-poison)
anchor, is a much rarer and sharper signal and is weighted accordingly.
"""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot, evaluate_ramp_anomaly
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity

_FILE_ACTIONS = frozenset({"file_access", "file_download"})


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    if baseline is None:
        return []

    ramp = evaluate_ramp_anomaly(baseline)
    if ramp is None or not ramp.any_detected:
        return []

    reasons: list[str] = []
    high_tier_hits = sum([ramp.sensitive_ratio_ramp_detected, ramp.long_term_drift_detected])

    if high_tier_hits > 0:
        severity = Severity.HIGH
        score = 30 + 10 * (high_tier_hits - 1)
        if ramp.sensitive_ratio_ramp_detected:
            reasons.append(
                f"the share of their activity touching sensitive resource classes has risen "
                f"from ~{ramp.sensitive_ratio_early_mean:.0%} to ~{ramp.sensitive_ratio_recent_mean:.0%} "
                "over the observed history"
            )
        if ramp.long_term_drift_detected:
            reasons.append(
                f"recent activity (mean {ramp.long_term_recent_mean:.1f}/day) has drifted well "
                f"above their long-term, harder-to-poison baseline "
                f"(mean {ramp.long_term_anchor_mean:.1f}/day)"
            )
        if ramp.volume_ramp_detected:
            score += 5
            reasons.append(
                f"raw daily volume has also risen from a mean of {ramp.volume_early_mean:.1f} "
                f"to {ramp.volume_recent_mean:.1f} over the same period"
            )
    elif ramp.volume_ramp_detected:
        severity = Severity.MEDIUM
        score = 10
        reasons.append(
            f"raw daily volume has risen from a mean of {ramp.volume_early_mean:.1f} to "
            f"{ramp.volume_recent_mean:.1f} over the observed history"
        )
    else:
        return []

    score = min(50, score)
    evidence_event_ids = [e.id for e in window.events if e.action in _FILE_ACTIONS and e.id is not None]

    return [
        make_finding(
            id="BASELINE_RAMP_ANOMALY",
            category="access",
            title="Gradual baseline-poisoning ramp detected",
            description=(
                f"'{window.actor}'s established baseline itself shows a sustained trend rather "
                f"than a single-day anomaly — {'; '.join(reasons)}. A gradual ramp like this "
                "never crosses a single-day volume-spike check, since no individual day is "
                "unusual relative to whatever came immediately before it."
            ),
            severity=severity,
            points=score,
            evidence_event_ids=evidence_event_ids,
        )
    ]
