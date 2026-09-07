"""First-time sensitive-resource-class access (Cordon detection max-out, Stage B) — closes
Phase 2 red-team scenario 4 (an insider touching finance/HR/legal files for the first time, at
completely normal volume and normal hours — nothing else in this codebase has any concept of
resource sensitivity to compare against). Uses the actor's own baseline
(app.baselines.aggregation.BaselineSnapshot.sensitive_classes_seen) — cold start never fires,
matching app.detections.anomalous_location's own precedent exactly: a brand-new actor's very
first activity is trivially "new" in every class, so it isn't evidence of anything until
there's enough history to know what's actually normal for them.
"""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot, is_sensitive_class_first_seen
from app.baselines.resource_sensitivity import classify_resource_sensitivity
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity

_FILE_ACTIONS = frozenset({"file_access", "file_download"})


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    if baseline is None or baseline.event_count < settings.baseline_min_events_for_resource_class:
        return []

    file_events = [e for e in window.events if e.action in _FILE_ACTIONS]

    first_time_by_class: dict[str, list] = {}
    for event in file_events:
        cls = classify_resource_sensitivity(event.target)
        if cls is None:
            continue
        if is_sensitive_class_first_seen(baseline, cls):
            first_time_by_class.setdefault(cls, []).append(event)

    if not first_time_by_class:
        return []

    classes = sorted(first_time_by_class.keys())
    evidence_event_ids = [
        e.id for events in first_time_by_class.values() for e in events if e.id is not None
    ]

    # Deliberately capped below SAFE_MAX (24) for a single new class — a one-off, legitimate
    # cross-department need must not flip a verdict alone. A multi-class sweep (the exact
    # Phase 2 #4 pattern — finance+HR+legal touched all at once) clears well past it.
    score = min(30, 15 + 10 * (len(classes) - 1))

    return [
        make_finding(
            id="SENSITIVE_RESOURCE_FIRST_ACCESS",
            category="access",
            title="First-time access to a sensitive resource class",
            description=(
                f"'{window.actor}' accessed resources in the "
                f"{'/'.join(classes)} sensitivity class{'es' if len(classes) > 1 else ''} for "
                "the first time in their observed history — at otherwise normal volume and "
                "hours, which no purely volume/hours-based check would ever surface on its own."
            ),
            severity=Severity.MEDIUM,
            points=score,
            evidence_event_ids=evidence_event_ids,
        )
    ]
