"""Config-driven resource-sensitivity classification (Cordon detection max-out, Stage B) — a
pure, dependency-free helper used by app.baselines.aggregation and the two new detection
modules that consume it. Deliberately class-level, not per-resource: tracking sensitivity
CLASS history (a small, fixed set — finance/HR/legal by default) keeps every new
ActorBaseline field bounded, the same way hour_counts/location_counts/daily_volume already
are — tracking every individual resource path an actor has ever touched would grow
unboundedly, unlike everything else in that model.
"""

from __future__ import annotations

from app.core.config import settings


def classify_resource_sensitivity(target: str | None) -> str | None:
    """Returns the configured sensitivity class a target belongs to ("finance"/"hr"/"legal"
    by default), or None if it doesn't match any configured prefix. Reads settings fresh on
    every call (no caching) so tests can monkeypatch the prefix lists directly, matching the
    convention used by every other settings-driven check in this codebase."""
    if not target:
        return None
    normalized = target.strip().lower()

    classes = {
        "finance": settings.sensitive_resource_prefixes_finance,
        "hr": settings.sensitive_resource_prefixes_hr,
        "legal": settings.sensitive_resource_prefixes_legal,
    }
    for cls, prefixes in classes.items():
        if any(normalized.startswith(prefix) for prefix in prefixes):
            return cls
    return None
