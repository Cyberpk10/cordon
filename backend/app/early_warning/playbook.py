"""Deterministic, rule-based recommended-action generation for early-warning alerts (Stage
2) — reuses app.remediation.playbook's generate_from_rules/PlaybookStep engine VERBATIM (the
"existing approvable-playbook pattern"), just with a different rule table keyed on Stage 1's
signal `type` strings instead of indicator/finding IDs (generate_from_rules is generic over
any string ID set, so this needed no changes there).

Purely descriptive, same as the existing intrusion/email playbooks — nothing here ties into
app.autonomy's executor or auto-fires anything. A human decides what to do with the
recommendation; app.api.routes.early_warning only ever lets them acknowledge the ALERT, not
execute a step.
"""

from __future__ import annotations

from app.remediation.playbook import PlaybookStep, generate_from_rules

_TRIGGERS_FORCE_PASSWORD_RESET = frozenset(
    {"PHISHING_EMAIL_RECEIVED", "SIMULATION_PHISHING_CLICKED", "AUTH_ANOMALY"}
)
_TRIGGERS_REVIEW_SENSITIVE_ACCESS = frozenset({"FIRST_TIME_SENSITIVE_ACCESS"})
_TRIGGERS_MONITOR_DATA_MOVEMENT = frozenset(
    {"SMALL_UNFAMILIAR_TRANSFER", "STAGE_D_ACCUMULATOR_SIGNAL"}
)
_TRIGGERS_NOTIFY_SOC = frozenset(
    {
        "PHISHING_EMAIL_RECEIVED",
        "SIMULATION_PHISHING_CLICKED",
        "AUTH_ANOMALY",
        "FIRST_TIME_SENSITIVE_ACCESS",
        "SMALL_UNFAMILIAR_TRANSFER",
        "STAGE_D_ACCUMULATOR_SIGNAL",
    }
)

# Fixed order: iteration order determines output order, same determinism guarantee as the
# email/intrusion rule tables — the first step is the primary recommendation.
_EARLY_WARNING_STEP_RULES: tuple[tuple[str, str, str, str, frozenset[str]], ...] = (
    (
        "FORCE_PASSWORD_RESET",
        "Pre-emptively force a password reset",
        "A phishing/auth-anomaly signal is part of this forming chain. Force a password "
        "reset and revoke active sessions for this actor before it progresses further.",
        "reset_credentials",
        _TRIGGERS_FORCE_PASSWORD_RESET,
    ),
    (
        "REVIEW_SENSITIVE_ACCESS",
        "Review the actor's recent sensitive-resource access",
        "This actor touched a sensitive resource class for the first time as part of this "
        "chain. Review what was accessed before deciding whether to restrict further access.",
        "review_access",
        _TRIGGERS_REVIEW_SENSITIVE_ACCESS,
    ),
    (
        "MONITOR_DATA_MOVEMENT",
        "Increase monitoring on this actor's data movement",
        "A small, unfamiliar-destination transfer is part of this chain. Watch for further "
        "transfers before any single one crosses a hard exfiltration threshold.",
        "monitor",
        _TRIGGERS_MONITOR_DATA_MOVEMENT,
    ),
    (
        "NOTIFY_SOC",
        "Notify the security operations team",
        "Notify SOC/security personnel that an attack appears to be forming against this "
        "actor, with the signal timeline below, for awareness and further investigation.",
        "notify_soc",
        _TRIGGERS_NOTIFY_SOC,
    ),
)


def generate_early_warning_playbook(signal_types: list[str]) -> list[PlaybookStep]:
    return generate_from_rules(signal_types, _EARLY_WARNING_STEP_RULES)
