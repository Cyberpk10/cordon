"""Pure phishing-simulation decision logic (M9 Stage 1) — no DB/I/O here, mirrors every other
pure aggregation/decision module in this codebase (app.autonomy.policy, app.dashboard.aggregation,
app.baselines.aggregation, ...).
"""

from __future__ import annotations

# A recipient's status only ever moves up this ladder, never back down — a click always
# proves the link was reachable (even overriding a prior "send_failed" bookkeeping state,
# since a click is direct evidence the email did arrive), and a submit is always the top.
_RANK = {
    "pending": 0,
    "send_failed": 0,
    "sent": 1,
    "clicked": 2,
    "submitted": 3,
}
_EVENT_TARGET = {"click": "clicked", "submit": "submitted"}


def advance_status(current: str, event: str) -> str:
    """Returns the recipient status after `event` ("click" | "submit"), never regressing a
    status that already ranks at or above the event's target."""
    target = _EVENT_TARGET[event]
    if _RANK[target] > _RANK.get(current, 0):
        return target
    return current


AUTHORIZATION_STATEMENT = (
    "I confirm this campaign targets only employees of my own organization, on domains this "
    "account has verified control of, and that I am authorized to conduct this security-"
    "awareness simulation."
)
