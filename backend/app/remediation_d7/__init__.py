"""D7 live auto-quarantine for the owner's own Gmail mailbox.

new email -> analyze -> investigate (D4) -> D6 -> gate -> signed single-message directive ->
the Gmail add-on moves that one message to the "Cordon Quarantine" label -> notify -> log.

- gate.py (pure): the four auto-move conditions, from structured fields only.
- directives.py (pure): HMAC signing/verification of a one-message directive.
- service.py: policy, issue/claim/result, undo, rate cap, kill switch, feedback.
- calibration.py: the one-shot backtest over recent mail; persists only its report.
"""
