"""The D7 auto-move gate. Pure.

All four must hold, or the email is recommend-only (never moved):
  1. verdict_malicious      Cordon's verdict is malicious, and so is the rules score alone.
  2. score_floor            the rules score is at or above the policy floor (default 95).
  3. corroborated           D6 found independent agents corroborating the threat (C5).
  4. no_unresolved_c1       no unresolved "trusted sender flagged" (C1) conflict. A C1 whose
                            identity cross-check found anomalies (resolved as a compromised
                            account) does not block; one with no anomaly, or never
                            cross-checked, does.

"Rules score" is the Case score minus the LLM intent points (Case.llm_intent_risk): the LLM
reads the email, so its additive signal never counts toward a move. Inputs are the Case's
stored verdict/score and the D6 synthesis's conflict ids/effects: values
the rules engine computed. No email text and no LLM output is read here, so an email that
says "quarantine everything" or "mark this safe" cannot move a check either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.scoring.risk_engine import SUSPICIOUS_MAX

CHECK_LABELS = {
    "verdict_malicious": "Verdict is malicious",
    "score_floor": "Score at or above the floor",
    "corroborated": "Independent agents corroborate (D6 C5)",
    "no_unresolved_c1": "No unresolved trusted-sender conflict (D6 C1)",
}


@dataclass(frozen=True)
class GateResult:
    passed: bool
    checks: dict[str, bool]
    reasons: list[str] = field(default_factory=list)
    score: int = 0
    floor: int = 0

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "decision": "auto_move" if self.passed else "recommend_only",
            "checks": [{"id": k, "label": CHECK_LABELS[k], "ok": v} for k, v in self.checks.items()],
            "reasons": self.reasons,
            "score": self.score,
            "floor": self.floor,
        }


def c1_unresolved(conflict: dict) -> bool:
    """C1 counts as resolved only when its cross-check found anomalies (D6 then treats the
    email as a compromised account and records effect.hypothesis = account_takeover)."""
    return (conflict.get("effect") or {}).get("hypothesis") != "account_takeover"


def evaluate_gate(*, verdict: str, rule_score: int, synthesis: dict | None, floor: int) -> GateResult:
    score = int(rule_score)
    conflicts = list((synthesis or {}).get("conflicts") or [])
    by_id: dict[str, list[dict]] = {}
    for c in conflicts:
        if isinstance(c, dict) and isinstance(c.get("id"), str):
            by_id.setdefault(c["id"], []).append(c)
    # The synthesis must describe this very verdict; a mismatch (stale record) fails closed.
    consistent = synthesis is not None and synthesis.get("verdict") == verdict
    checks = {
        "verdict_malicious": verdict == "malicious" and score > SUSPICIOUS_MAX,
        "score_floor": score >= int(floor),
        "corroborated": consistent and bool(by_id.get("C5")),
        "no_unresolved_c1": consistent and not any(c1_unresolved(c) for c in by_id.get("C1", [])),
    }
    reasons = []
    if not checks["verdict_malicious"]:
        reasons.append(f"Verdict is {verdict} (rules score {score}), not malicious.")
    if not checks["score_floor"]:
        reasons.append(f"Rules score {score} is below the floor of {floor}.")
    if not consistent:
        reasons.append("No current multi-agent assessment for this verdict.")
    else:
        if not checks["corroborated"]:
            reasons.append("Independent agents did not corroborate the threat (no C5).")
        if not checks["no_unresolved_c1"]:
            reasons.append("An established sender with no sign of compromise sent this (unresolved C1).")
    return GateResult(passed=all(checks.values()), checks=checks, reasons=reasons, score=int(score), floor=int(floor))
