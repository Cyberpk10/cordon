"""D7 gate and directive signing (pure)."""

from __future__ import annotations

import pytest

from app.remediation_d7 import directives as D
from app.remediation_d7.gate import evaluate_gate

C5 = {"id": "C5", "effect": {"confidence": 1}}
C1_UNRESOLVED = {"id": "C1", "effect": {"confidence": -1}}
C1_NOT_CHECKED = {"id": "C1", "effect": {}}
C1_ATO = {"id": "C1", "effect": {"hypothesis": "account_takeover"}}


def syn(*conflicts, verdict="malicious"):
    return {"verdict": verdict, "conflicts": list(conflicts)}


def gate(verdict="malicious", score=97, synthesis=None, floor=95):
    return evaluate_gate(verdict=verdict, rule_score=score, synthesis=synthesis, floor=floor)


def test_high_score_with_corroboration_and_no_c1_passes():
    g = gate(synthesis=syn(C5))
    assert g.passed and all(g.checks.values()) and g.as_dict()["decision"] == "auto_move"


def test_high_score_without_corroboration_fails():
    g = gate(synthesis=syn({"id": "C4"}))
    assert not g.passed and g.checks == {"verdict_malicious": True, "score_floor": True,
                                         "corroborated": False, "no_unresolved_c1": True}


def test_just_below_floor_fails():
    g = gate(score=94, synthesis=syn(C5))
    assert not g.passed and not g.checks["score_floor"]


@pytest.mark.parametrize("c1", [C1_UNRESOLVED, C1_NOT_CHECKED])
def test_unresolved_c1_blocks(c1):
    g = gate(synthesis=syn(C5, c1))
    assert not g.passed and not g.checks["no_unresolved_c1"]


def test_c1_resolved_as_compromised_account_does_not_block():
    assert gate(synthesis=syn(C5, C1_ATO)).passed


@pytest.mark.parametrize("verdict", ["suspicious", "safe"])
def test_non_malicious_never_passes(verdict):
    assert not gate(verdict=verdict, synthesis=syn(C5, verdict=verdict)).passed


def test_missing_or_stale_synthesis_fails_closed():
    assert not gate(synthesis=None).passed
    assert not gate(synthesis=syn(C5, verdict="suspicious")).passed  # describes another verdict


def test_rules_score_in_suspicious_band_fails_even_if_floor_low():
    assert not gate(score=50, floor=40, synthesis=syn(C5)).passed


DIR = {"id": "a", "kind": "move", "gmail_message_id": "18c2f0a1b2c3d4e5", "fingerprint": "f" * 64,
       "label": "Cordon Quarantine", "nonce": "n", "expires_at": "2026-11-27T12:00:00Z"}


def test_directive_roundtrip_and_tamper_detection():
    d = D.build(DIR, "s3cret")
    assert D.verify(d, "s3cret")
    assert not D.verify(d, "other")
    assert not D.verify({**d, "gmail_message_id": "18c2f0a1b2c3d4e6"}, "s3cret")
    assert not D.verify({**d, "query": "in:inbox"}, "s3cret")  # no extra fields, ever
    assert not D.verify({**d, "gmail_message_id": ["18c2f0a1b2c3d4e5"]}, "s3cret")
    assert not D.verify(d, "")  # no secret configured: nothing verifies
