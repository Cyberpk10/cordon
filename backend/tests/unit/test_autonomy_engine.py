"""Pure tests for the D5 graduated-autonomy engine and its action catalog."""

from __future__ import annotations

import dataclasses

import pytest

from app.autonomy import cordon_actions as C
from app.autonomy.engine import DecisionInputs, PolicyView, plan

WAVE = DecisionInputs(
    verdict="malicious", confidence="high", campaign_status="wave", linked_case_ids=("c2", "c3"),
    campaign_signature="sig", recommended_action="BLOCK_SENDER_DOMAIN", recommended_tier="L2",
    sender_classification="first_contact", sender_address="x@evil.top", sender_domain="evil.top",
    sending_ip="198.51.100.7", hypothesis="credential_phishing", recipients=("a@corp.com",),
)
ALL_TYPES = {
    C.LABEL_CASE, C.SET_TRIAGE, C.NOTIFY, C.OPEN_INVESTIGATION, C.WATCHLIST_SENDER, C.BLOCKLIST_DOMAIN,
    C.WATCHLIST_IP, C.GROUP_CAMPAIGN, C.ESCALATE_PRIORITY, C.RECOMMEND_MAILBOX_REMEDIATION,
}


def _by_type(actions):
    return {a.action_type: a for a in actions}


def test_wave_plans_every_action_with_its_rule():
    acts = _by_type(plan(WAVE, PolicyView(shadow_mode=False, tier="L3"), "c1"))
    assert set(acts) == ALL_TYPES
    assert acts[C.BLOCKLIST_DOMAIN].rule_id == "R5-BLOCK-DOMAIN"
    assert acts[C.GROUP_CAMPAIGN].params["case_ids"] == ["c1", "c2", "c3"]
    assert acts[C.RECOMMEND_MAILBOX_REMEDIATION].params["case_ids"] == ["c1", "c2", "c3"]


def test_shadow_mode_performs_nothing_but_records_within_tier():
    acts = plan(WAVE, PolicyView(shadow_mode=True, tier="L1"), "c1")
    assert {a.outcome for a in acts} == {"shadow"}
    by = _by_type(acts)
    assert by[C.LABEL_CASE].within_tier and not by[C.BLOCKLIST_DOMAIN].within_tier


@pytest.mark.parametrize("tier", ["L0", "L1", "L2", "L3"])
def test_tier_ceiling_is_never_exceeded(tier):
    order = ["L0", "L1", "L2", "L3"]
    for a in plan(WAVE, PolicyView(shadow_mode=False, tier=tier), "c1"):
        if a.outcome == "performed":
            assert order.index(a.tier) <= order.index(tier)
        if order.index(a.tier) > order.index(tier):
            assert a.outcome in ("awaiting_approval", "above_tier")


def test_l1_account_gets_l2_as_recommendations_and_l3_logged_only():
    by = _by_type(plan(WAVE, PolicyView(shadow_mode=False, tier="L1"), "c1"))
    assert by[C.LABEL_CASE].outcome == "performed"
    assert by[C.BLOCKLIST_DOMAIN].outcome == "awaiting_approval"
    assert by[C.RECOMMEND_MAILBOX_REMEDIATION].outcome == "above_tier"


def test_l3_mailbox_recommendation_is_queued_never_performed():
    by = _by_type(plan(WAVE, PolicyView(shadow_mode=False, tier="L3"), "c1"))
    assert by[C.RECOMMEND_MAILBOX_REMEDIATION].outcome == "awaiting_approval"
    assert by[C.RECOMMEND_MAILBOX_REMEDIATION].within_tier


def test_l0_performs_nothing():
    assert all(a.outcome != "performed" for a in plan(WAVE, PolicyView(shadow_mode=False, tier="L0"), "c1"))


def test_kill_switch_halts_everything_even_in_shadow():
    for shadow in (True, False):
        acts = plan(WAVE, PolicyView(shadow_mode=shadow, tier="L3", kill_switch=True), "c1")
        assert {a.outcome for a in acts} == {"halted"}


def test_protected_identity_is_never_auto_listed():
    by = _by_type(plan(WAVE, PolicyView(shadow_mode=False, tier="L3", exclusions=frozenset({"evil.top"})), "c1"))
    assert by[C.BLOCKLIST_DOMAIN].outcome == "awaiting_approval"
    assert by[C.WATCHLIST_SENDER].outcome == "awaiting_approval"
    assert by[C.LABEL_CASE].outcome == "performed"


def test_rate_cap_bounds_l2_actions_and_never_l1_bookkeeping():
    acts = plan(WAVE, PolicyView(shadow_mode=False, tier="L2", blast_radius_limit=2, performed_in_window=1), "c1")
    l1 = [a for a in acts if a.tier == "L1"]
    l2 = [a for a in acts if a.tier == "L2"]
    assert all(a.outcome == "performed" for a in l1)
    assert sum(a.outcome == "performed" for a in l2) == 1
    assert all(a.outcome == "awaiting_approval" for a in l2 if a.outcome != "performed")


def test_low_confidence_only_labels_and_investigates():
    low = dataclasses.replace(WAVE, confidence="low", verdict="suspicious")
    assert {a.action_type for a in plan(low, PolicyView(shadow_mode=False, tier="L3"), "c1")} == {
        C.LABEL_CASE, C.SET_TRIAGE, C.OPEN_INVESTIGATION,
    }


def test_safe_mail_plans_nothing():
    assert plan(dataclasses.replace(WAVE, verdict="safe"), PolicyView(shadow_mode=False, tier="L3"), "c1") == []


def test_provider_ip_is_never_watched():
    acts = _by_type(plan(dataclasses.replace(WAVE, ip_is_provider=True), PolicyView(shadow_mode=False, tier="L3"), "c1"))
    assert C.WATCHLIST_IP not in acts


def test_established_sender_is_never_watched_or_blocked():
    est = dataclasses.replace(WAVE, sender_classification="established", recommended_action="QUARANTINE_EMAIL")
    acts = _by_type(plan(est, PolicyView(shadow_mode=False, tier="L3"), "c1"))
    assert C.WATCHLIST_SENDER not in acts and C.BLOCKLIST_DOMAIN not in acts


def test_decision_inputs_carry_no_free_text():
    # Injection resistance is structural: nothing an email says can reach the engine.
    names = {f.name for f in dataclasses.fields(DecisionInputs)}
    assert not names & {"subject", "body", "text", "narrative", "claims", "display_name"}


def test_every_catalog_action_has_an_undo_and_a_missing_one_refuses_to_load():
    assert set(C.ACTION_SPECS) == ALL_TYPES
    assert all(s.undo and s.undo_description for s in C.ACTION_SPECS.values())
    broken = dict(C.ACTION_SPECS)
    broken["NO_UNDO"] = dataclasses.replace(C.ACTION_SPECS[C.LABEL_CASE], type="NO_UNDO", undo=None)
    with pytest.raises(RuntimeError, match="no undo path"):
        C.validate_catalog(broken)
