"""Pure tests for app.investigation.verify and app.investigation.assessment."""

from __future__ import annotations

from datetime import datetime, timedelta

from app.investigation import assessment as A
from app.investigation.artifacts import campaign_signature, normalize_subject
from app.investigation.verify import concrete_tokens, verify_submission

EV = {
    "EV1": "The triggering case has deterministic verdict=malicious, score=80/100.",
    "EV2": "The sending server IP 198.51.100.7 geolocates to Nigeria; the sending host belongs to bulkmail.example.",
    "EV3": "3 related case(s) in the last 30 days, reaching 4 distinct recipient(s).",
}


def _sub(claims, verdict="malicious", hyp_ids=("EV1",), rationale="Credential lure."):
    return {
        "stated_verdict": verdict,
        "claims": [{"text": t, "evidence_ids": ids} for t, ids in claims],
        "hypothesis": {"category": "credential_phishing", "rationale": rationale,
                       "evidence_ids": list(hyp_ids), "uncertainty": "medium"},
    }


def _verify(raw, shown=frozenset(EV)):
    return verify_submission(raw, cordon_verdict="malicious", shown_ids=set(shown), evidence_text=EV)


def test_tokens_extracted_ignore_evidence_refs():
    assert concrete_tokens("Sent from 198.51.100.7 via bulkmail.example to 4 people (EV2, EV3)") == {
        "198.51.100.7", "bulkmail.example", "4",
    }


def test_grounded_claims_are_kept():
    r = _verify(_sub([("Sent from 198.51.100.7 in Nigeria.", ["EV2"]), ("It reached 4 recipients.", ["EV3"])]))
    assert r.accepted and len(r.claims) == 2 and not r.removed


def test_number_not_in_cited_evidence_is_dropped():
    r = _verify(_sub([("Rated 80/100.", ["EV1"]), ("It reached 14 recipients.", ["EV3"]), ("Via bulkmail.example.", ["EV2"])]))
    assert r.accepted and [c["text"] for c in r.removed] == ["It reached 14 recipients."]


def test_token_must_be_in_the_evidence_it_cites_not_just_anywhere():
    # 198.51.100.7 is real evidence, but EV1 doesn't contain it.
    r = _verify(_sub([("Rated 80/100.", ["EV1"]), ("Sent from 198.51.100.7.", ["EV1"]), ("4 recipients.", ["EV3"])]))
    assert len(r.removed) == 1 and "198.51.100.7" in r.removed[0]["reason"]


def test_uncited_claim_is_dropped():
    r = _verify(_sub([("Rated 80/100.", ["EV1"]), ("Looks bad.", []), ("4 recipients.", ["EV3"])]))
    assert r.accepted and r.removed[0]["reason"] == "no evidence cited"


def test_mostly_unsupported_is_rejected_whole():
    r = _verify(_sub([("Rated 80/100.", ["EV1"]), ("From 10.9.9.9.", ["EV2"]), ("To 99 people.", ["EV3"])]))
    assert not r.accepted


def test_verdict_mismatch_unknown_id_and_unseen_id_reject():
    assert not _verify(_sub([("Fine.", ["EV1"])], verdict="safe")).accepted
    assert not _verify(_sub([("Rated 80/100.", ["EV7"])])).accepted
    assert not _verify(_sub([("Rated 80/100.", ["EV3"])]), shown={"EV1"}).accepted


def test_schema_violations_reject():
    raw = _sub([("Rated 80/100.", ["EV1"])])
    raw["recommendation"] = "none"
    assert not _verify(raw).accepted
    raw = _sub([("Rated 80/100.", ["EV1"])])
    raw["hypothesis"]["category"] = "nation_state_apt"
    assert not _verify(raw).accepted


def test_ungrounded_hypothesis_is_replaced_not_trusted():
    r = _verify(_sub([("Rated 80/100.", ["EV1"])], rationale="Sent by APT29 from 203.0.113.5."))
    assert r.accepted and r.hypothesis is None and r.hypothesis_rejected


# --- assessment -------------------------------------------------------------------------

NOW = datetime(2026, 11, 18, 12, 0)


def _rel(days, to, reasons):
    return {"id": f"c{days}{to}", "created_at": (NOW - timedelta(days=days)).isoformat(), "verdict": "malicious",
            "score": 70, "subject": None, "to_addresses": [to], "match_reasons": reasons}


def test_campaign_statuses():
    assert A.assess_campaign([], ["a@x"], NOW)["status"] == "one_off"
    same_sender_only = [_rel(1, "b@x", ["same sender"]), _rel(2, "c@x", ["same sender"])]
    assert A.assess_campaign(same_sender_only, ["a@x"], NOW)["status"] == "one_off"
    assert A.assess_campaign([_rel(1, "b@x", ["same campaign signature"])], ["a@x"], NOW)["status"] == "possible_campaign"
    wave = [_rel(1, "b@x", ["same campaign signature"]), _rel(2, "c@x", ["shared link domain evil.top"])]
    assert A.assess_campaign(wave, ["a@x"], NOW)["status"] == "wave"
    old = [_rel(20, "b@x", ["same campaign signature"]), _rel(25, "c@x", ["same campaign signature"])]
    assert A.assess_campaign(old, ["a@x"], NOW)["status"] == "possible_campaign"
    one_person = [_rel(1, "a@x", ["same campaign signature"]), _rel(2, "a@x", ["same campaign signature"])]
    assert A.assess_campaign(one_person, ["a@x"], NOW)["status"] == "possible_campaign"


def test_confidence_counts_families_not_points():
    one_off = {"status": "one_off"}
    many_weak = ["URGENCY_LANGUAGE", "FIRST_CONTACT_SENDER", "AI_AUTHORED_SUSPECTED"]
    assert A.assess_confidence("suspicious", many_weak, one_off, True, None)["level"] == "low"
    assert A.assess_confidence("malicious", ["LINK_SHORTENER", "LINK_SUSPICIOUS_TLD"], one_off, True, None)["level"] == "low"
    assert A.assess_confidence("malicious", ["LINK_SHORTENER", "CREDENTIAL_REQUEST"], one_off, True, None)["level"] == "medium"
    assert A.assess_confidence("malicious", ["LINK_SHORTENER", "CREDENTIAL_REQUEST", "AUTH_DMARC_FAIL"], one_off, True, None)["level"] == "high"
    assert A.assess_confidence("malicious", ["LINK_SHORTENER", "CREDENTIAL_REQUEST"], {"status": "wave"}, True, None)["level"] == "high"


def test_tier_follows_the_autonomy_policy_shape():
    high = {"level": "high", "score": 0.85}
    low = {"level": "low", "score": 0.4}
    one_off = {"status": "one_off", "linked_case_ids": []}
    block = A.recommend("malicious", ["LOOKALIKE_DOMAIN"], high, one_off, None, "first_contact", "evil.example")
    assert block["action"] == "BLOCK_SENDER_DOMAIN" and block["suggested_tier"] == "L2"  # containment
    quarantine = A.recommend("malicious", ["CREDENTIAL_REQUEST"], high, one_off, None, None, None)
    assert quarantine["action"] == "QUARANTINE_EMAIL" and quarantine["suggested_tier"] == "L1"
    assert A.recommend("suspicious", ["CREDENTIAL_REQUEST"], low, one_off, None, None, None)["suggested_tier"] == "L0"


def test_never_suggests_blocking_an_established_correspondent():
    high = {"level": "high", "score": 0.85}
    rec = A.recommend("malicious", ["SENDER_REPLYTO_MISMATCH"], high, {"status": "one_off", "linked_case_ids": []},
                      None, "established", "real-vendor.example")
    assert rec["action"] == "QUARANTINE_EMAIL"


def test_subject_normalization_and_signature():
    assert normalize_subject("RE: Fwd: Invoice #4471 overdue!") == normalize_subject("Invoice #9902 overdue")
    assert campaign_signature("Invoice 1 overdue", ["evil.top"]) == campaign_signature("RE: Invoice 2 overdue", ["evil.top"])
    assert campaign_signature("", []) is None


def test_hypothesis_rules():
    assert A.rules_hypothesis("malicious", ["LINK_DISPLAY_HREF_MISMATCH", "AUTH_SPF_FAIL"]) == "credential_phishing"
    assert A.rules_hypothesis("malicious", ["LINK_SUSPICIOUS_TLD", "AUTH_DMARC_FAIL"]) == "credential_phishing"
    assert A.rules_hypothesis("suspicious", ["LINK_SHORTENER"]) == "scam"
    assert A.rules_hypothesis("malicious", ["PAYMENT_REQUEST", "LINK_SHORTENER"]) == "bec_payment_fraud"
    assert A.rules_hypothesis("malicious", ["ACCOUNT_TAKEOVER", "PAYMENT_REQUEST"]) == "account_takeover"
    assert A.rules_hypothesis("malicious", ["ATTACHMENT_MACRO_ENABLED"]) == "malware_delivery"
    assert A.rules_hypothesis("suspicious", ["URGENCY_LANGUAGE"]) == "unclear"
    assert A.rules_hypothesis("safe", []) == "benign"
