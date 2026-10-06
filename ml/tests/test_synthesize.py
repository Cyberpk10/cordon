from __future__ import annotations

from aegis_ml.schema import Source
from aegis_ml.synthesize import (
    CATEGORY_CONFIG,
    DEFAULT_TARGET_PER_CATEGORY,
    SyntheticEmail,
    _build_eml_bytes,
    _validate_email,
)


def _valid_raw(**overrides) -> dict:
    payload = {
        "from_display": "IT Support",
        "from_address": "support@fictional-example-corp.test",
        "reply_to_address": None,
        "subject": "Action required",
        "body_text": "Please verify your account by signing in again.",
        "auth_result": "fail",
        "technique": "lookalike domain",
    }
    payload.update(overrides)
    return payload


def test_validate_email_accepts_well_formed_payload():
    result = _validate_email(_valid_raw())
    assert result == SyntheticEmail(
        from_display="IT Support",
        from_address="support@fictional-example-corp.test",
        reply_to_address=None,
        subject="Action required",
        body_text="Please verify your account by signing in again.",
        auth_result="fail",
        technique="lookalike domain",
    )


def test_validate_email_rejects_missing_required_field():
    raw = _valid_raw()
    del raw["subject"]
    assert _validate_email(raw) is None


def test_validate_email_rejects_address_without_at_sign():
    assert _validate_email(_valid_raw(from_address="not-an-email")) is None


def test_validate_email_rejects_empty_body():
    assert _validate_email(_valid_raw(body_text="   ")) is None


def test_validate_email_defaults_invalid_auth_result_to_fail():
    result = _validate_email(_valid_raw(auth_result="maybe"))
    assert result is not None
    assert result.auth_result == "fail"


def test_validate_email_accepts_pass_auth_result():
    result = _validate_email(_valid_raw(auth_result="pass"))
    assert result is not None
    assert result.auth_result == "pass"


def test_validate_email_handles_missing_technique_gracefully():
    raw = _valid_raw()
    del raw["technique"]
    result = _validate_email(raw)
    assert result is not None
    assert result.technique == "unspecified"


def test_validate_email_rejects_non_dict_input():
    assert _validate_email("not a dict") is None  # type: ignore[arg-type]
    assert _validate_email(None) is None  # type: ignore[arg-type]


def test_build_eml_bytes_round_trips_through_the_real_parser():
    """The whole point of writing a real RFC822 message (not a hand-rolled string) is that
    it must survive a real parse — this is the same email.message_from_bytes path
    aegis_ml.parsers.mbox_parser.iter_single_message_dir_records uses on every synthetic file
    at normalize time."""
    import email as email_module

    sample = SyntheticEmail(
        from_display="Billing",
        from_address="billing@fictional-vendor.test",
        reply_to_address="reply@fictional-other.test",
        subject="Invoice update",
        body_text="Please review the attached invoice.",
        auth_result="fail",
        technique="compromised vendor",
    )
    raw_bytes = _build_eml_bytes(sample, "bec")
    parsed = email_module.message_from_bytes(raw_bytes)

    assert parsed["Subject"] == "Invoice update"
    assert "billing@fictional-vendor.test" in parsed["From"]
    assert parsed["Reply-To"] == "reply@fictional-other.test"
    assert parsed["X-Aegis-Synthetic"] == "true"
    assert parsed["X-Aegis-Synthetic-Category"] == "bec"
    assert parsed["X-Aegis-Synthetic-Technique"] == "compromised vendor"
    assert "fail" in parsed["Authentication-Results"]
    assert parsed.get_payload() == "Please review the attached invoice."


def test_every_category_has_a_source_enum_and_they_are_distinct():
    sources = {cfg["source"] for cfg in CATEGORY_CONFIG.values()}
    assert sources == {
        Source.SYNTHETIC_CREDENTIAL_PHISHING,
        Source.SYNTHETIC_BEC,
        Source.SYNTHETIC_AI_LURE,
    }


def test_default_target_per_category_is_a_bounded_small_number():
    """Guards against someone accidentally bumping this into "most of the corpus" territory
    without updating the documented bounded-fraction rationale in ml/corpus/sources.md."""
    assert 0 < DEFAULT_TARGET_PER_CATEGORY <= 200
